import os
from keyword import kwlist
from typing import *
from base64 import b64decode
from functools import lru_cache

from fastapi import FastAPI, Response, status, Depends
from sqlalchemy.orm import Session

import passlib.hash

import ldap3

import socket
import struct
import syslog
from systemd import journal

import crud
from audit import audit
from config import Settings
import models
from database import SessionLocal, engine
from models import LookupResult, AuthRequest, AuditRequest
from schemas import LogCreate
from util import check_whois, check_maxmind

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

@lru_cache
def get_settings():
    return Settings()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_ldap():
    tls = None
    if get_settings().ldap.tls and os.path.isfile(get_settings().ldap.tls_cert):
        tls = ldap3.Tls(ca_certs_file=get_settings().ldap.tls_cert)
    srv = ldap3.Server(get_settings().ldap.host, get_settings().ldap.port, tls=tls)
    conn = ldap3.Connection(srv, user=get_settings().ldap.bind, password=get_settings().ldap.password)
    # conn.authentication = "ANONYMOUS" if
    if get_settings().ldap.tls:
        conn.start_tls()
    conn.bind()

    try:
        yield conn
    finally:
        conn.unbind()


async def lookup(ip: str, service: str, user: str, settings: Settings) -> LookupResult:
    ip_int = struct.unpack("!L", socket.inet_aton(ip))[0]
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        rdns = "<>"

    result = LookupResult(user=user, service=service, ip=ip, rev_host=rdns)
    for net in settings.audit.local_networks.items():
        addr, mask = net[0].split("/")
        net_int = struct.unpack("!L", socket.inet_aton(addr))[0]
        mask = 0xffffffff << (32 - int(mask))
        if net_int & mask == ip_int & mask:
            result.asn = None
            result.as_cc = "ZZ"
            result.as_desc = settings.audit.local_locationname
            result.net_name = net[1]
            result.net_cc = "ZZ"
            result.entities = None
            result.log = settings.audit.log_local
            break
    else:
        result = (result.model_copy(update=check_whois(ip, settings))
                  .model_copy(update=check_maxmind(ip, settings), deep=True))
    return result


@app.post("/auth", status_code=status.HTTP_400_BAD_REQUEST)
async def post_auth(
        request: AuthRequest,
        response: Response,
        settings: Annotated[Settings, Depends(get_settings)],
        db: Session = Depends(get_db),
        ldap: ldap3.Connection = Depends(get_ldap)
):
    # ldap
    ldap.search(settings.ldap.basedn, "(uid={})".format(request.username), attributes=ldap3.ALL_ATTRIBUTES)
    if len(ldap.entries) == 0:
        response.status_code = status.HTTP_404_NOT_FOUND
        return { "status": "user not found" }
    elif len(ldap.entries) > 1:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return { "status": "user not unique" }

    account = ldap.entries[0]
    # print(account)
    if account.homeDirectory == "/dev/null" or account.loginShell == "/bin/false":
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "account disabled"}

    # fetch passwords
    app_passwords : Iterable[models.AppPassword] = crud.get_app_passwords_by_uid(db, request.username)
    for app_password in app_passwords:
        if passlib.hash.ldap_sha512_crypt.verify(b64decode(request.password), app_password.password):
            result = await lookup(request.remote_ip, request.service, request.username, settings)

            audit_result = audit(result, settings)

            location = ""
            if result.maxmind is None:
                location = settings.audit.local_locationname
            else:
                if "postal" in result.maxmind:
                    location += result.maxmind["postal"]["code"] + " "

                if "city" in result.maxmind:
                    location += result.maxmind["city"]["names"]["en"] + ", "

                if "subdivisions" in result.maxmind:
                    location += result.maxmind["subdivisions"][0]["iso_code"] + ", "

                if "country" in result.maxmind:
                    location += result.maxmind["country"]["names"]["en"]

            crud.create_log(
                db,
                LogCreate(
                    service=request.service,
                    src_ip=request.remote_ip,
                    src_rdns=result.rev_host,
                    src_loc=location,
                    src_isp=(result.as_org or result.as_desc)),
                app_password.id)

            result.matched = audit_result.matched
            result.blocked = audit_result.status_code != 200
            if audit_result.log:
                # syslog.openlog(ident="mail-audit", logoption=syslog.LOG_PID, facility=syslog.LOG_MAIL)
                # syslog.syslog(syslog.LOG_INFO, str(result))
                logmodel = dict(
                    map(lambda i: ("AUDIT_" + str(i[0]).upper(), i[1]), result.model_dump(exclude={"maxmind"}).items()))
                maxmindmodel = dict(map(lambda i: ("AUDIT_MAXMIND_" + str(i[0]).upper(), i[1]), result.model_dump()[
                    "maxmind"].items())) if result.maxmind is not None else dict()
                journal.send(str(result), **logmodel, **maxmindmodel, SYSLOG_IDENTIFIER="mail-audit")

            response.status_code = audit_result.status_code
            return {"status": audit_result.status}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"status": "invalid password"}

@app.post("/audit", status_code=status.HTTP_400_BAD_REQUEST)
async def post_audit(
        request: AuditRequest,
        response: Response,
        settings: Annotated[Settings, Depends(get_settings)],
):

    if request.passdbs_seen_user_unknown and not settings.audit.audit_process_unknown:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"status": "unknown"}

    result = await lookup(request.remote_ip, request.service, request.username, settings)
    audit_result = audit(result, settings)

    result.matched = audit_result.matched
    result.blocked = audit_result.status_code != 200
    if audit_result.log:
        # syslog.openlog(ident="mail-audit", logoption=syslog.LOG_PID, facility=syslog.LOG_MAIL)
        # syslog.syslog(syslog.LOG_INFO, str(result))
        logmodel = dict(
            map(lambda i: ("AUDIT_" + str(i[0]).upper(), i[1]), result.model_dump(exclude={"maxmind"}).items()))
        maxmindmodel = dict(map(lambda i: ("AUDIT_MAXMIND_" + str(i[0]).upper(), i[1]),
                                result.model_dump()["maxmind"].items())) if result.maxmind is not None else dict()
        journal.send(str(result), **logmodel, **maxmindmodel, SYSLOG_IDENTIFIER="mail-audit")

    if audit_result.status_code == status.HTTP_200_OK:
        if settings.audit.audit_result_success == "next":
            response.status_code = status.HTTP_307_TEMPORARY_REDIRECT
        elif settings.audit.audit_result_success == "unknown":
            response.status_code = status.HTTP_404_NOT_FOUND
        elif settings.audit.audit_result_success == "ok":
            if request.skip_password_check:
                response.status_code = status.HTTP_200_OK
            else:
                response.status_code = status.HTTP_404_NOT_FOUND
    else:
        response.status_code = audit_result.status_code

    return {"status": audit_result.status}
