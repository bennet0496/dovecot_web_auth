import datetime
import os
from typing import *
from base64 import b64decode
from functools import lru_cache

from fastapi import FastAPI, Response, status, Depends
from sqlalchemy.orm import Session

import passlib.hash

import ldap3

import socket
import struct
from systemd import journal

from database import crud, Base
from audit import audit, audit_log
from config import Settings
from database import SessionLocal, engine
from request_model import LookupResult, AuthRequest, AuditRequest
from database.schemas import LogCreate, AppPassword
from util import check_whois, check_maxmind, find_net, maxmind_location_str

Base.metadata.create_all(bind=engine)

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
    app_passwords : Iterable[AppPassword] = crud.get_app_passwords_by_uid(db, request.username)
    for app_password in app_passwords:
        if passlib.hash.ldap_sha512_crypt.verify(b64decode(request.password), app_password.password):
            # disallow app password from webmail
            if find_net(request.remote_ip, settings.auth.disallow_passwords_from) is not None:
                response.status_code = status.HTTP_401_UNAUTHORIZED
                return {"status": "app passwords not allowed"}

            result = await lookup(request.remote_ip, request.service, request.username, settings)
            audit_result_p = audit(result, settings)

            location = maxmind_location_str(result.maxmind, settings)

            crud.create_log(db, LogCreate(
                    service=request.service,
                    src_ip=request.remote_ip,
                    src_rdns=result.rev_host,
                    src_loc=location,
                    src_isp=(result.as_org or result.as_desc),
                ), app_password.id)

            audit_result = await audit_result_p
            await audit_log(audit_result, result)

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
    audit_result = await audit(result, settings)

    await audit_log(audit_result, result)

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
