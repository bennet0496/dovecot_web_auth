from typing import *
from base64 import b64decode

import uvicorn
from fastapi import FastAPI, Response, status, Depends, BackgroundTasks
from sqlalchemy.orm import Session

import passlib.hash

import ldap3

from database import crud, Base
from audit import audit, audit_log
from config import Settings
from database import engine
from lookup import lookup
from models.request import AuthRequest, AuditRequest
from database.schemas import LogCreate, AppPassword
from util import find_net, maxmind_location_str
from util.depends import get_settings, get_db, get_ldap, get_lists

Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.post("/auth", status_code=status.HTTP_400_BAD_REQUEST)
async def post_auth(
        request: AuthRequest,
        response: Response,
        settings: Annotated[Settings, Depends(get_settings)],
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db),
        ldap: ldap3.Connection = Depends(get_ldap),
):
    # ldap
    ldap.search(settings.ldap.basedn, "(uid={})".format(request.username), attributes=ldap3.ALL_ATTRIBUTES)
    if len(ldap.entries) == 0:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"status": "user not found"}
    elif len(ldap.entries) > 1:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "user not unique"}

    account = ldap.entries[0]
    # print(account)
    if account.homeDirectory == "/dev/null" or account.loginShell == "/bin/false":
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "account disabled"}

    # fetch passwords
    app_passwords: Iterable[AppPassword] = crud.get_app_passwords_by_uid(db, request.username)
    for app_password in app_passwords:
        try:
            if passlib.hash.ldap_sha512_crypt.verify(b64decode(request.password), app_password.password):
                # disallow app password from webmail
                if find_net(request.remote_ip, settings.auth.disallow_passwords_from) is not None:
                    response.status_code = status.HTTP_401_UNAUTHORIZED
                    return {"status": "app passwords not allowed"}

                result = lookup(request.remote_ip, request.service, request.username)
                audit_result = audit(result)

                if result.maxmind_result is not None:
                    location = maxmind_location_str(result.maxmind_result.maxmind)
                else:
                    location = result.whois_result.net_name

                log = LogCreate(
                    service=request.service,
                    src_ip=request.remote_ip,
                    src_rdns=result.rev_host,
                    src_loc=location,
                    src_isp=(result.maxmind_result and result.maxmind_result.as_org or result.whois_result.as_desc))

                background_tasks.add_task(crud.create_log, db=db, log=log, pwid=app_password.id)

                background_tasks.add_task(audit_log, audit_result=audit_result, lookup_result=result)

                response.status_code = audit_result.status_code
                return {"status": audit_result.status}
        except ValueError as e:
            print(app_password.id, app_password.uid, e)
            response.status_code = 500
            return {"status": "password validation error, please check password " + str(app_password.id)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"status": "invalid password"}


@app.post("/audit", status_code=status.HTTP_400_BAD_REQUEST)
async def post_audit(
        request: AuditRequest,
        response: Response,
        settings: Annotated[Settings, Depends(get_settings)],
        background_tasks: BackgroundTasks,
):
    if request.passdbs_seen_user_unknown and not settings.audit.audit_process_unknown:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"status": "unknown"}

    result = lookup(request.remote_ip, request.service, request.username)
    audit_result = audit(result)

    background_tasks.add_task(audit_log, audit_result=audit_result, lookup_result=result)

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


@app.post("/reload")
async def post_reload():
    # print(get_settings.cache_info())
    get_settings.cache_clear()

    # print(get_lists.cache_info())
    get_lists.cache_clear()

    # print(lookup.cache_info())
    lookup.cache_clear()

    # print(audit.cache_info())
    audit.cache_clear()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)