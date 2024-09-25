import logging
import os
from functools import lru_cache

import ldap3
import redis

from config import Settings
from database import SessionLocal
from logger import rootlogger

from util.lists import Manager

logger = rootlogger.getChild("depends")

@lru_cache
def get_settings():
    return Settings()

@lru_cache
def get_lists():
    return Manager(get_settings())

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

    logger.debug("get_ldap: %s", conn)

    try:
        yield conn
    finally:
        conn.unbind()