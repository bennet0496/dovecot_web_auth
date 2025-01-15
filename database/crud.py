import datetime
import logging

import redis
from sqlalchemy.orm import Session

from util import get_settings
from . import alchemy as models
from . import schemas

logger = logging.getLogger("dovecot_web_auth.database.crud")

def get_app_passwords_by_uid(db: Session, uid: str):
    return db.query(models.AppPassword).filter(models.AppPassword.uid.like(uid)).all()


def create_log(db: Session, log: schemas.LogCreate, pwid: int):
    r = redis.Redis(get_settings().cache.host, get_settings().cache.port, db = 1, decode_responses=True)
    val = r.get(str(pwid))
    logger.debug("create_log pwid %d hash_log %d redis %s, %s", pwid, hash(log), str(r.get(str(pwid))), str(val != str(hash(log))))
    if val != str(hash(log)):
        db_log = models.LogEntry(**log.model_dump(), pwid=pwid)
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        r.set(str(pwid), hash(log), exat=datetime.datetime.now() + datetime.timedelta(seconds=get_settings().audit.db_authlog_dd_hash_bucket))
        return db_log
    else:
        r.expire(str(pwid), min(get_settings().audit.db_authlog_dd_hash_bucket, r.ttl(str(pwid)) + get_settings().audit.db_authlog_dd_per_login))
        return None
