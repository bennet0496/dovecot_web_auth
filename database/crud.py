from sqlalchemy.orm import Session

from . import alchemy as models
from . import schemas


def get_app_passwords_by_uid(db: Session, uid: str):
    return db.query(models.AppPassword).filter(models.AppPassword.uid.like(uid)).all()


def create_log(db: Session, log: schemas.LogCreate, pwid: int):
    db_log = models.LogEntry(**log.model_dump(), pwid=pwid)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log
