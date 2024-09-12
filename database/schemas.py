from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel


class AppPasswordBase(BaseModel):
    uid: str
    password: str
    created: datetime
    comment: str | None = None


class AppPassword(AppPasswordBase):
    id: int

    class Config:
        from_attributes = True


class LogBase(BaseModel):
    service: str
    src_ip: str
    src_rdns: str
    src_loc: str
    src_isp: str
    timestamp: datetime

class LogCreate(LogBase):
    pass

class Log(LogBase):
    id: int
    pwid: int
    timestamp: datetime

    app_password: AppPassword

    class Config:
        from_attributes = True