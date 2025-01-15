from datetime import datetime

from pydantic import BaseModel


class AppPasswordBase(BaseModel):
    uid: str
    password: str
    created: datetime
    comment: str | None = None
    deleted: datetime | None = None


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


class LogCreate(LogBase):
    def __hash__(self):
        return hash((self.service, self.src_ip, self.src_rdns, self.src_loc, self.src_isp))


class Log(LogBase):
    id: int
    pwid: int
    timestamp: datetime

    app_password: AppPassword

    class Config:
        from_attributes = True
