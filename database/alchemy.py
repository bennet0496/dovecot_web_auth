import datetime

from sqlalchemy import Column, ForeignKey, String, DateTime, BigInteger, UniqueConstraint, text
from sqlalchemy.orm import relationship

from . import Base


class AppPassword(Base):
    __tablename__ = "app_passwords"

    id = Column(BigInteger, primary_key=True)
    uid = Column(String, nullable=False)
    password = Column(String, nullable=False)
    created = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    comment = Column(String, nullable=True)
    UniqueConstraint(uid, password)

    logs = relationship("LogEntry", back_populates="app_password")


class LogEntry(Base):
    __tablename__ = "log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    pwid = Column(BigInteger, ForeignKey("app_passwords.id"))
    service = Column(String)
    src_ip = Column(String)
    src_rdns = Column(String)
    src_loc = Column(String)
    src_isp = Column(String)
    timestamp = Column(DateTime, default=text('UTC_TIMESTAMP(3)'))

    app_password = relationship("AppPassword", back_populates="logs")


