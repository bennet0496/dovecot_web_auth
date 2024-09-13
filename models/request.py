from pydantic import BaseModel


class AuthRequest(BaseModel):
    username: str
    password: str
    service: str
    remote_ip: str

    def __cmp__(self, other):
        return (self.username == other.username and
                self.password == other.password and
                self.service == other.service and
                self.remote_ip == other.remote_ip)

    def __hash__(self):
        return hash((self.username, self.password, self.service, self.remote_ip))


class AuditRequest(BaseModel):
    username: str
    service: str
    remote_ip: str
    skip_password_check: bool
    passdbs_seen_user_unknown: bool

    def __cmp__(self, other):
        return (self.username == other.username and self.service == other.service and
                self.remote_ip == other.remote_ip and self.skip_password_check == other.skip_password_check and
                self.passdbs_seen_user_unknown == other.passdbs_seen_user_unknown)

    def __hash__(self):
        return hash((self.username, self.service, self.remote_ip,
                     self.skip_password_check, self.passdbs_seen_user_unknown))
