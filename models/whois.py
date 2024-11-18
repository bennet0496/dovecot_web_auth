from pydantic import BaseModel


class WhoisResult(BaseModel):
    asn: str | None
    as_cc: str | None
    as_desc: str | None
    net_name: str | None
    net_cc: str | None
    entities: list[str]
    reserved: bool = False

    def __cmp__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        e = self.entities.copy()
        e.sort()
        return hash((self.asn, self.as_cc, self.as_desc, self.net_name, self.net_cc, tuple(e), self.reserved))
