from typing import List, Dict, Any

from pydantic import BaseModel


class LookupResult(BaseModel):
    user: str | None = None
    service: str | None = None
    ip: str | None = None
    rev_host: str | None = None
    asn: str | None = None
    as_cc: str | None = None
    as_desc: str | None = None
    as_org: str | None = None # maxmind
    net_name: str | None = None
    net_cc: str | None = None
    entities: List[str] | None = None
    maxmind: Dict[str, Any] | None = None

    blocked: bool = False
    matched: str | None = None
    log: bool = True
    reserved: bool = False

    def __str__(self):
        if self.entities is not None:
            e = ", entity=".join(self.entities)
        else:
            e = "<>"
        val = "user=<{}>, service={}, ip={}, host={}, asn={}, as_cc={}, as_desc=<{}>, as_org=<{}>, net_name=<{}>, net_cc={}, entity={}".format(
            self.user, self.service, self.ip, self.rev_host, self.asn, self.as_cc, self.as_desc, self.as_org, self.net_name, self.net_cc, e
        )

        if self.maxmind is not None:
            if "city" in self.maxmind:
                val = "{}, city=<{}/{}>".format(val, self.maxmind["city"]["geoname_id"], self.maxmind["city"]["names"]["en"])
            else:
                val += ", city=<>"

            if "subdivisions" in self.maxmind:
                val = "{}, subdivision={}".format(val, ", subdivision=".join(["<{}/{}>".format(s["geoname_id"], s["names"]["en"]) for s in self.maxmind["subdivisions"]]))

            if "country" in self.maxmind:
                val = "{}, country=<{}/{}>".format(val, self.maxmind["country"]["geoname_id"], self.maxmind["country"]["names"]["en"])
            else:
                val += ", country=<>"

            if "represented_country" in self.maxmind:
                val = "{}, represented_country=<{}/{}>".format(val, self.maxmind["represented_country"]["geoname_id"], self.maxmind["represented_country"]["names"]["en"])

            if "registered_country" in self.maxmind:
                val = "{}, registered_country=<{}/{}>".format(val, self.maxmind["registered_country"]["geoname_id"], self.maxmind["registered_country"]["names"]["en"])

            if "location" in self.maxmind:
                val = "{}, lat={}, lon={}, rad={}km".format(val, self.maxmind["location"]["latitude"], self.maxmind["location"]["longitude"], self.maxmind["location"]["accuracy_radius"])

        if self.blocked:
            return "{}, blocked=True, matched={}".format(val, self.matched)

        return val


class AuthRequest(BaseModel):
    username: str
    password: str
    service: str
    remote_ip: str


class AuditRequest(BaseModel):
    username: str
    service: str
    remote_ip: str
    skip_password_check: bool
    passdbs_seen_user_unknown: bool
