import logging
import socket
from functools import lru_cache
from typing import Any, Optional

from pydantic import BaseModel

from logger import rootlogger
from models.maxmind import MMResult, MMCity
from models.whois import WhoisResult
from util import find_net, check_whois, check_maxmind
from util.depends import get_settings

logger = rootlogger.getChild("lookup")

class LookupResult(BaseModel):
    user: str | None = None
    password: int | None = None
    service: str | None = None
    ip: str | None = None
    rev_host: str | None = None
    whois_result: WhoisResult | None = None
    maxmind_result: MMResult | None = None

    blocked: bool = False
    matched: str | None = None
    log: bool = True

    def __str__(self):
        if self.whois_result.entities is not None:
            e = ", entity=".join(self.whois_result.entities)
        else:
            e = "<>"
        val = "user=<{}>, password={}, service={}, ip={}, host={}, asn={}, as_cc={}, as_desc=<{}>, as_org=<{}>, net_name=<{}>, net_cc={}, entity={}".format(
            self.user, self.password, self.service, self.ip, self.rev_host, self.whois_result.asn, self.whois_result.as_cc,
            self.whois_result.as_desc, self.maxmind_result and self.maxmind_result.as_org, self.whois_result.net_name,
            self.whois_result.net_cc, e
        )

        if self.maxmind_result and self.maxmind_result.maxmind:
            if self.maxmind_result.maxmind.city:
                val = "{}, city=<{}/{}>".format(val, self.maxmind_result.maxmind.city.geoname_id,
                                                self.maxmind_result.maxmind.city.name)
            else:
                val += ", city=<>"

            if len(self.maxmind_result.maxmind.subdivisions) > 0:
                val = "{}, subdivision={}".format(val, ", subdivision=".join(
                    ["<{}/{}>".format(s.geoname_id, s.name) for s in self.maxmind_result.maxmind.subdivisions]))

            if self.maxmind_result.maxmind.country:
                val = "{}, country=<{}/{}>".format(val, self.maxmind_result.maxmind.country.geoname_id,
                                                   self.maxmind_result.maxmind.country.name)
            else:
                val += ", country=<>"

            if self.maxmind_result.maxmind.represented_country:
                val = "{}, represented_country=<{}/{}>".format(val,
                                                               self.maxmind_result.maxmind.represented_country.geoname_id,
                                                               self.maxmind_result.maxmind.represented_country.name)

            if self.maxmind_result.maxmind.registered_country:
                val = "{}, registered_country=<{}/{}>".format(val,
                                                              self.maxmind_result.maxmind.registered_country.geoname_id,
                                                              self.maxmind_result.maxmind.registered_country.name)

            if self.maxmind_result.maxmind.location:
                val = "{}, lat={}, lon={}, rad={}km".format(val, self.maxmind_result.maxmind.location.latitude,
                                                            self.maxmind_result.maxmind.location.longitude,
                                                            self.maxmind_result.maxmind.location.accuracy_radius)

        if self.blocked:
            return "{}, blocked=True, matched={}".format(val, self.matched)

        return val

    def __cmp__(self, other):
        return (self.user == other.user and
                self.password == other.password and
                self.service == other.service and
                self.ip == other.ip and
                self.rev_host == other.rev_host and
                self.whois_result == other.whois_result and
                self.maxmind_result == other.maxmind_result and
                self.blocked == other.blocked and
                self.matched == other.matched and
                self.log == other.log and
                self.reserved == other.reserved)

    def __hash__(self):
        return hash((self.user, self.password, self.service, self.ip, self.rev_host, self.whois_result, self.maxmind_result,
                     self.blocked, self.matched, self.log))


@lru_cache(maxsize=16)
def lookup(ip: str, service: str, user: str, password_id: Optional[int] = None) -> LookupResult:
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        logger.debug("lookup for %s returned socket.herror/NXDOMAIN", ip)
        rdns = "<>"

    result = LookupResult(user=user, service=service, ip=ip, rev_host=rdns, password=password_id)
    local_net = find_net(ip, get_settings().audit.local_networks.keys())
    if local_net is not None:
        logger.debug("%s is in local network %s, synthesizing WhoisResult", ip, local_net)
        result.whois_result = WhoisResult(asn=None, as_cc="ZZ", as_desc=get_settings().audit.local_locationname,
                                          net_name=get_settings().audit.local_networks[local_net], net_cc="ZZ",
                                          entities=[],
                                          reserved=True)
        result.log = get_settings().audit.log_local
    else:
        result.whois_result = check_whois(ip)
        result.maxmind_result = check_maxmind(ip)
    logger.debug(result)
    return result
