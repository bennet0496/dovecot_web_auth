import re
from functools import lru_cache
from ipaddress import ip_address, ip_network

from fastapi import status
from pydantic import BaseModel
from systemd import journal

from logger import rootlogger
from lookup import LookupResult
from util import iso_codes, regexp_list
from util.depends import get_settings, get_lists

logger = rootlogger.getChild("audit")


class AuditResult(BaseModel):
    status: str = ""
    status_code: int = 400
    matched: str | None = None
    log: bool = True


@lru_cache(maxsize=16)
def audit(lookup_result: LookupResult) -> AuditResult:
    # Disabled Services
    if lookup_result.service in get_settings().audit.disabled_services:
        logger.debug("audit: %s: %s is disabled", lookup_result.user, lookup_result.service)
        return AuditResult(status="{} is disabled".format(lookup_result.service), matched="service",
                           status_code=status.HTTP_403_FORBIDDEN)

    ip = ip_address(lookup_result.ip)
    # Never Block internal networks (except for disabled services)
    if ip.is_private:
        logger.debug("audit: %s: %s is private", lookup_result.user, ip)
        return AuditResult(status="success", status_code=status.HTTP_200_OK, log=get_settings().audit.log_local)

    ip_regex = re.compile(r"^([0-9a-fA-F.:]*/[0-9]{1,3})")

    if get_settings().audit.ignore_networks:
        for network in get_settings().audit.ignore_networks:
            net = ip_network(network, False)
            if int(ip) & int(net.netmask) == int(net.network_address):
                logger.debug("audit: %s: %s is ignored", lookup_result.user, ip)
                return AuditResult(status="success", status_code=status.HTTP_200_OK, log=False)

    # IP Networks
    if get_lists().ip_networks:
        for line in get_lists().ip_networks:
            if ip_regex.match(line):
                net = ip_network(ip_regex.search(line).groups()[0], False)
                if int(ip) & int(net.netmask) == int(net.network_address):
                    return AuditResult(status="access from {} is forbidden".format("/".join(str(net))), matched="ip",
                                       status_code=status.HTTP_403_FORBIDDEN)

    # Reverse Hostnames
    if get_lists().reverse_hostname and regexp_list(get_lists().reverse_hostname, lookup_result.rev_host):
        return AuditResult(status="access from this hostname is forbidden", matched="rev_host",
                           status_code=status.HTTP_403_FORBIDDEN)

    # Network Names
    if get_lists().network_name and regexp_list(get_lists().network_name, lookup_result.whois_result.net_name):
        return AuditResult(status="access from network {} is forbidden".format(lookup_result.whois_result.net_name),
                           matched="net_name", status_code=status.HTTP_403_FORBIDDEN)

    # Network Country Codes
    if get_lists().network_cc and lookup_result.whois_result.net_cc in map(lambda x: x.strip("\n\r \t"),
                                                                           get_lists().network_cc):
        return AuditResult(
            status="access from {} is forbidden".format(iso_codes.ISO_COUNTRY[lookup_result.whois_result.net_cc]),
            matched="net_cc", status_code=status.HTTP_403_FORBIDDEN)

    # Entities
    if get_lists().entities and len(set(lookup_result.whois_result.entities) & get_lists().entities) > 0:
        return AuditResult(status="access denied",
                           matched="entity:" + (set(lookup_result.whois_result.entities) & get_lists().entities).pop(),
                           status_code=status.HTTP_403_FORBIDDEN)

    # AS Numbers
    if get_lists().as_numbers:
        for line in get_lists().as_numbers:
            if lookup_result.whois_result.asn in re.findall(r"AS\d*", line):
                return AuditResult(status="access from {} is forbidden".format(
                    lookup_result.maxmind_result.as_org or lookup_result.whois_result.as_desc), matched="asn",
                    status_code=status.HTTP_403_FORBIDDEN)

    # AS Names
    if get_lists().as_names and (
            regexp_list(get_lists().as_names, lookup_result.whois_result.as_desc) or regexp_list(get_lists().as_names,
                                                                                                 lookup_result.maxmind_result.as_org)):
        return AuditResult(status="access from {} is forbidden".format(
            lookup_result.maxmind_result.as_org or lookup_result.whois_result.as_desc), matched="as_desc",
                           status_code=status.HTTP_403_FORBIDDEN)

    # AS Country Codes
    if get_lists().as_cc and lookup_result.whois_result.as_cc in map(lambda x: x.strip("\n\r \t"), get_lists().as_cc):
        return AuditResult(
            status="access from {} is forbidden".format(iso_codes.ISO_COUNTRY[lookup_result.whois_result.as_cc]),
            matched="net_cc", status_code=status.HTTP_403_FORBIDDEN)

    # Geo Location IDs
    if get_lists().geo_location_ids:
        for line in get_lists().geo_location_ids:
            try:
                geoid = int(line)
                for subval in lookup_result.maxmind_result.maxmind.model_dump().values():
                    if "geoname_id" in subval and subval["geoname_id"] == geoid:
                        return AuditResult(status="access from {} is forbidden".format(subval["name"]), matched="geoid",
                                           status_code=status.HTTP_403_FORBIDDEN)
            except ValueError:
                pass

    # Coordinates
    if get_lists().coordinates:
        for line in get_lists().coordinates:
            pass

    return AuditResult(status="success", status_code=200)


async def audit_log(audit_result: AuditResult, lookup_result: LookupResult):
    lookup_result.matched = audit_result.matched
    lookup_result.blocked = audit_result.status_code != 200

    if audit_result.log:
        logmodel = dict(map(lambda i: ("AUDIT_" + str(i[0]).upper(), i[1]),
                            lookup_result.model_dump(exclude={"maxmind_result", "whois_result"}).items()))
        maxmindmodel = dict(map(lambda i: ("AUDIT_MAXMIND_" + str(i[0]).upper(), i[1]),
                                lookup_result.maxmind_result.model_dump()[
                                    "maxmind"].items())) if lookup_result.maxmind_result and lookup_result.maxmind_result.maxmind else dict()
        whoismodel = dict(map(lambda i: ("AUDIT_" + str(i[0]).upper(), i[1]),
                              lookup_result.whois_result.model_dump().items())) if lookup_result.whois_result else dict()
        logger.debug(lookup_result)
        journal.send(str(lookup_result), **logmodel, **maxmindmodel, **whoismodel, SYSLOG_IDENTIFIER="mail-audit")
    else:
        logger.debug("audit_log: journal disabled")
