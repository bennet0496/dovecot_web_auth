import os
import re
import socket
import struct

from ipwhois.utils import ipv4_is_defined
from pydantic import BaseModel
from fastapi import status

import iso_codes
from config import Settings
from models import LookupResult
from util import regexp_file


class AuditResult(BaseModel):
    status: str = ""
    status_code: int = 400
    matched: str | None = None


def audit(result: LookupResult, settings: Settings) -> AuditResult:

    # Never Block internal networks
    if ipv4_is_defined(result.ip)[0]:
        return AuditResult(status="success", status_code=status.HTTP_200_OK)

    # Disabled Services
    if result.service in settings.audit.disabled_services:
        return AuditResult(status="{} is disabled".format(result.service), matched="service", status_code=status.HTTP_403_FORBIDDEN)

    # IP Networks
    if settings.audit.lists.ip_networks and os.path.isfile(settings.audit.lists.ip_networks):
        packed_ip = socket.inet_aton(result.ip)
        ip_int = struct.unpack("!L", packed_ip)[0]
        with open(settings.audit.lists.ip_networks, "r") as f:
            for line in f.readlines():
                ip = re.compile(r"^([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/([0-9]{1,2})")
                if not line.startswith("#") and not line.isspace() and ip.match(line):
                    addr, mask = ip.search(line).groups()
                    packed_net = socket.inet_aton(addr)
                    net_int = struct.unpack("!L", packed_net)[0]
                    if net_int & (0xffffffff << (32 - int(mask))) == ip_int & (0xffffffff << (32 - int(mask))):
                        return AuditResult(status="access from {} is forbidden".format("/".join(ip.findall(line)[0])),
                                           matched="ip_net", status_code=status.HTTP_403_FORBIDDEN)

    # Reverse Hostnames
    if settings.audit.lists.reverse_hostname and regexp_file(settings.audit.lists.reverse_hostname, result.host):
        return AuditResult(status="access from this hostname is forbidden",
                           matched="rev_host", status_code=status.HTTP_403_FORBIDDEN)

    # Network Names
    if settings.audit.lists.network_name and regexp_file(settings.audit.lists.network_name, result.net_name):
        return AuditResult(status="access from network {} is forbidden".format(result.net_name),
                           matched="net_name", status_code=status.HTTP_403_FORBIDDEN)

    # Network Country Codes
    if settings.audit.lists.network_cc and os.path.isfile(settings.audit.lists.network_cc):
        with open(settings.audit.lists.network_cc, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0 and \
                        result.net_cc == line.strip("\n\r \t"):
                    return AuditResult(status="access from {} is forbidden".format(iso_codes.ISO_COUNTRY[result.net_cc]),
                                       matched="net_cc", status_code=status.HTTP_403_FORBIDDEN)

    # Entities
    if settings.audit.lists.entities and os.path.isfile(settings.audit.lists.entities):
        with open(settings.audit.lists.entities, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0 and \
                        line.strip("\n\r \t") in result.entities:
                    return AuditResult(status="access denied",
                                       matched="entity", status_code=status.HTTP_403_FORBIDDEN)

    # AS Numbers
    if settings.audit.lists.as_numbers and os.path.isfile(settings.audit.lists.as_numbers):
        with open(settings.audit.lists.as_numbers, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0:
                    if result.asn in re.findall(r"AS\d*", line):
                        return AuditResult(status="access from {} is forbidden".format(result.as_org or result.as_desc),
                                            matched="asn", status_code=status.HTTP_403_FORBIDDEN)

    # AS Names
    if settings.audit.lists.as_names and (regexp_file(settings.audit.lists.as_names, result.as_desc) or
                                          regexp_file(settings.audit.lists.as_names, result.as_org)):
        return AuditResult(status="access from {} is forbidden".format(result.as_org or result.as_desc),
                           matched="as_name", status_code=status.HTTP_403_FORBIDDEN)

    # AS Country Codes
    if settings.audit.lists.as_cc and os.path.isfile(settings.audit.lists.as_cc):
        with open(settings.audit.lists.as_cc, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0 and \
                        result.as_cc == line.strip("\n\r \t"):
                    return AuditResult(status="access from {} is forbidden".format(iso_codes.ISO_COUNTRY[result.as_cc]),
                                       matched="as_cc", status_code=status.HTTP_403_FORBIDDEN)

    # Geo Location IDs
    if settings.audit.lists.geo_location_ids and os.path.isfile(settings.audit.lists.geo_location_ids):
        with open(settings.audit.lists.geo_location_ids, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0:
                    try:
                        geoid = int(line)
                        for subval in result.maxmind.values():
                            if "geoname_id" in subval and subval["geoname_id"] == geoid:
                                return AuditResult(status="access from {} is forbidden".format(subval["names"]["en"]),
                                       matched="geoid", status_code=status.HTTP_403_FORBIDDEN)
                    except ValueError:
                        pass

    # Coordinates
    if settings.audit.lists.coordinates and os.path.isfile(settings.audit.lists.coordinates):
        with open(settings.audit.lists.coordinates, "r") as f:
            for line in f.readlines():
                pass

    return AuditResult(status="success", status_code=200)
