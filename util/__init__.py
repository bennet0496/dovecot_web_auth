import json
import os
import re
import socket
import struct
from os import PathLike
from typing import Iterable, Dict, Any, AnyStr, Optional

import geoip2.database
import geoip2.errors
import geoip2.models

import redis
from ipwhois import IPWhois
from ipwhois.utils import ipv4_is_defined

from models.maxmind import MMCity, MMResult
from models.whois import WhoisResult
from util.depends import get_settings


def maxmind_location_str(data: MMCity | None) -> str:
    location = ""
    if "postal" in data:
        location += data["postal"]["code"] + " "

    if "city" in data:
        location += data["city"]["name"] + ", "

    if "subdivisions" in data:
        location += data["subdivisions"][0]["code"] + ", "

    if "country" in data:
        location += data["country"]["name"]
    return location

def find_net(ip: str, arr: Iterable[str]) -> str | None:
    packed_ip = socket.inet_aton(ip)
    ip_int = struct.unpack("!L", packed_ip)[0]
    for net_str in arr:
        net, mask = net_str.split("/")
        packed_net = socket.inet_aton(net)
        net_int = struct.unpack("!L", packed_net)[0]
        if net_int & (0xffffffff << (32 - int(mask))) == ip_int & (0xffffffff << (32 - int(mask))):
            return net_str
    return None

def check_whois_redis_cache(ip) -> dict[str, Any]:
    r = redis.Redis(get_settings().cache.host, get_settings().cache.port, decode_responses=True)
    netw = find_net(ip, r.keys("*/*"))
    if netw:
        results = json.loads(r.get(netw))
    else:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        r.set(results['asn_cidr'], json.dumps(results))
        r.expire(results['asn_cidr'], 60 * 60 * 24)

    return results

def check_whois(ip: str) -> WhoisResult:
    reserved = ipv4_is_defined(ip)
    if reserved[0]:
        return WhoisResult(asn=None, as_cc="ZZ", as_desc="IANA-RESERVED", net_name=reserved[1], net_cc="ZZ", entities=[], reserved=True)
    else:
        results = check_whois_redis_cache(ip)

        return WhoisResult(asn="AS" + results['asn'],
                           as_cc=results['asn_country_code'] or "None",
                           as_desc=results['asn_description'],
                           net_name=results['network']['name'],
                           net_cc=results['network']['country'] or "None",
                           entities=results['entities'],
                           reserved=False)

def check_maxmind(ip: str) -> MMResult | None:
    with geoip2.database.Reader(get_settings().audit.maxmind.city) as city_reader, geoip2.database.Reader(
            get_settings().audit.maxmind.asn) as asn_reader:
        try:
            city = city_reader.city(ip)
            asn = asn_reader.asn(ip)
            return MMResult(as_org=asn.autonomous_system_organization, maxmind=MMCity.from_mm(city))
        except geoip2.errors.AddressNotFoundError:
            return None

def regexp_list(haystack: Iterable[AnyStr], needle: str) -> bool:
    for line in haystack:
        regexp = re.compile(line)
        if regexp is not None and regexp.match(needle):
            return True
    return False