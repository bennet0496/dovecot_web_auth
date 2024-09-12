import json
import os
import re
import socket
import struct
from os import PathLike
from typing import Iterable, Dict, Any

import geoip2.database
import geoip2.errors

import redis
from ipwhois import IPWhois
from ipwhois.utils import ipv4_is_defined

from config import Settings


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


def check_whois_redis_cache(ip, settings: Settings):
    r = redis.Redis(settings.cache.host, settings.cache.port, decode_responses=True)
    netw = find_net(ip, r.keys("*/*"))
    if netw:
        results = json.loads(r.get(netw))
    else:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        r.set(results['asn_cidr'], json.dumps(results))
        r.expire(results['asn_cidr'], 60 * 60 * 24)

    return results


def check_whois(ip: str, settings: Settings) -> Dict[str, Any]:
    reserved = ipv4_is_defined(ip)
    if reserved[0]:
        return { "asn": None, "as_cc": "ZZ", "as_desc": "IANA-RESERVED", "net_name": reserved[1],
            "net_cc": "ZZ", "entities": [None], "reserved": True }
    else:
        results = check_whois_redis_cache(ip, settings)

        return {
            "asn": "AS" + results['asn'],
            "as_cc": results['asn_country_code'] or "None",
            "as_desc": results['asn_description'],
            "net_name": results['network']['name'],
            "net_cc": results['network']['country'] or "None",
            "entities": results['entities']
        }


def check_maxmind(ip: str, settings: Settings):

    with geoip2.database.Reader(settings.audit.maxmind.city) as city_reader, geoip2.database.Reader(
            settings.audit.maxmind.asn) as asn_reader:
        try:
            city = city_reader.city(ip)
            asn = asn_reader.asn(ip)

            return {
                "as_org": asn.autonomous_system_organization,
                "maxmind": city.raw
            }
        except geoip2.errors.AddressNotFoundError:
            return {}


def regexp_file(filename: str | PathLike, needle: str) -> bool:
    if os.path.isfile(filename):
        with open(filename, "r") as f:
            for line in f.readlines():
                if not line.startswith("#") and not line.isspace() and len(line) > 0:
                    if re.compile(line).match(needle):
                        return True
    return False
