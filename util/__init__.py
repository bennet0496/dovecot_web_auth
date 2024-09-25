import json
import logging
import os
import re
import socket
import struct
from ipaddress import ip_address, ip_network
from os import PathLike
from typing import Iterable, Dict, Any, AnyStr, Optional

import geoip2.database
import geoip2.errors
import geoip2.models

import redis
from ipwhois import IPWhois
from ipwhois.utils import ipv4_is_defined, ipv6_is_defined

from models.maxmind import MMCity, MMResult
from models.whois import WhoisResult
from util.depends import get_settings

logger = logging.getLogger("dovecot_web_auth.util")

def maxmind_location_str(data: MMCity | None) -> str | None:
    if data is None:
        logger.debug("maxmind_location_str: no maxmind data")
        return None

    logger.debug(data)
    location = ""
    if data.postal_code:
        location += data.postal_code + " "

    if data.city.name:
        location += data.city.name + ", "

    if len(data.subdivisions) > 0:
        location += data.subdivisions[0].code + ", "

    if data.country.name:
        location += data.country.name

    logger.debug(location)
    return location

def find_net(ip: str, arr: Iterable[str]) -> str | None:
    logger.debug("find_net: searching for ip %s in %s", ip, arr)
    ipo = ip_address(ip)
    for net in arr:
        neto = ip_network(net)
        if int(ipo) & int(neto.netmask) == int(neto.network_address):
            return net
    return None

def check_whois_redis_cache(ip) -> dict[str, Any]:
    r = redis.Redis(get_settings().cache.host, get_settings().cache.port, decode_responses=True)
    logger.debug("check_whois_redis_cache: %s", r)
    netw = find_net(ip, r.keys("*/*"))
    logger.debug("check_whois_redis_cache: found %s in redis cache", netw)
    if netw:
        results = json.loads(r.get(netw))
    else:
        logger.debug("check_whois_redis_cache: contacting whois service")
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        logger.debug("check_whois_redis_cache: writing %s to redis", results['asn_cidr'])
        r.set(results['asn_cidr'], json.dumps(results))
        r.expire(results['asn_cidr'], 60 * 60 * 24)

    return results

def check_whois(ip: str) -> WhoisResult:
    if ip_address(ip).version == 4:
        reserved = ipv4_is_defined(ip)
    else:
        reserved = ipv6_is_defined(ip)

    if reserved[0]:
        logger.debug("check_whois: %s is reserved IPv%d: %s, synthesizing WhoisResult", ip, ip_address(ip).version, reserved)

        result = WhoisResult(asn=None, as_cc="ZZ", as_desc="IANA-RESERVED", net_name=reserved[1], net_cc="ZZ", entities=[], reserved=True)
    else:
        logger.debug("check_whois: sending whois")
        results = check_whois_redis_cache(ip)

        result = WhoisResult(asn="AS" + results['asn'],
                           as_cc=results['asn_country_code'] or "None",
                           as_desc=results['asn_description'],
                           net_name=results['network']['name'],
                           net_cc=results['network']['country'] or "None",
                           entities=results['entities'],
                           reserved=False)
    logger.debug(result)
    return result

def check_maxmind(ip: str) -> MMResult | None:
    logger.debug("check_maxmind: checking maxmind data")
    with geoip2.database.Reader(get_settings().audit.maxmind.city) as city_reader, geoip2.database.Reader(
            get_settings().audit.maxmind.asn) as asn_reader:
        try:
            city = city_reader.city(ip)
            asn = asn_reader.asn(ip)
            return MMResult(as_org=asn.autonomous_system_organization, maxmind=MMCity.from_mm(city))
        except geoip2.errors.AddressNotFoundError as e:
            logger.debug("check_maxmind: no maxmind data for %s: %s", ip, e)
            return None

def regexp_list(haystack: Iterable[AnyStr], needle: str) -> bool:
    for line in haystack:
        regexp = re.compile(line)
        if regexp is not None and regexp.match(needle):
            return True
    return False