import json
from datetime import datetime
from json import JSONDecodeError

from systemd import journal
# from datetime import datetime, timedelta
import datetime
import re
import sys
from collections import Counter

KNOWN_GOOD_ASNS = [
    "AS680",    # DFN
    "AS207592", # GWDG
    "AS2200",   # Réseau national de télécommunications pour la technologie, l'enseignement et la recherche (EDU ISP)
    "AS56166",  # Indian Institute of Science Education and Research Bhopal
    "AS1835",   # FSKNET-DK Forskningsnettet - Danish network for Research and Education
    "AS40194",  # The University of Chicago Marine Biological Laboratory
    "AS3",      # Massachusetts Institute of Technology
    "AS3320",   # DTAG/Deutsche Telekom
    "AS204445", # DB WiFi
    "AS8447",   # A1 Telekom Austria
    "AS29580",  # A1 Bulgaria
    "AS8717",   # A1 Bulgaria
    "AS21928",  # t-mobile US
    "AS13036",  # t-mobile CZ
    "AS3215",   # France Telecom, Orange
    "AS9121",   # Türk Telekomünikasyon Anonim Şirketi
    "AS16232",  # Telecom Italia S.p.A.
    "AS8881",   # VERSATEL/1&1
    "AS3209",   # Vodafone DE
    "AS12430",  # Vodafone ES
    "AS12302",  # Vodafone RO
    "AS38266",  # Vodafone Idea Ltd, IN
    "AS25135",  # Vodafone UK
    "AS30722",  # Vodafone IT
    "AS6805",   # Telefonica/O2 DE
    "AS3352",   # Telefonica ES
    "AS5610",   # O2 CZ
    "AS35228",  # O2 GB
    "AS16202",  # Telecolumbus/Pÿur
    "AS20676",  # Plusnet https://www.plusnet.de/
    "AS60294",  # Deutsche Glasfaser
    "AS7922",   # Comcast US
    "AS15600",  # Quickline CH
    "AS12874",  # Fastweb IT
    "AS51207",  # Free Mobile SAS, FR
    "AS54004",  # Optimum WiFi US
    "AS8002",   # Stealth, NYC ISP, US
    "AS26615",  # TIM (Brazillian ISP)
    "AS1257",   # TELE2, SE
    "AS5089",   # Virgin Media Consumer Broadband UK
    "AS16205",  # DSI -> DresdenRooms (Coschütz)
    "AS40959",  # Denver International Airport
]
KNOWN_DNS_SUFF = [
    "mpg.de",
    "pool.telefonica.de",
    "dynamic.kabel-deutschland.de",
    "dip0.t-ipconnect.de",
    "customers.d1-online.com",
    "versanet.de",
    "dyn.pyur.net",
    "web.vodafone.de",
    "cam.ac.uk",
    "oxuni.org.uk",
    "net.ed.ac.uk",
    "res.spectrum.com",
    "cable.virginm.net",
]

AS_COMMENTS = {
    "AS136787": "Commercial VPN", # TEFINCOMSA -> NordVPN
    "AS212238": "Commercial VPN", # CDNEXT, GB -> NordVPN/ProtonVPN
    "AS60068": "Commercial VPN", # CDN77 _, GB -> NordVPN/ProtonVPN
    "AS14618": "Commercial VPN or Bad App", # Amazon
    "AS147049": "Commercial VPN", # PACKETHUBSA-AS-AP PacketHub S.A., AU
    "AS786": "Cambridge University",
    "AS44407": "Business ISP",
    "AS15372": "Business ISP and Hosting Company in DD and B", # IBH
    "AS8002": "NYC ISP", # Stealth
    "AS16276": "French Hosting/Cloud Company", # OVH
    "AS5089": "Virgin Media Limited",
    "AS62240": "Commercial VPN (Surfshark)",
    "AS209103": "Commercial VPN (ProtonVPN)",
    "AS16205": "DSI -> DresdenRooms (Coschütz)",
    "AS40959": "Denver International Airport",
}


if __name__ == "__main__":
    j = journal.Reader()
    since = datetime.datetime.now() - datetime.timedelta(hours=24, minutes=6)
    until = datetime.datetime.now(datetime.UTC)

    j.seek_realtime(since)
    data = list()
    for entry in j:
        if entry['__REALTIME_TIMESTAMP'] > until:
            break
        if "SYSLOG_IDENTIFIER" in entry and entry['SYSLOG_IDENTIFIER'] == "mail-audit":
            d = []
            for e in dict((str(i[0]).lower()[len("audit_"):], i[1]) for i in entry.items() if i[0].startswith("AUDIT_")).items():
                try:
                    d.append((e[0], json.loads(e[1].replace("'", "\""))))
                except JSONDecodeError:
                    if e[1] == "True":
                        d.append((e[0], True))
                    elif e[1] == "False":
                        d.append((e[0], False))
                    elif e[1] == "None":
                        d.append((e[0], None))
                    else:
                        d.append((e[0], str(e[1])))
            if len(d) > 0 and 'host' not in dict(d) and dict(d)['rev_host'] is not None:
                data.append(dict(d))
    # print(data)
    # sys.exit(0)
    print("Blocked users:")
    bu = set([e["user"] for e in data if e["blocked"]])
    for u in bu:
        print(" {} ({})".format(u, ", ".join(
            set(["{}:{}".format(e["matched"], e[e["matched"]] if e["matched"] in e else "") for e in data if e["blocked"] and e["user"] == u]))))


    def suffixes(str):
        arr = str.split(".")
        suf = []
        for _ in range(len(arr)):
            suf.append(".".join(arr))
            arr.pop(0)
        return suf


    new_ips = Counter([
        "{0} {1}".format(
            ((e["blocked"] and "!" or "") + e["ip"]).ljust(16, ' '),
            e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(e["as_desc"][:30] + (e["as_desc"][30:] and ".."))
        ) for e in data if
        len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) == 0 and e["asn"] not in KNOWN_GOOD_ASNS])
    new_asn = Counter(
        ["{} {} {}".format(
            ((e["blocked"] and "!" or "") + str(e["asn"])).ljust(10, ' '),
            e["as_desc"],
            (e["asn"] in AS_COMMENTS.keys() and "({})".format(AS_COMMENTS[e["asn"]]) or "")
        ) for e in data if e["asn"] not in KNOWN_GOOD_ASNS])

    old_ips = Counter([
        "{0} {1}".format(
            ((e["blocked"] and "!" or "") + e["ip"]).ljust(16, ' '),
            e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(e["as_desc"][:30] + (e["as_desc"][30:] and ".."))
        ) for e in data if len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) > 0 and e["asn"] in KNOWN_GOOD_ASNS])

    old_asn = Counter(
        ["{} {} {}".format(
            e["asn"].ljust(10, ' '),
            e["as_desc"],
            (e["asn"] in AS_COMMENTS.keys() and "({})".format(AS_COMMENTS[e["asn"]]) or "")
        ) for e in data if e["asn"] in KNOWN_GOOD_ASNS])

    print("\nStatistics")
    print(" {} unique ASNs, {} unknown, {} known".format(len(new_asn.keys()) + len(old_asn.keys()), len(new_asn.keys()),
                                                         len(old_asn.keys())))
    print(" {} unique IPs, {} unknown, {} known".format(len(new_ips.keys()) + len(old_ips.keys()), len(new_ips.keys()),
                                                        len(old_ips.keys())))


    def print_counter_list(ctr: Counter):
        if len(ctr.keys()) < 1:
            print("empty list")
            return
        most = ctr.most_common(1)[0][1]
        digits = len(str(most))
        print(" " + "\n ".join(["{} {}".format(str(e[1]).rjust(digits, ' '), e[0]) for e in ctr.most_common()]))


    print("\nUnknown ASNs")
    print_counter_list(new_asn)

    print("\nUnknown IPs and Hosts")
    print_counter_list(new_ips)

    print("\nKnown ASNs")
    print_counter_list(old_asn)

    print("\nKnown IPs and Hosts")
    print_counter_list(old_ips)
