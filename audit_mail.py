import json
from datetime import datetime
from json import JSONDecodeError

import yaml
from systemd import journal
# from datetime import datetime, timedelta
import datetime
import re
import sys
from collections import Counter

with open(sys.argv[1], "r") as f:
    info = yaml.safe_load(f)

if "KNOWN_GOOD_ASNS" in info.keys():
    KNOWN_GOOD_ASNS = info["KNOWN_GOOD_ASNS"]
else:
    KNOWN_GOOD_ASNS = []
if "KNOWN_DNS_SUFF" in info.keys():
    KNOWN_DNS_SUFF = info["KNOWN_DNS_SUFF"]
else:
    KNOWN_DNS_SUFF = []
if "AS_COMMENTS" in info.keys():
    AS_COMMENTS = dict(dict(d).popitem() for d in info['AS_COMMENTS'])
else:
    AS_COMMENTS = {}


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
            e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(("as_org" in e and e["as_org"] or e["as_desc"])[:30] + (("as_org" in e and e["as_org"] or e["as_desc"])[30:] and ".."))
        ) for e in data if
        len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) == 0 and e["asn"] not in KNOWN_GOOD_ASNS])
    new_asn = Counter(
        ["{} {} {}".format(
            ((e["blocked"] and "!" or "") + str(e["asn"])).ljust(10, ' '),
            e["as_org"] or e["as_desc"],
            (e["asn"] in AS_COMMENTS.keys() and "({})".format(AS_COMMENTS[e["asn"]]) or "")
        ) for e in data if e["asn"] not in KNOWN_GOOD_ASNS])

    old_ips = Counter([
        "{0} {1}".format(
            ((e["blocked"] and "!" or "") + e["ip"]).ljust(16, ' '),
            e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(("as_org" in e and e["as_org"] or e["as_desc"])[:30] + (("as_org" in e and e["as_org"] or e["as_desc"])[30:] and ".."))
        ) for e in data if len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) > 0 and e["asn"] in KNOWN_GOOD_ASNS])

    old_asn = Counter(
        ["{} {} {}".format(
            e["asn"].ljust(10, ' '),
            e["as_org"] or e["as_desc"],
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
