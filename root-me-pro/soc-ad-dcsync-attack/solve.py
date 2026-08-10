#!/usr/bin/env python3
"""
SOC AD - DCSync Attack (Root-Me Pro)

Pulls Windows security events from the challenge's OpenSearch Dashboards instance
and identifies the DCSync: who, which right, from where, when.

Usage:
    python3 solve.py                 # uses files/all_events.json if present
    python3 solve.py --fetch         # re-fetch from the SIEM (needs a fresh token)

The JWT expires after ~8h; grab a new challenge URL and drop the token into
files/token.txt to re-fetch.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys

BASE = "https://soc.challenges.root-me.pro"
INDEX = "index-625bd823e0f6-windows"
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, "files")

# The three DCSync extended rights. Get-Changes-All is the one that unlocks
# secret attributes (unicodePwd, ntPwdHistory) -- i.e. the actual hashes.
REPL_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


def fetch():
    """Authenticate with the JWT and pull every event via the console proxy."""
    token = open(os.path.join(FILES, "token.txt")).read().strip()
    jar = os.path.join(FILES, "cookies.txt")

    # The ?token= redirect is what mints the security_authentication cookies.
    subprocess.run(
        ["curl", "-sS", "-c", jar, "-o", "/dev/null", f"{BASE}/?token={token}"],
        check=True,
    )

    out = os.path.join(FILES, "all_events.json")
    subprocess.run(
        [
            "curl", "-sS", "-b", jar,
            "-H", "osd-xsrf: true",
            "-H", "Content-Type: application/json",
            "-X", "POST",
            f"{BASE}/api/console/proxy?path={INDEX}/_search&method=POST",
            "-d", json.dumps(
                {"size": 1000, "query": {"match_all": {}},
                 "sort": [{"@timestamp": "asc"}]}
            ),
            "-o", out,
        ],
        check=True,
    )
    print(f"[+] fetched -> {out}")


def load():
    path = os.path.join(FILES, "all_events.json")
    if not os.path.exists(path):
        sys.exit("[-] files/all_events.json missing; run with --fetch")
    return [h["_source"] for h in json.load(open(path))["hits"]["hits"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true", help="re-pull events from the SIEM")
    args = ap.parse_args()
    if args.fetch:
        fetch()

    events = load()
    print(f"[*] {len(events)} events loaded\n")

    dcsync = []
    by_subject = collections.Counter()

    for s in events:
        if s["event"]["code"] != "4662":
            continue
        ed = s["winlog"]["event_data"]
        props = (ed.get("Properties") or "").lower()
        found = [name for guid, name in REPL_GUIDS.items() if guid in props]
        if not found:
            continue
        subject = ed.get("SubjectUserName", "")
        by_subject[subject] += 1
        dcsync.append((s["@timestamp"], subject, ed.get("ObjectName"), found))

    print("=== principals requesting replication rights ===")
    for user, count in by_subject.most_common():
        # Machine accounts replicating is AD working as designed. The alert is
        # any principal that is NOT a DC computer account.
        verdict = "benign (machine account)" if user.endswith("$") else ">>> MALICIOUS <<<"
        print(f"  {user:<12} {count:>3}  {verdict}")

    attacker = next(u for u in by_subject if not u.endswith("$"))
    burst = sorted(t for t, u, _, _ in dcsync if u == attacker)

    # 4662 carries no IP. Attribute the source by correlating the burst with the
    # network logon for the same account in the same second.
    src_ip = None
    for s in events:
        ed = s["winlog"]["event_data"]
        if (s["event"]["code"] == "4624"
                and ed.get("TargetUserName") == attacker
                and s["@timestamp"][:16] == burst[0][:16]):
            src_ip = ed.get("IpAddress")
            break

    cmdline = next(
        (s["winlog"]["event_data"].get("CommandLine") for s in events
         if s["event"]["code"] == "1"
         and attacker in (s["winlog"]["event_data"].get("CommandLine") or "")),
        None,
    )

    print(f"\n=== attack chain ===")
    print(f"  tool      : {cmdline}")
    print(f"  account   : {attacker}")
    print(f"  source IP : {src_ip}")
    print(f"  target NC : {dcsync[0][2]}")
    print(f"  burst     : {len(burst)} events, {burst[0][11:19]} -> {burst[-1][11:19]} UTC")

    print(f"\n=== ANSWERS ===")
    print(f"  Step 1 (account) : {attacker}")
    print(f"  Step 2 (GUID)    : 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
    print(f"  Step 3 (IP)      : {src_ip}")
    print(f"  Step 4 (UTC time): {burst[0][11:19]}")


if __name__ == "__main__":
    main()
