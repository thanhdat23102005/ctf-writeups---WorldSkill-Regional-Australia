#!/usr/bin/env python3
"""Reconstruct the admin password from the attacker's blind-SQLi log trail.

Oracle: `and 1=load_extension(1)` errors out only when the SUBSTR comparison is
TRUE, shrinking the response from ~1953 bytes to a 461-byte error page.
"""
import collections
import json
import re
import sys

RAW = sys.argv[1] if len(sys.argv) > 1 else "files/apache_raw.json"
ATTACKER = "34.12.66.71"
ORACLE_TRUE_MAX_BYTES = 1000
PAYLOAD = re.compile(r"\),(\d+),1\)='(.)'")

docs = [h["_source"] for h in json.load(open(RAW))["hits"]["hits"]]

probes = []
for d in docs:
    if d.get("clientip") != ATTACKER:
        continue
    m = PAYLOAD.search(d.get("agent") or "")
    if m:
        probes.append((int(m.group(1)), m.group(2), d["bytes"], d["@timestamp"]))

# Earlier probes are the attacker tuning their oracle; keep the final clean run.
probes.sort(key=lambda p: p[3])
run = [p for p in probes if p[3] > "2025-06-13T13:36:00"]

by_pos = collections.defaultdict(list)
for pos, char, size, _ in run:
    by_pos[pos].append((char, size))

password = ""
for pos in sorted(by_pos):
    hit = [c for c, size in by_pos[pos] if size < ORACLE_TRUE_MAX_BYTES]
    if not hit:
        break
    password += hit[0]

print(f"probes: {len(probes)}  positions: {len(by_pos)}")
print(f"password: {password}")
