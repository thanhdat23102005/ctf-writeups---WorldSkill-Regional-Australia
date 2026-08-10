#!/usr/bin/env python3
"""Dump every request the webhook.site collector has received, newest first."""
import json
import sys
import urllib.parse

import requests

UUID = sys.argv[1] if len(sys.argv) > 1 else "1c193db3-164e-4804-8c79-ada6bbd6bab5"

d = requests.get(
    f"https://webhook.site/token/{UUID}/requests",
    params={"sorting": "newest", "per_page": 50},
    timeout=20,
).json()

print("TOTAL:", d.get("total"))
for r in d.get("data", []):
    ua = (r.get("headers", {}).get("user-agent") or [""])[0]
    print("---", r.get("created_at"), r.get("method"), r.get("url")[:130])
    print("    UA:", ua[:90])
    for k, v in (r.get("query") or {}).items():
        print(f"    {k} = {urllib.parse.unquote(str(v))[:1200]}")
