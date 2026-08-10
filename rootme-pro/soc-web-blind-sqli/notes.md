# SOC Web - Blind SQL Injection (Root-Me Pro)

- Category: SOC
- Difficulty: Medium
- Points: 300
- Est. time: ~1h
- Sub-type: SQLite Advanced

## Challenge Step 1
Scenario: while admin was on vacation, someone logged into their account. Nothing else has happened since.
Mission: analyze logs preceding this login to understand the attacker's entry point.
Index: `index-*-apache`
Goal: identify the administrator account password.

Access URL (token, session-scoped):
https://soc.challenges.root-me.pro/?token=<jwt redacted, see below>
Resource page: https://root-me.pro/ctf/resources/0197c566-d079-72f5-95c9-1dff6db52289

## Progress
- [x] Access Kibana/Elastic SOC interface
- [x] Query index-*-apache for logs before admin login
- [x] Identify SQLi payload / attacker IP
- [x] Extract admin password
- [x] All 3 steps answered — writeup.md written

## Findings

**Target app**: `colorblind.dash` (Apache). Index resolved to `index-4ee4e12f0116-apache`, 1867 docs.

**Access method**: OpenSearch Dashboards (`osd-name: soc-dashboards`). No browser needed —
grab the session cookie from the `?token=` redirect, then hit the console proxy:
```
curl -s -c cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"
curl -s -b cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST 'https://soc.challenges.root-me.pro/api/console/proxy?path=index-*-apache/_search&method=POST' \
  -d '{"size":2000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}'
```
`_cat/indices` is blocked (403, no `cluster:monitor/state`) but `_search` on the tenant index works.

**Attacker IP**: `34.12.66.71` — 735 of 1867 requests.

**Timeline (CEST, 13 Jun 2025)**:
| Time | Event |
|---|---|
| 15:22:40 | First visit to `/` |
| 15:25:48 / 15:25:52 | Two failed logins `POST /admin/` → 401 (4454 bytes) |
| ~15:26–15:33 | Content discovery: `/.env`, `/.git/HEAD`, `/backup.zip`, `/config.yaml`, `/init.sql`, `/passwords.txt`… (dot/slash URL-encoded as `%2e`/`%2f`) — all 404 |
| 15:34:29–15:35:14 | Oracle tuning — payload probes on position 1 |
| 15:36:15–15:38:29 | Blind SQLi extraction, positions 1→10 |
| 15:39:03 | `POST /admin/` → **200** (233 bytes) — successful login |

**Vulnerability**: blind SQL injection in the **User-Agent header** (not the URL — no query
strings anywhere in the logs, which is why it hides from normal request-param triage).

Payload template:
```
' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),N,1)='C') and 1=load_extension(1)--
```

**Oracle**: `load_extension()` is disabled in default SQLite builds and raises an error when
evaluated. `OR` short-circuits — if the SUBSTR comparison is FALSE the right side never runs and
the page renders normally (1953/1954 bytes). If TRUE, `load_extension(1)` fires and the app returns
a short error page (**461 bytes**). Error-size, not error-status: every response was HTTP 200.

**Extraction** (461-byte responses in the 15:36+ run):

| Pos | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Char | N | e | 0 | m | 4 | t | r | 1 | X | — |

Position 10 exhausted the full 62-char alphanumeric charset with no TRUE hit → string ends at 9.

## Credentials / Flags

**Admin password: `Ne0m4tr1X`**  ← Step 1 answer

## Step 2 — total requests sent by the attacker

**Answer: `735`**

Confirmed server-side rather than by local grep:
```
POST index-*-apache/_count   {"query":{"term":{"clientip":"34.12.66.71"}}}   -> 735
POST index-*-apache/_count   {"query":{"match_all":{}}}                      -> 1867
```
Terms aggregation over `clientip` for the whole index:

| IP | Requests |
|---|---|
| **34.12.66.71** | **735** |
| ::1 (localhost) | 64 |
| 138.197.63.241 | 30 |
| 3.219.110.76 | 28 |
| 91.198.174.192 | 28 |

735 vs 64 for the runner-up — the attacker is unambiguous. Breakdown of those 735 by verb/status:

| Verb | Status | Count | What |
|---|---|---|---|
| GET | 200 | 695 | 664 × `/` (640 of them SQLi probes) + static assets + `/admin/` |
| GET | 404 | 37 | content discovery (`.env`, `.git/HEAD`, `backup.zip`, …) + favicon |
| POST | 401 | 2 | failed admin logins at 15:25 |
| POST | 200 | 1 | successful admin login at 15:39:03 |

## Step 3 — payload that obtained the 4th password character

**Answer:**
```
' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),4,1)='m') and 1=load_extension(1)--
```

Sent in the User-Agent header of a `GET /`. Only one position-4 probe returned the 461-byte
oracle-TRUE page, at `2025-06-13T13:37:16.741083Z` — the char is `m`, matching position 4 of
`Ne0m4tr1X`.

Query used:
```python
[s for s in docs if s['clientip']=='34.12.66.71'
                 and ',4,1)' in s['agent'] and s['bytes'] < 1000]
```
