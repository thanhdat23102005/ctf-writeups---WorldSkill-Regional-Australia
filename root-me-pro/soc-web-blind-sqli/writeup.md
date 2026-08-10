# SOC Web — Blind SQL Injection

| | |
|---|---|
| **Platform** | Root-Me Pro |
| **Category** | SOC / Log Analysis |
| **Sub-type** | SQLite Advanced |
| **Difficulty** | Medium |
| **Points** | 300 |
| **Index** | `index-*-apache` (resolved to `index-4ee4e12f0116-apache`, 1867 docs) |

## Challenge

> While the administrator was on vacation, someone logged into their account. Since then, nothing
> else has happened. Your mission is to analyze the logs preceding this login to understand the
> attacker's point of entry.

Three steps:

1. Identify the administrator account password.
2. Identify the total number of requests sent by the attacker.
3. Identify the payload used to obtain the **4th** character of the compromised password.

This is a **defensive** exercise — we never touch the vulnerable app (`colorblind.dash`), which no
longer exists. Everything is reconstructed from Apache access logs already shipped into OpenSearch.

## Answers

| Step | Answer |
|---|---|
| 1 | `Ne0m4tr1X` |
| 2 | `735` |
| 3 | `' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),4,1)='m') and 1=load_extension(1)--` |

## Approach

### 1. Talk to OpenSearch directly instead of clicking through Dashboards

The challenge link is a JWT-bearing URL that 302s into OpenSearch Dashboards (the response carries
`osd-name: soc-dashboards`). Rather than driving Discover in a browser, exchange the token for a
session cookie once and then query the cluster through the Dashboards console proxy:

```bash
TOKEN='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...'

# The ?token= redirect sets security_authentication* cookies
curl -s -c cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"

# Now any _search / _count is reachable through the console proxy
curl -s -b cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST 'https://soc.challenges.root-me.pro/api/console/proxy?path=index-*-apache/_search&method=POST' \
  -d '{"size":2000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}' > files/apache_raw.json
```

Notes on the two non-obvious bits:

- `osd-xsrf: true` is mandatory — OpenSearch Dashboards rejects any state-changing API call
  without it. (Kibana's equivalent is `kbn-xsrf`.)
- The proxy takes the real ES path and verb as **query parameters**
  (`?path=<index>/_search&method=POST`), not as the request path.

Admin APIs are locked down for this tenant — `_cat/indices` returns
`403 no permissions for [cluster:monitor/state]` — but `_search` and `_count` against the tenant's
own index work fine. That's all we need. 1867 documents is small enough to pull down whole and
analyze offline.

### 2. Find the attacker

A terms aggregation over `clientip` makes this a one-liner:

```json
{"size":0,"aggs":{"ips":{"terms":{"field":"clientip","size":5}}}}
```

| IP | Requests |
|---|---|
| **34.12.66.71** | **735** |
| `::1` (localhost) | 64 |
| 138.197.63.241 | 30 |
| 3.219.110.76 | 28 |
| 91.198.174.192 | 28 |

735 out of 1867 from a single IP, against 64 for the runner-up. No ambiguity — **`34.12.66.71`**.

### 3. The dead end that matters

The obvious next move is to look at what those 735 requests asked for:

```bash
grep -oP '"\K(GET|POST) [^"]+' files/attacker.log | sed 's/ HTTP.*//' | sort | uniq -c | sort -rn
```

```
    664 GET /
      6 GET /static/js/custom/script.js
      6 GET /admin/
      3 POST /admin/
      ...
      1 GET /%2eenv
      1 GET /%2egit%2fHEAD
      1 GET /backup%2ezip
```

Two things stand out. There's a burst of content-discovery 404s (`.env`, `.git/HEAD`, `backup.zip`,
`init.sql`, `passwords.txt` — with dots and slashes URL-encoded as `%2e`/`%2f`, a light WAF-evasion
habit), all of which failed. And then **664 identical requests to `/`**.

Grepping for a query string returns nothing:

```bash
grep -c '?' files/attacker.log   # 0
```

Not a single request in the entire index carries a query string. So the injection is not in the URL
— and any triage that only looks at request parameters finds nothing here. It has to be in a header
that Apache logs. Apache's combined format logs exactly two: `Referer` and `User-Agent`.

### 4. The payload

Aggregating `agent` across the attacker's requests gives it up immediately:

```python
collections.Counter(s['agent'] for s in atk).most_common(5)
```

```
Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0                              6
' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),1,1)='a') and 1=load_extension(1)--   3
' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),2,1)='a') and 1=load_extension(1)--   2
...
```

640 of the 664 `GET /` requests carry a SQL injection payload **in the User-Agent header**. The app
was logging the UA into a SQLite database — probably an analytics or visitor table — via string
concatenation.

## Vulnerability

Blind (boolean-based) SQL injection into a SQLite backend, reached through the `User-Agent` request
header rather than any user-facing parameter.

Payload template:

```sql
' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),N,1)='C') and 1=load_extension(1)--
```

The clever part is the oracle. There is no visible output difference to work with, so the attacker
manufactured one using `load_extension()`:

- `load_extension()` is **disabled in default SQLite builds** (`SQLITE_OMIT_LOAD_EXTENSION`, or
  simply not enabled at the API level). Evaluating it raises `not authorized`.
- SQL boolean operators **short-circuit**. In `A or (B and C)`, if `B` is false, `C` is never
  evaluated.

So:

| `SUBSTR(...)='C'` | `1=load_extension(1)` | Result |
|---|---|---|
| FALSE | never evaluated | query succeeds, page renders normally |
| TRUE | evaluated → SQLite error | app throws, returns a short error page |

The attacker turned "does this character match?" into "does the app crash?".

**What this looks like in the logs is the detection lesson:** every single one of those 640
responses is **HTTP 200**. The only signal is response size.

```python
collections.Counter(s['bytes'] for s in probes).most_common()
# [(1953, 521), (1954, 105), (461, 9), (468, 2), (467, 2), (466, 1)]
```

- **1953 / 1954 bytes** → normal homepage → guess was wrong
- **461 bytes** → error page → **guess was correct**

If you pivot on status code you see nothing. You have to pivot on `bytes`.

## Solution

### Step 1 — the password

Filter to the attacker's payload requests, parse position and candidate character out of the
User-Agent, and keep the ones that returned the 461-byte error page.

```python
pat = re.compile(r"\),(\d+),1\)='(.)'")
probes = [(int(m.group(1)), m.group(2), d['bytes'], d['@timestamp'])
          for d in docs if d.get('clientip') == '34.12.66.71'
          if (m := pat.search(d.get('agent') or ''))]

# 13:34–13:35 is the attacker tuning their oracle on position 1; keep the clean run
run = [p for p in sorted(probes, key=lambda p: p[3]) if p[3] > '2025-06-13T13:36:00']
```

That filter matters. There are 14 total oracle-TRUE responses but only 9 characters. The five extras
sit at 13:34:29–13:35:14, all on position 1, all with slightly different sizes (466/467/468 bytes) —
the attacker experimenting to find a reliable oracle before committing. The real extraction run is
the consistent 461-byte set from 13:36:15 onward.

Walking that run position by position:

| Pos | Probes until hit | Char | Time (UTC) |
|---|---|---|---|
| 1 | 15 of 63 | `N` | 13:36:15 |
| 2 | 32 of 63 | `e` | 13:36:48 |
| 3 | 56 of 63 | `0` | 13:37:02 |
| 4 | 40 of 63 | `m` | 13:37:16 |
| 5 | 58 of 63 | `4` | 13:37:31 |
| 6 | 41 of 63 | `t` | 13:37:51 |
| 7 | 43 of 63 | `r` | 13:38:07 |
| 8 | 55 of 63 | `1` | 13:38:18 |
| 9 | 24 of 63 | `X` | 13:38:29 |
| 10 | all 63 exhausted | — | — |

Position 10 burned the attacker's full 62-character alphanumeric charset with no hit, which is how
they knew to stop. That's the password boundary.

> **Password: `Ne0m4tr1X`**

Note the charset order in the probes — `aCBADEFGHIJKMNLOPQSRTUVWXYaZbdcefhijglkmnpqstoruvwxy0z341695278` —
shuffled, not sequential. Also note that case survives: SQLite's `=` on TEXT is case-sensitive by
default, so the uppercase `N` and `X` are real, not artifacts.

### Step 2 — request count

```bash
curl -s -b cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST 'https://soc.challenges.root-me.pro/api/console/proxy?path=index-*-apache/_count&method=POST' \
  -d '{"query":{"term":{"clientip":"34.12.66.71"}}}'
# {"count":735, ...}
```

> **735**

Breakdown by verb and status:

| Verb | Status | Count | What |
|---|---|---|---|
| GET | 200 | 695 | 664 × `/` (640 of them SQLi probes) + static assets + `/admin/` |
| GET | 404 | 37 | content discovery + favicon |
| POST | 401 | 2 | failed admin logins at 15:25 |
| POST | 200 | 1 | successful admin login at 15:39:03 |

### Step 3 — the position-4 payload

Only one probe targeting position 4 returned the oracle-TRUE page:

```python
[s for s in docs if s['clientip'] == '34.12.66.71'
                and ',4,1)' in (s.get('agent') or '')
                and s['bytes'] < 1000]
# 2025-06-13T13:37:16.741083Z  200  461
```

> ```
> ' or (SUBSTR((SELECT password FROM users where username LIKE '%admin%'),4,1)='m') and 1=load_extension(1)--
> ```

`m` — position 4 of `Ne0m4tr1X`. ✓

## Full attack timeline

All times CEST (logs are `+0200`; the `@timestamp` field is UTC).

| Time | Event |
|---|---|
| 15:22:40 | First visit to `/`, normal Firefox UA |
| 15:25:48, 15:25:52 | Two failed logins `POST /admin/` → 401 — credential guessing fails |
| ~15:26–15:33 | Content discovery: `.env`, `.git/HEAD`, `backup.zip`, `config.yaml`, `init.sql`, `passwords.txt`, `Dockerfile`… all 404 |
| 15:34:29–15:35:14 | Oracle tuning — 5 probes on position 1, refining the error condition |
| 15:36:15–15:38:29 | Blind SQLi extraction, 640 probes, positions 1→10 |
| **15:39:03** | `POST /admin/` → **200** — login succeeds with `Ne0m4tr1X` |

The whole compromise took 16 minutes and 23 seconds. The two failed logins at the start and the one
successful login at the end are the bookends; everything in between is the attacker earning the
password.

## Lessons

**Blind SQLi can hide in any logged header.** No query string appeared anywhere in 1867 requests.
Triage that starts and ends at request parameters would have found nothing. Apache's combined format
logs `Referer` and `User-Agent` — check both. `X-Forwarded-For` too if the log format includes it.

**Aggregate the User-Agent field as routine hunting.** A `terms` agg on `agent` surfaced this in one
query. Attack payloads in a UA field are self-announcing once you look; the problem is that nobody
looks.

**HTTP 200 does not mean "nothing happened."** Every probe here returned 200. The application caught
its own exception and rendered an error page — so the only discriminator was `bytes`. When hunting
blind injection, aggregate response **size** and response **time**, not just status code. A bimodal
size distribution against a constant status code is the signature.

**`load_extension()` is a SQLite oracle primitive.** Where MySQL attackers reach for `SLEEP()` and
MSSQL for `WAITFOR DELAY`, SQLite has no sleep function. `load_extension()` is the common substitute:
it reliably errors, and short-circuit evaluation makes that error conditional on the injected
predicate. Others in the same family: `randomblob(...)` for a timing signal, or plain
`abs(-9223372036854775808)` for an integer-overflow error. Seeing `load_extension` in traffic is a
near-certain indicator of blind SQLite injection.

**Probe count is a fingerprint.** 63 attempts per position, a shuffled charset, ~15 seconds per
character — this is a hand-rolled script, not sqlmap (which would use binary search over character
ranges, ~7 requests per character, not 63 linear guesses). Attacker tooling sophistication is
readable straight from the request pattern.

**Watch for the tuning phase.** Those five extra oracle-TRUE hits at 13:34 with inconsistent response
sizes were the attacker calibrating. Naively collecting every TRUE response yields 14 hits for a
9-character password. In log analysis, the setup noise before the clean run is a real hazard — and
also a useful detection window, since it's when the attacker is at their loudest and least certain.

## Files

```
~/ctf/rootme-pro/soc-web-blind-sqli/
├── files/
│   ├── apache_raw.json   # full 1867-doc dump from OpenSearch
│   ├── apache.log        # flattened raw log lines
│   └── attacker.log      # 735 lines from 34.12.66.71
├── notes.md
├── solve.py              # reconstructs the password from the log trail
└── writeup.md
```
