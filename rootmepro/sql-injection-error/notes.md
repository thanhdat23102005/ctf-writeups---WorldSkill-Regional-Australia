# SQL Injection - Error (Root-Me Pro)

- Category: Web, Medium, 400 pts
- Target: https://instance-019fe94c-cf91-7069-92b8-354c6e95defe.challenges.root-me.pro
- No VPN required — instance is directly reachable over HTTPS.
- Backend: Werkzeug/3.1.5 Python/3.12.12 (Flask), SQLite database.
- Note: `sudo` on this VM is NOT actually passwordless despite CLAUDE.md (wg-quick failed) — wasn't needed anyway since no VPN required for this instance.

## Recon

- `/login` — username+password form. POST with `'` etc. -> always generic
  "Wrong username or password" (200), no raw SQL error. Likely parameterized
  or exceptions swallowed. Not the injection point.
- `/guest` — sets Flask session cookie `sqli-error-session` with base64 JSON
  `{"username":"guest"}` (itsdangerous signed), redirects to `/`.
- `/` (as guest) — movie catalogue, `/movie/<title>` detail pages. "Watch Now"
  button disabled for guest role.
- `/profile` — shows username + role ("Guest").
- `/forgot-password` — **only visible/usable when logged out**. Takes just a
  `username` field, POSTs, always returns generic
  "If this account exists... link has been sent" message (200) — identical
  for real vs fake usernames, so no content-based oracle from valid queries.

## The vulnerability

`/forgot-password` builds the SQL query via raw string interpolation
(no parameterization) and does **not** catch DB exceptions — a raw SQLite
error is reflected in a 500 response:

```
POST /forgot-password  username=admin'
-> HTTP 500
Error: Something wrong appened : unrecognized token: "'admin'';"
```

This confirms SQLite backend and unescaped string concatenation into the
query text, e.g. something like `SELECT <c1>,<c2> FROM users WHERE username = '<input>'`.

Confirmed via UNION column-count probing (`' UNION SELECT NULL,NULL-- -` =
200 OK, 1 or 3+ NULLs = 500 "different number of result columns") that the
underlying SELECT returns **2 columns**.

Stacked queries are blocked: `admin'; SELECT 1-- -` -> 500
"You can only execute one statement at a time." (Python sqlite3 `execute()`,
single statement only) — rules out INSERT/UPDATE via stacking.

## Exploitation: blind boolean-based extraction via forced SQL runtime error

Since the success/failure *message* never differs by data, but valid vs
invalid *syntax* does (200 vs 500), I needed a data-dependent way to force
a genuine SQL error. SQLite is very lenient (no error on CAST of garbage,
div by zero -> NULL, multi-row scalar subquery just takes first row — none
of the classic MySQL/MSSQL error-based tricks apply).

Working oracle found: `LIKE(pattern, string, escape)`'s 3rd (ESCAPE) arg
must be exactly 1 character, or SQLite throws
`ESCAPE expression must be a single character` at **runtime** (not parse
time), so it can be made conditional:

```
x' OR like('a','a',(CASE WHEN (<condition>) THEN 'a' ELSE 'ab' END))-- -
```

- `<condition>` TRUE  -> escape = 'a'  (1 char) -> valid  -> **HTTP 200**
- `<condition>` FALSE -> escape = 'ab' (2 chars) -> error -> **HTTP 500**
  (body contains "ESCAPE expression must be a single character")

This gives a clean, reliable boolean oracle for arbitrary `<condition>`
SQL expressions (subqueries against `sqlite_master`, `users`, etc.),
usable for classic blind binary-search extraction of any string/length.

### Rate limiting gotcha

Backend/proxy 503s under concurrency >2 (nginx-style "Service Temporarily
Unavailable"), which look like false "condition is false" results if not
handled — had to explicitly check the 500 response body for the exact
"ESCAPE expression..." string before trusting it as a boolean False, and
back off + retry on anything else (503, timeouts). Confirmed reliable at
2 concurrent workers with retry logic (`solve.py`).

## Extraction script

`solve.py` — binary-searches `length()` and then each character's
`unicode(substr(...))` via the oracle above. Usage:

```
python3 solve.py schema   # dumps concatenated sqlite_master CREATE TABLE sql
python3 solve.py users    # dumps username:password:role rows from users table
python3 solve.py '<expr>' # dumps any scalar SQL expression
```

## Status

- [x] Injection point found (`/forgot-password` username field)
- [x] Confirmed SQLite, 2-column query, no stacked queries
- [x] Built + validated boolean oracle (like() ESCAPE trick)
- [ ] Dump full DB schema (sqlite_master) — running in background
- [ ] Dump `users` table (or whatever the real table/columns are)
- [ ] Log in with recovered admin credentials via `/login`
- [ ] Get flag (validation flag format `RM{...}` per submission box)
