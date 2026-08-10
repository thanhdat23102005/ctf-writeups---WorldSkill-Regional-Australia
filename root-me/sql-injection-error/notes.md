# Root-Me Pro — SQL Injection - Error (Rootflix)

- Category: Web, Medium, 400pts
- URLs:
  - https://root-me.pro/ctf/resources/0197c566-d079-72f5-95c9-1dff6db52289
  - https://root-me.pro/ctf/resources/0197c566-d291-71ed-b8b8-c38d736351cb
  - Instance: https://instance-019fe94c-cf91-7069-92b8-354c6e95defe.challenges.root-me.pro/
- Reachable directly (public), no VPN needed for this instance.
- App: "Rootflix" — Flask/Werkzeug + Python 3.12, backend DB = SQLite.
- Description: can log in as guest but can't watch films without a valid account.
  Goal: get access with enough privileges to watch films freely.

## Recon

- `/login` — POST username/password. Quote injection (`admin'`) does NOT error
  (200, generic page) — likely parametrized or errors swallowed.
- `/forgot-password` — POST `username`. **Vulnerable.**
  - `username=admin'` -> HTTP 500:
    `Error: Something wrong appened : unrecognized token: "'admin'';"`
    -> raw SQLite error, string-concatenated query, naive quote-doubling escaping.
  - Response body for valid POST is **always** the same success message
    regardless of true/false condition injected — no boolean channel in content.
  - BUT: HTTP status code (200 vs 500) *is* a reliable oracle.

## Oracle (boolean via forced SQLite error)

```
admin' AND like('a','a', CASE WHEN (<cond>) THEN 'a' ELSE 'ab' END) -- 
```
- `<cond>` TRUE  -> ESCAPE = 'a' (1 char, valid)   -> HTTP 200
- `<cond>` FALSE -> ESCAPE = 'ab' (2 chars, invalid) -> HTTP 500
  ("ESCAPE expression must be a single character")

Verified working via curl and via solve.py (sanity: 1=1->True, 1=2->False).

- Multiple tables confirmed to exist (`type='table'` count > 1).
- `users` table confirmed to exist.

## Extraction notes

- Sequential requests are reliable. Concurrency (tried 2+ workers in an
  earlier attempt) corrupted results — looked like shared per-request state
  or rate limiting on the instance. **Stick to sequential requests.**
- solve.py uses binary search per character (unicode(substr(...))) instead
  of linear charset walk — ~7 requests/char instead of up to 94.

## Files
- files/login.html, files/forgot.html — page dumps
- files/fp_quote.html — raw 500 error demonstrating the injection
- solve.py — extraction script (modes: sanity, tables, schema, count, dump, raw)
- tables.output — background run enumerating table names

## Results

- Tables: `users`, `sqlite_sequence`, `movies`.
- `users` schema: `id INTEGER PK AUTOINCREMENT, username TEXT, password TEXT`.
- 4 rows, passwords stored in **plaintext**:
  - theo   : c864elblhxlu4hvvzn
  - tony   : 9oflvmj1myiucgmgth
  - rachel : pxuemvn31kwntenl56
  - admin  : avfbmjlt4qyfmow597
- Logged in as `admin` via `/login` -> 302, session cookie set, `/profile`
  confirms Role: Admin.
- Flag found on `/movie/American Shadow` page body once authenticated as admin.

## TODO
- [x] Enumerate table names
- [x] Dump `users` schema (columns)
- [x] Dump users table (username/password)
- [x] Log in with recovered creds (admin)
- [x] Get flag, write up

## Flag

RM{1c7d5032632faf89b776dfbcc3cdd2ca}

See writeup.md for the full writeup.
