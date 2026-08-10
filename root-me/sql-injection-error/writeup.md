# SQL Injection - Error (Root-Me Pro)

## Challenge
- **Platform / Category**: Root-Me Pro, Web, Medium, 400 points
- **App**: "Rootflix" — a movie catalogue with guest/registered access, built on
  Flask/Werkzeug (Python 3.12) + SQLite.
- **Goal**: "I can log in as a guest, but I can't watch films until I have a
  valid account. Get access to the platform with enough privileges to watch
  my favorite films freely."
- Links:
  - https://root-me.pro/ctf/resources/0197c566-d079-72f5-95c9-1dff6db52289
  - https://root-me.pro/ctf/resources/0197c566-d291-71ed-b8b8-c38d736351cb

## Approach

1. Fetched `/login` — POST `username`/`password`. Injecting a quote produced
   no error; login always returns a generic failure. Parameterized / not the
   injection point.
2. Fetched `/forgot-password` — POST `username` only. Normal request returns
   a generic success message ("If this account exists... a link has been
   sent") **regardless of whether the username is real** — no boolean signal
   in the response body.
3. Injected a single quote: `username=admin'` → **HTTP 500** with a raw
   SQLite error reflected in the body:
   ```
   Error: Something wrong appened : unrecognized token: "'admin'';"
   ```
   Confirms: SQLite backend, the query is built via raw string
   concatenation, exceptions are not caught, and the app does a naive
   `'` → `''` "escape" that doesn't actually neutralize the injection.

## Vulnerability

`/forgot-password` interpolates the `username` parameter directly into a
SQL query (something like
`SELECT username, password FROM users WHERE username = '<input>'`),
with unhandled DB exceptions surfaced as raw 500 errors.

The catch: the *success/failure message never differs based on data* — so
there's no classic boolean-based oracle from the response content. But the
HTTP status code (200 vs 500) differs based on whether the injected SQL is
syntactically/semantically valid — a error-based blind channel.

SQLite doesn't support the classic MySQL/MSSQL error-based extraction
tricks (no informative CAST errors, no XML functions, division by zero
returns NULL). Instead, `like(pattern, string, escape)` requires its
`ESCAPE` argument to be **exactly one character**, or SQLite throws
`ESCAPE expression must be a single character` at **runtime**, which can be
made conditional:

```sql
admin' AND like('a','a', CASE WHEN (<condition>) THEN 'a' ELSE 'ab' END) -- 
```

- `<condition>` **TRUE**  → escape = `'a'`  (1 char, valid)   → **HTTP 200**
- `<condition>` **FALSE** → escape = `'ab'` (2 chars, invalid) → **HTTP 500**

This gives a clean, reliable boolean oracle for arbitrary SQL sub-expressions
against `sqlite_master`, `users`, etc.

## Solution

Using the oracle above, ran a blind binary-search extraction (`solve.py`) —
binary search on `length(expr)`, then binary search on
`unicode(substr(expr, pos, 1))` per character (ASCII 32–126), all against
`sqlite_master` and the recovered table names. Sequential requests were
reliable; the instance rate-limits/misbehaves under concurrency.

1. Enumerated tables: `sqlite_master` → **`users`**, `sqlite_sequence`,
   **`movies`**.
2. Dumped `users` schema:
   ```sql
   CREATE TABLE users (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     username TEXT,
     password TEXT
   )
   ```
3. `SELECT count(*) FROM users` → 4 rows.
4. Dumped `username` column: `theo`, `tony`, `rachel`, `admin`.
5. Dumped `password` column (plaintext, no hashing):
   ```
   theo   : c864elblhxlu4hvvzn
   tony   : 9oflvmj1myiucgmgth
   rachel : pxuemvn31kwntenl56
   admin  : avfbmjlt4qyfmow597
   ```
6. Logged in via `/login` as `admin:avfbmjlt4qyfmow597` → HTTP 302, session
   cookie `sqli-error-session` set. `/profile` confirmed
   `Username: admin` / `Role: Admin`.
7. Visited a movie detail page (`/movie/American Shadow`) as admin — the
   "Watch Now" flow revealed the flag directly in the page body.

## Flag

```
RM{1c7d5032632faf89b776dfbcc3cdd2ca}
```

## Lesson

- A response body that looks identical for true/false conditions isn't
  proof there's no oracle — check the **status code**, headers, and timing
  too. Error-based blind SQLi doesn't require the error text to leak data;
  it just needs *some* observable difference (200 vs 500 here) tied to a
  conditional expression.
- For SQLite specifically (which lacks MySQL/MSSQL-style informative error
  functions), `like(x, y, escape)`'s single-character `ESCAPE` constraint is
  a reliable, portable way to force a conditional runtime error — worth
  remembering as a general SQLite error-oracle trick.
- Always check whether "escaping" (e.g. naive `'` → `''` doubling) actually
  neutralizes the injection — here it didn't, since the app's own escaping
  routine could be sent unbalanced input that still broke query syntax.
- Storing plaintext passwords made the final step trivial once extraction
  worked — no cracking needed, just read the column.
