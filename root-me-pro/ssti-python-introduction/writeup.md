# SSTI - Python - Introduction — writeup

| | |
|---|---|
| **Platform** | Root-Me Pro |
| **Category** | Web — Server-Side Template Injection |
| **Difficulty** | Medium, 300 points, ~30 min |
| **Target** | `https://instance-019fe9e3-…challenges.root-me.pro/` ("RMeet", Flask/gunicorn + Jinja2) |
| **Brief** | *"7\*7 == 49"* — flag at `/flag.txt` |
| **Flag** | `RM{0c4bb76e02f9a8a44ca9db638cf3b6ac}` |

RMeet is a dating-app clone. It's the same codebase as the sibling challenge
*SSTI - Python - Filter Bypass*, but the injectable field is a different one and there is
no filter here at all. The whole challenge is **finding the sink**, not defeating it.

## Approach

**1. Map the app.** Register → auto-login → `/start` (complete profile) → `/swipe`.
Routes: `/swipe`, `/matches`, `/photos`, `/profile/<username>`, `/messages/<username>`,
`/config.js` (a rendered JS file: `window.myUserId = 10;`), plus `POST /api/swipe`
`{user_id, direction}` and `GET /api/user/<id>`. Profile fields are `full_name`, `age`,
`gender`, `location`, `bio`, `interests`.

**2. Probe every field at once.** Rather than one field at a time, each got its own
marker — `N{{7*7}}N` in `full_name`, `L{{7*7}}L` in `location`, `B{{7*7}}B` in `bio`,
`I{{7*7}}I` in `interests` — then grep every page for both the raw marker and the
evaluated one. One request per view instead of one per field-view pair.

**3. Chase the wrong sink first.** In the sibling challenge the vuln lives in
`/messages/<user>`, which is gated behind a real match. Bot profiles never like back, so
I forced one with a second account: B likes A via `POST /api/swipe`, A likes B →
`match_created: true`, and `/matches` exposes the chat route. Here it was a dead end —
messages are stored and echoed back **raw** (`{{7*7}}` stays literal, not even
HTML-escaped: stored XSS, no template evaluation). Worth knowing the same app can move
its bug between releases.

**4. Find the real sink.** Sweeping the marker-laden profile from a *different* account
turned up exactly one evaluation:

```
<div class="profile-bio">B49B this is the bio</div>
```

`bio` is evaluated — but only when drawn on the **swipe card**, and the card is served at
`/` or `/swipe` depending on where that viewer sits in the queue. The identical bio string
is escaped on `/profile/<user>` and `/matches`, and returned raw as JSON by
`/api/user/<id>`.

## Vulnerability

The swipe-card view builds its template by interpolating the profile `bio` into template
*source* and calling `render_template_string()` on the result, instead of passing the bio
as a **variable** to a static template. Everything inside a user's bio is therefore Jinja
source with full expression evaluation, unsandboxed and unfiltered.

Two things hide it:

* **Only one of six fields, in only one of four views.** The same `bio` renders safely on
  the profile page and in the match list — so testing the obvious profile view and moving
  on gives a clean bill of health.
* **You cannot see your own card.** The payload must be planted on account A and observed
  from account B, and only once B's swipe queue reaches A. A single-account test never
  triggers it.

## Solution

```jinja
{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}
```

`lipsum` is a Jinja global defined in `jinja2.utils`, and that module does `import os` —
so `lipsum.__globals__['os']` is the `os` module in one hop, no `__subclasses__()` walk
needed. Nothing is filtered, so the textbook form works as-is.

Steps:

1. **Attacker account** — set `bio` to the payload (via `POST /profile/<user>`; `gender`
   must be exactly `Male`/`Female`/`Other` or the form fails validation silently).
2. **Viewer account** — register a second user, then swipe left through the seeded bot
   profiles (`POST /api/swipe {user_id, direction}`) until the attacker's card comes up.
3. Read the bio bubble on `/` or `/swipe`:

```html
<div class="profile-bio">RM{0c4bb76e02f9a8a44ca9db638cf3b6ac}</div>
```

`exploit.py` automates the whole chain (both accounts → payload → queue walk → flag).

> **Verification status:** the flag was captured and confirmed against the live instance.
> The instance was torn down minutes later (all routes 404), so `exploit.py` as a single
> consolidated script could not be re-run end to end — each step in it was executed live
> during the solve, but the script as a unit is unverified. Replay against a fresh
> instance with `python3 exploit.py <base_url>`.

## Lessons

- **Enumerate sinks as a matrix, not a list.** The bug was field × view: `bio` was safe in
  three views and injectable in the fourth. Tag each input with its own marker and sweep
  every rendering surface — testing "does this field reflect?" on one page is what makes a
  vuln like this invisible.
- **Some sinks are only observable from another account.** You never see your own swipe
  card, so no amount of single-session probing reaches it. When an app has a "how others
  see you" surface, get a second account in place early — the same trick (forcing a match
  via the swipe API) unlocked the sibling challenge too.
- **Same app, different release, different sink.** Prior notes on RMeet pointed hard at
  `/messages/<user>`; here that endpoint is raw-but-inert and the bug moved to `bio`. Reuse
  old recon as a map, not as an answer.
- **`lipsum.__globals__['os']` is the shortest path to RCE in Jinja** when nothing is
  filtered, because `jinja2.utils` imports `os` itself. Keep the long
  `''.__class__.__mro__[1].__subclasses__()` chain for when the short one is blocked.
- **Silent validation failures read as "not stored".** An invalid `gender` blanked the
  whole profile with no visible error; I briefly concluded the fields weren't persisted at
  all. Always confirm the success flash before trusting a negative result.
- **Fix:** render untrusted data as data — `render_template("card.html", bio=bio)` — never
  concatenate it into template source. A denylist on the bio would not have helped (see the
  sibling challenge, where exactly that filter falls to `~` and `'_'*2`).
