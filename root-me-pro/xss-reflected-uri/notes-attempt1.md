# XSS - Reflected - URI (Root-Me, Web, Medium, 450 pts)

## Challenge description
> Mirror mirror...
> This site presents the new video game craze called "The Pirate Creek". They've recently updated the site, but a vulnerability still seems to exist.
> Get the administrator's account to steal his treasure!

Category: Web | Difficulty: Medium | Points: 450 | Est. time: ~1h
Instance was showing "initializing" at challenge start.

## Plan
1. Get target URL from instance once ready.
2. Bring up Root-Me VPN if this is a Pro-hosted instance.
3. Recon site — find where a URI-based param reflects unescaped into the page (likely a "path"/"page"/redirect param, given "XSS - Reflected - URI" title + "Mirror mirror" hint suggests reflecting `location`/`document.URL`/`window.location.href` or similar via DOM-based sink, not a query param necessarily).
4. Identify sink (server-side reflection into HTML attribute/tag, or DOM sink via JS reading `location.pathname`/`location.href`).
5. Craft payload to steal admin cookie/session — need an exfil endpoint (Root-Me usually provides a "report to admin" / bot feature, or challenge provides a webhook-like target, or we host a listener since Root-Me Pro instances often lack outbound internet — check first).
6. Trigger admin bot with malicious link, capture cookie/token, use to steal "treasure".

## Findings
(pending target info)

## Dead ends
(none yet)

## Recon results (instance: instance-019fe9b6-aa86-7256-a750-fb4a492c3f7a.challenges.root-me.pro)

Stack: Flask / Werkzeug 3.1.3, Python 3.11.2. Public HTTPS — no VPN needed.

### Routes
- `/` game landing page
- `/forum` thread list (10 threads, UUID links)
- `/forum/<uuid>` thread — all say "You can't see this / administrator does not allow"
- `/forum/report` POST only (302 -> /forum?reported=1) — **admin bot visits submitted URL**
- `/login` POST form, error "Error: Wrong username or password."
- `/register` disabled ("Servers are currently overloaded")
- `/profile`, `/logout` -> 302 /login
- No robots.txt / sitemap.xml. gobuster common.txt found nothing else.

### Dead ends
- Query params on /, /forum, /login, /register: no reflection (tested next/redirect/url/return/ref/continue/callback/page/path/q/search + arbitrary)
- Headers Referer / User-Agent / X-Forwarded-For / X-Forwarded-Host / Cookie: no reflection
- Werkzeug 307 redirect body is empty — no reflection there
- /static/js/custom/script.js reads `document.location` but has NO sink
  (only classList/style writes) — this is the *patched* v1 vector, red herring
- No thread-create / comment endpoint (all 404)

### VULNERABILITY — reflected XSS in forum thread UUID path segment
`GET /forum/<INPUT>` reflects INPUT **completely unescaped** into HTML body:

    Oops ! No thread where found with the uuid '<INPUT>'.

Confirmed raw: `<img src=x onerror=alert(1)>` comes back verbatim. `<` `>` `"` `'` `(` `)` `=` all unfiltered.

**Constraint**: a literal `/` in the payload is URL-decoded by Werkzeug into a path
separator, splitting the route -> generic 404. So the injected tag must be slash-free
(no closing tags, no `</script>`, no URLs inline).

**Workaround**: put the slash-free loader in the path, real JS in the fragment:

    /forum/<img src=x onerror=eval(unescape(location.hash).slice(1))>#<JS with slashes>

### Delivery to admin
POST /forum/report  body: url=<our XSS link>&comment=<text>
-> 302 /forum?reported=1 (accepted). Bot then browses the URL as admin.

### BLOCKED ON: exfil channel
Need a collector the admin bot can reach to receive document.cookie / page content.
All options leave the challenge host -> per scope rule, asking Pauk first.
