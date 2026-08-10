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

- Instance URL: _pending — waiting on Pauk_

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
