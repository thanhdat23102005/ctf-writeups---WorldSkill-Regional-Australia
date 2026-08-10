# BLE - 2FA bypass — notes

- Platform: Root-Me Pro, Web, Medium, 450pts
- First instance (`instance-019fe974-...`) expired mid-solve (~1h instance timer) — 404 on everything after ~25 referrals. Restarted, got second instance `instance-019fe980-884f-707f-8711-dfb7ff32fb8d.challenges.root-me.pro`.
- No VPN needed — `challenges.root-me.pro` instance subdomains are public HTTPS, unlike the older internal-range Root-Me Pro targets. `sudo wg-quick up rootme` wasn't required (and sudo wasn't actually passwordless on this box despite CLAUDE.md, couldn't bring up VPN anyway).
- Source (`app.zip`) provided via presigned S3 link on the challenge page — downloaded to `files/app.zip`, extracted to `files/app/`.

## Source review (app.py)

- Flask + custom tiny ORM wrapper (`database/statements.py`) over sqlite.
- `users` table: `money` (default 100), `role` (default `crypto-starter`), `status` (default 1 = verified), `referral_code`.
- `/register` accepts optional `referral-code` form field -> `apply_referral_code()`:
  - looks up referrer by code, gives **+$4000 to referrer AND +$4000 to the new user**, no cap, no cooldown, no per-pair limit.
  - on success, redirects to `/verify-account?code=<referral_code>`.
- `/verify-account`: if `code` param given, looks up that referrer and sets **both** the referrer's and the current session user's `status = 0` (unverified/"2FA" not passed). No route ever sets status back to 1 — visiting this endpoint is a one-way trap.
- `/profile` is the ONLY route that checks `status` (redirects to verify-account if `status` falsy).
- `/roles` (buy `crypto-brother` $100k or `crypto-ninja` $1,000,000) and `/crypto-<role>` (view perks/flag) **never check `status`**.
- `/crypto-<role>` route: the `<role>` URL segment is unused in the function body — access is gated purely on `got_enough_privileges(user.role)` (`crypto-ninja`, `crypto-brother`, `admin`). BUT `templates/crypto-roles.html` only prints `{{ flag }}` when `user.role == "crypto-ninja"` exactly — `crypto-brother` gets a "too poor" placeholder. So crypto-brother is a dead end for the flag; must actually reach $1,000,000 and hold the `crypto-ninja` role.

## Vulnerability

Business logic error: unlimited self-referral money farming, combined with the "2FA"/verification status check being enforced only on `/profile` and NOT on the money-spending (`/roles`) or privileged-content (`/crypto-<role>`) routes. So the account "verification" gate is entirely bypassable for anything that matters — you can farm unlimited money and buy/view privileged content while permanently "unverified".

## Exploit

1. Register attacker account (status=1 by default, so `/profile` loads, giving us the referral code from the readonly input).
2. Loop: register N throwaway "burner" accounts, each supplying the attacker's referral code. Each one is +$4000 to attacker (and +$4000 to the burner, irrelevant).
   - Note: after the FIRST referral, attacker's `status` flips to 0, so `/profile` 302s to `/verify-account` from then on — money can no longer be read from the profile page. Just compute it arithmetically: `100 + 4000*n`.
   - Needed n = 250 for crypto-ninja's $1,000,000 (`100 + 4000*250 = 1,000,100`). Used 255 for buffer.
   - Tried concurrent registration (8 threads) first — broke the connection (`IncompleteRead`/`ProtocolError`). The Werkzeug dev server backing the challenge appears single-threaded; had to go strictly sequential with retries. ~255 sequential requests took ~5 minutes.
3. `POST /roles` with `role=crypto-ninja` from attacker's session → redirect `Location: /profile?message=2` (success, even though attacker is "unverified" — confirms the bypass).
4. `GET /crypto-ninja` from attacker's session → 200, page renders the flag.

## Flag

`RM{cc827c53f311b514f02adf9648313a38}`

## Credentials used (throwaway, for reference)

- attacker_vih8ig / Passw0rd! (on instance `019fe980-884f-707f-8711-dfb7ff32fb8d`)

## Lesson

Any state check meant to gate access (verification/2FA/KYC-style flags) has to be enforced on **every** sensitive route, not just the "obvious" one (`/profile`). Auditing this kind of bug: grep every route for the guard condition used elsewhere (`status`, `is_verified`, etc.) and check which routes are missing it — especially routes that spend/grant value (`/roles`) or reveal privileged content (`/crypto-<role>`). Also: when a business feature explicitly says "no maximum limit" (as the profile page literally advertised for referrals), treat that as the intended abuse vector, not a throwaway line.
