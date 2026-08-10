# BLE - 2FA bypass (Root-Me Pro, Web, Medium, 450pts)

## Challenge

Author: Don Vito Corleone. A crypto-trading web app added a referral ("word-of-mouth")
feature to counter bad publicity. Objective: access the **Crypto-Ninja** role.
Source code (`app.zip`) was provided; listed vulnerability category is *Business
Logic Errors*.

## Approach

1. Fingerprinted the instance: Flask (Werkzeug dev server) app, `/` redirects to
   `/marketplace`. Downloaded and extracted the provided `app.zip` source.
2. Read `app.py` end to end, focusing on the money/role/referral flow and every
   place `status` (the account "verification"/2FA flag) is checked.
3. Mapped out the referral money-farming primitive and confirmed which routes
   do — and don't — check `status`.
4. Wrote a script to farm money via unlimited self-referral, then bought the
   `crypto-ninja` role and pulled the flag from `/crypto-ninja`.

## Vulnerability

Two business-logic bugs compound:

**1. Unlimited referral farming.** `apply_referral_code()` in `app.py`:

```python
def apply_referral_code(user, ref_code):
    referral = get_user_from_ref_code(ref_code)
    if referral:
        referral = referral[0]
        update_user(referral['id'], {"money": referral['money'] + 4000, ...})
        update_user(user['id'], {"money": user['money'] + 4000})
        return True
    return False
```

Every `/register` submission that includes someone's `referral-code` gives
**+$4000 to the referrer and +$4000 to the new account**, with no cap, no
cooldown, and no check that the referrer/referred pair hasn't been used
before. The profile page even says so outright: *"no maximum limit on the
number of referrals!"*. Registering N throwaway accounts, all citing the same
referral code, gives the referrer `100 + 4000*N` dollars — arbitrarily large.

**2. The verification ("2FA") gate only guards one route.** After a referral
is applied, `/verify-account?code=<ref_code>` runs:

```python
update_user_status(referral.get("id"), 0)
update_user_status(user.get("id"), 0)
```

setting `status=0` ("unverified") on both the referrer and the new user —
and nothing ever sets it back to 1. Only `/profile` checks `status`:

```python
if not user.get("status"):
    return redirect(f"{url_for('verify_account')}?message=1")
```

`/roles` (spend money to buy a role) and `/crypto-<role>` (view role-gated
content) never check `status` at all. So the intended flow — verify before
you can do anything meaningful — is bypassable for everything that actually
matters: an account permanently stuck "unverified" can still buy the
`crypto-ninja` role and read the flag it gates.

(Minor extra note: the `<role>` URL segment on `/crypto-<role>` is unused —
access is gated purely on `user.role`. But `crypto-roles.html` only prints
the flag when `role == "crypto-ninja"` exactly; `crypto-brother` just gets a
"too poor" placeholder, so the cheaper role is a dead end for the flag.)

## Solution

1. Register an attacker account (starts `status=1`, so `/profile` loads
   normally) and read its `referral_code` off the profile page.
2. Loop: register throwaway "burner" accounts, each submitting the attacker's
   `referral_code`. Each registration is +$4000 to the attacker. Need
   `100 + 4000*n >= 1,000,000` → `n >= 250` (used 255 for margin). Note: after
   the *first* referral the attacker's own `status` flips to 0, so `/profile`
   stops rendering (redirects to `/verify-account`) — money has to be tracked
   arithmetically from then on rather than scraped from the page.
3. `POST /roles` with `role=crypto-ninja` from the attacker's session →
   `302 Location: /profile?message=2` (purchase succeeded, despite being
   "unverified").
4. `GET /crypto-ninja` from the attacker's session → `200`, flag in the body.

Full script: `solve.py` (in this challenge folder). Runs sequentially — an
earlier attempt at parallelizing the burner registrations broke the
connection (`IncompleteRead`/`ProtocolError`), consistent with the backing
Werkzeug dev server not being thread-safe/concurrent here.

Note: the first challenge instance died mid-solve (hit its ~1h lifetime) and
had to be restarted; the flag below was pulled from the second instance.

## Flag

```
RM{cc827c53f311b514f02adf9648313a38}
```

## Lesson

A gating flag (verification, 2FA, KYC, whatever) is only as strong as its
weakest checked route. When auditing this class of bug: grep every route for
the guard condition used on the "obvious" gated page, and diff that against
every *other* route that spends value or reveals privileged content — it's
common for a refactor or a new feature route to simply forget to copy the
check. Also worth flagging as a tell: when a feature's own UI copy brags
about having **no limit**, that's usually the intended abuse vector, not
marketing fluff.
