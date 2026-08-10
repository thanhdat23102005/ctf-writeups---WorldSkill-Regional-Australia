# SOC AD - DCSync Attack (Root-Me Pro, SOC, Medium, 400pts)

"The domain controller talks too much"

## Access

OpenSearch Dashboards (header `osd-name: soc-dashboards`) at `https://soc.challenges.root-me.pro/?token=<JWT>`.
No browser needed — the token sets session cookies, then query via the console proxy:

```bash
TOKEN=$(cat files/token.txt)
curl -sS -c files/cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"

curl -sS -b files/cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://soc.challenges.root-me.pro/api/console/proxy?path=index-625bd823e0f6-windows/_search&method=POST" \
  -d '{"size":1000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}'
```

- Direct `_cat/indices` is **403** (no `cluster:monitor/state`). Get the index name from saved objects instead:
  `GET /api/saved_objects/_find?type=index-pattern&per_page=100`
- Index: `index-625bd823e0f6-windows` — 1095 docs, winlogbeat 8.12.0 schema.
- `event.code` is a text field — aggregate on **`event.code.keyword`**.

## Environment

- Domain `rootme.local`, DC01 = 192.168.10.10 (Windows Server 2022)
- Workstations WS01/WS02/WS03, servers SRV-FILE01 / SRV-APP01 / SRV-WEB01
- WS03.rootme.local = **192.168.10.56**

## Event code breakdown

| Code | Count | Meaning |
|------|-------|---------|
| 4769 | 280 | Kerberos service ticket |
| 4662 | 219 | Directory Service Access |
| 4768 | 180 | Kerberos TGT request |
| 4624 | 125 | Logon |
| 1    | 121 | Sysmon process create |
| 3    | 86  | Sysmon network connection |
| 4634 | 69  | Logoff |
| 4672 | 15  | Special privileges assigned |

## DCSync detection

Filtered the 219 x 4662 events for the three replication control-access GUIDs in `winlog.event_data.Properties`:

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set

Only two subjects match:

| Subject | Hits | Verdict |
|---------|------|---------|
| `DC02$` | 24 | **Benign** — DC machine account, legitimate inter-DC replication, spread across the day in Get-Changes/Get-Changes-All pairs |
| `agarcia` | 15 | **MALICIOUS** — standard user account, all 15 in a 2-second burst at 14:22:07–14:22:08 against `DC=rootme,DC=local`, includes the Filtered-Set GUID |

A user account has no business requesting directory replication. That's the whole signature.

## Attack chain (2026-05-01)

```
14:21:57  WS03  Sysmon 1  python.exe secretsdump.py rootme.local/agarcia@DC01.rootme.local -just-dc -output creds
14:22:02  WS03  Sysmon 3  python.exe -> outbound (192.168.10.56)
14:22:04  DC01  4624      logon agarcia from 192.168.10.56
14:22:07  DC01  4662 x7   replication GUIDs, object DC=rootme,DC=local
14:22:08  DC01  4662 x8   replication GUIDs
14:22:08-11 WS03 Sysmon 3 python.exe continued connections
```

- **Tool**: impacket `secretsdump.py`, `-just-dc` = pull domain hashes via DRSUAPI (DCSync), `-output creds` writes the loot
- **Attacker host**: WS03.rootme.local / 192.168.10.56
- **Compromised account**: agarcia
- **Target**: entire domain NC `DC=rootme,DC=local` (so krbtgt included)

Earlier agarcia 4662 activity (08:55 cleblanc, 11:01 OU=IT, 11:31 pdupont, 12:41 jmartin) is plain object reads — recon-ish, but no replication GUIDs.

## GUID / AccessList mapping (verified against the raw logs)

Only three GUIDs in the entire 219-event set carry `AccessList: Control Access` — the replication triple.
Everything else is ordinary List Contents / Read Property / Write Property on user objects.

| GUID | Right | Seen as | Notes |
|------|-------|---------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes | DC02$ 24, agarcia 14 | non-secret attributes only |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | **DS-Replication-Get-Changes-All** | DC02$ 24, agarcia 14 | **unlocks secret attrs (unicodePwd, ntPwdHistory) — the DCSync signature** |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set | agarcia 2 only | DC02$ never requests it — extra tell that agarcia's rights were attacker-granted |

## Answers

- **Step 1 — user account that performed the DCSync: `agarcia`**
- **Step 2 — DS-Replication-Get-Changes-All GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`**
  (the form's placeholder `89e95b76-...` is a decoy = Filtered-Set)
- **Step 3 — source IP: `192.168.10.56`** (WS03.rootme.local; 4662 has no IP field, pivot via the
  14:22:04 4624 LogonType 3 for agarcia + Sysmon 3 to 192.168.10.10:445)
- **Step 4 — time (UTC): `14:22:07`** (first replication-GUID 4662; burst = 7 @ 14:22:07 + 8 @ 14:22:08.
  `@timestamp` is already UTC/Z, no conversion.)

## Caveat on counts

`all_events.json` is a `size:1000` pull against 1095 total docs, so it is missing ~95 events.
Running `solve.py` off it reports `DC02$` = 22 replication events; the complete `4662_events.json`
(all 219 Directory Service Access events) gives 24. `agarcia` = 15 in both, so no answer changes.
Use `4662_events.json` for any exact 4662 counting.

## Files

- `files/token.txt` — JWT (exp 2026-08-10 06:59 EDT)
- `files/cookies.txt` — session cookie jar
- `files/all_events.json` — all 1000 events
- `files/4662_events.json` — the 219 Directory Service Access events
