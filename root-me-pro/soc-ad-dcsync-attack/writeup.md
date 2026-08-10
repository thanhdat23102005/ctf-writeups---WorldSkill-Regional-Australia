# SOC AD — DCSync Attack

| | |
|---|---|
| **Platform** | Root-Me Pro |
| **Category** | SOC / Blue Team (AD threat hunting) |
| **Difficulty** | Medium |
| **Points** | 400 |
| **Description** | *"The domain controller talks too much"* — A standard user account triggered Directory Service Access events containing unusual control access GUIDs. Identify the DCSync. |
| **Solved** | 2026-08-09 |

## Answers

| Step | Question | Answer |
|------|----------|--------|
| 1 | Which user account performed the DCSync? | `agarcia` |
| 2 | GUID for `DS-Replication-Get-Changes-All`? | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| 3 | From which IP was the DCSync launched? | `192.168.10.56` |
| 4 | At what time (UTC) did the DCSync occur? | `14:22:07` |

---

## Environment

Domain `rootme.local`, logs shipped by winlogbeat 8.12.0 into OpenSearch, 1095 events from 2026-05-01.

| Host | IP |
|------|-----|
| DC01 | 192.168.10.10 |
| DC02 | 192.168.10.11 |
| WS01 / WS02 / **WS03** | 192.168.10.42 / .55 / **.56** |
| SRV-APP01 / SRV-FILE01 / SRV-WEB01 | 192.168.10.60 / .70 / .80 |

## Approach

### 1. Get at the data without a browser

The challenge hands you an OpenSearch Dashboards URL with a JWT. No browser was available, so I drove the REST API directly. The token sets session cookies on first request; after that the Dashboards **console proxy** relays arbitrary queries to the backing cluster:

```bash
TOKEN='<jwt>'
curl -sS -c cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"

curl -sS -b cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://soc.challenges.root-me.pro/api/console/proxy?path=<INDEX>/_search&method=POST" \
  -d '{"size":1000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}'
```

Two snags worth remembering:

- `_cat/indices` returns **403** — the challenge role has no `cluster:monitor/state`. Recover the index name from saved objects instead:
  `GET /api/saved_objects/_find?type=index-pattern&per_page=100` → `index-625bd823e0f6-windows`
- `event.code` is mapped as text; terms aggregations must target **`event.code.keyword`**.

### 2. Triage the event mix

```json
{"size":0,"aggs":{"codes":{"terms":{"field":"event.code.keyword","size":50}}}}
```

| Code | Count | Meaning |
|------|-------|---------|
| 4769 | 280 | Kerberos service ticket |
| 4662 | 219 | Directory Service Access |
| 4768 | 180 | Kerberos TGT request |
| 4624 | 125 | Logon |
| 1 | 121 | Sysmon process create |
| 3 | 86 | Sysmon network connection |
| 4634 | 69 | Logoff |
| 4672 | 15 | Special privileges (all `administrator`, background noise) |

### 3. Filter 4662 for the replication rights

DCSync abuses three extended rights. Their control-access GUIDs appear in `winlog.event_data.Properties`:

| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

Rather than trusting memory, I pulled all 219 events and grouped every GUID against its `AccessList` string. Only three GUIDs in the entire dataset carry `AccessList: Control Access` — exactly the replication triple. Everything else is ordinary `List Contents` / `Read Property` / `Write Property` on user objects.

Two principals matched:

| Subject | Hits | Verdict |
|---------|------|---------|
| `DC02$` | 24 | **Benign** — DC machine account, legitimate inter-DC replication, spread across the day in Get-Changes / Get-Changes-All pairs |
| `agarcia` | 15 | **MALICIOUS** — standard user, all 15 in a 2-second burst against `DC=rootme,DC=local` |

`agarcia` is also the *only* principal that ever requests the Filtered-Set GUID — a real DC never does, which independently confirms the rights were attacker-granted rather than part of AD's replication topology.

### 4. Attribute the source IP

4662 records carry no IP field. The pivot is to correlate the burst with the network logon sharing the same account and second:

```
14:21:57  WS03  Sysmon 1  python.exe secretsdump.py rootme.local/agarcia@DC01.rootme.local -just-dc -output creds
14:22:02  WS03  Sysmon 3  192.168.10.56 -> 192.168.10.10:445
14:22:04  DC01  4624      agarcia, LogonType 3, Kerberos, IpAddress 192.168.10.56
14:22:07  DC01  4662 x7   replication GUIDs, object DC=rootme,DC=local
14:22:08  DC01  4662 x8   replication GUIDs
14:22:08-11 WS03 Sysmon 3 continued SMB to DC01
```

Three independent sources agree on `192.168.10.56` = WS03.rootme.local.

## Vulnerability

Not a software bug — an **Active Directory ACL misconfiguration**. The standard user account `agarcia` had been granted the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights on the domain naming context.

Those rights let *any* principal impersonate a domain controller and invoke `DRSUAPI_DSReplicaGetChanges` (`IDL_DRSGetNCChanges`) to request replication of secret attributes — `unicodePwd`, `ntPwdHistory`, `supplementalCredentials`. No code execution on the DC and no admin session is required; the DC hands over the hashes because the requester is authorised to ask.

The distinction that matters: plain **Get-Changes** returns non-secret attributes only. **Get-Changes-All** is what unlocks the secret attributes. That is why `1131f6ad` is *the* DCSync signature.

## Solution

```bash
# 1. Authenticate and cache cookies
TOKEN=$(cat files/token.txt)
curl -sS -c files/cookies.txt -o /dev/null "https://soc.challenges.root-me.pro/?token=$TOKEN"

# 2. Find the index (direct _cat/indices is 403)
curl -sS -b files/cookies.txt \
  "https://soc.challenges.root-me.pro/api/saved_objects/_find?type=index-pattern&per_page=100"

# 3. Pull every event locally
curl -sS -b files/cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://soc.challenges.root-me.pro/api/console/proxy?path=index-625bd823e0f6-windows/_search&method=POST" \
  -d '{"size":1000,"query":{"match_all":{}},"sort":[{"@timestamp":"asc"}]}' -o files/all_events.json
```

Then group the 4662 events by GUID (see `solve.py`). The equivalent hunt as a Lucene/DQL query in Discover:

```
event.code:4662 and winlog.event_data.Properties:*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*
  and not winlog.event_data.SubjectUserName:*$
```

The trailing `not ...:*$` drops machine accounts — without it `DC02$` buries the signal in legitimate replication.

**Attack chain**: `agarcia` (compromised, over-privileged) → impacket `secretsdump.py -just-dc` on WS03 (192.168.10.56) → DRSUAPI replication of `DC=rootme,DC=local` from DC01 → full domain hash dump written to `creds`.

## Impact & remediation

`-just-dc` against the domain NC dumps **krbtgt**, so the domain is fully compromised — the attacker can forge Golden Tickets valid until krbtgt is rotated.

- Reset `krbtgt` **twice**, allowing full replication between resets (the account keeps two password generations)
- Strip the replication ACEs from `agarcia`; audit the domain object's ACL for any other non-DC principal holding them
- Reset `agarcia` and treat WS03 as compromised
- Detection: alert on 4662 where `Properties` contains `1131f6aa` / `1131f6ad` / `89e95b76` and `SubjectUserName` is not a DC machine account. Near-zero false positives once DCs are allow-listed.

## Lessons

1. **`1131f6ad` = Get-Changes-All = DCSync.** Memorise the triple. `1131f6aa` alone is not enough to dump hashes; `1131f6ad` is the one that exposes secret attributes.
2. **Machine accounts are the baseline, not the alert.** `DC02$` doing replication is the system working as designed. The detection is "who requested this that *isn't* a DC" — always exclude `*$` before concluding.
3. **4662 has no source IP.** Pivot to 4624 on the same account within the same second to attribute a host. Correlating across event IDs is the core SOC skill this challenge tests.
4. **Read the placeholder text sceptically.** Step 2's input box was pre-filled with `89e95b76-...` (Filtered-Set) — a deliberate decoy for anyone pattern-matching the form instead of the logs.
5. **Verify GUID→right mappings against the data.** Grouping GUIDs by their `AccessList` value proved only three carried `Control Access`, confirming the mapping from the evidence rather than from recall.
6. **Kibana/OpenSearch Dashboards is scriptable.** `api/console/proxy` + a cookie jar beats clicking through Discover, and pulling the corpus locally makes correlation a five-line Python loop. Watch for text-vs-`.keyword` when aggregating.
