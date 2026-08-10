# SOC AD — Kerberoasting — Writeup

## Challenge
- **Platform**: Root-Me PRO — **SOLVED**
- **Category**: SOC / Blue Team (Active Directory)
- **Difficulty**: Medium — **350 points**, ~1 h
- **Description**: "Typical Kerberos attack." An external entity gained access to the internal
  network. One AD user account is believed compromised and used to run a **kerberoasting** attack.
- **Environment**: OpenSearch Dashboards (`soc-dashboards`) holding winlogbeat 8.14.1 telemetry
  from the `ROOTME.local` domain — 3341 events, 2025-05-09 11:30:00 → 11:44:59 UTC.

## Flags
| Step | Question | Flag |
|---|---|---|
| 1 | Identify the newly compromised user | `mfletcher` |
| 2 | Identify the encryption type | `0x17` |
| 3 | Exact login date/time (`@timestamp`) of the compromised user account | `11:37:32.224_2025-05-09` |

---

## Approach

### 1. Query the backend instead of clicking Discover
The challenge hands you a JWT-in-URL that sets `security_authentication*` cookies. The stack is
**OpenSearch Dashboards** — given away by the `osd-name: soc-dashboards` response header.

```bash
curl -b cookies.txt -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://soc.challenges.root-me.pro/api/console/proxy?path=$IDX/_search&method=POST" \
  -d @-
```

Three obstacles worth remembering:

- **Cluster APIs are 403** for the challenge role — `_cat/indices` and `_mapping` both refuse
  (`no permissions for [indices:admin/mappings/get]`). `_search` is permitted. Enumerate via
  `/api/saved_objects/_find?type=index-pattern` → `index-be447e0099b7-winlogbeat`, and recover
  the 416-field schema from `/api/index_patterns/_fields_for_wildcard?pattern=<index>`.
- **Every string field is mapped `text`**, so aggregating on `winlog.event_id` throws
  `illegal_argument_exception: Text fields are not optimised for ... aggregations`.
  Use the **`.keyword`** subfield for every terms agg and exact-match filter.
- **`GET /api/opensearch-dashboards/settings`** revealed the author's display config:
  `dateFormat = HH:mm:ss.SSS YYYY-MM-DD` and `dateFormat:tz = UTC`. The Step 3 flag format is
  literally that display string with the space swapped for `_` — and it is UTC, so raw
  `@timestamp` values need no shifting. Checking this early removes any timezone doubt.

### 2. Profile, then pivot on ticket encryption
One aggregation gives the shape of the incident: 15-minute window, 12 hosts, and only
**29 × event 4769** (Kerberos Service Ticket Operations) — small enough to read every one.

Kerberoasting is not about the *volume* of 4769; it is about the **cipher**.

---

## Vulnerability

**Kerberoasting** (MITRE **T1558.003**). Any authenticated domain user may request a TGS for any
account with a registered SPN. The KDC encrypts that ticket with the *service account's own
password hash*, so the requester can crack it **offline** — no further DC traffic, no failed-logon
noise.

The attacker deliberately requested **RC4-HMAC (`0x17`)** instead of the domain's normal
**AES256 (`0x12`)**:

| etype | Cipher | Hash format | Hashcat | Crack cost |
|---|---|---|---|---|
| `0x11` | AES128-CTS-HMAC-SHA1-96 | `$krb5tgs$17$` | 19600 | high |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | `$krb5tgs$18$` | 19700 | high (AES + 4096-round PBKDF2) |
| **`0x17`** | **RC4-HMAC** | **`$krb5tgs$23$`** | **13100** | **cheap — keyed on the raw NTLM hash** |

An RC4 request in a domain that otherwise negotiates AES256 is one of the highest-fidelity
detections in all of AD security.

---

## Solution

### Step 1 — the compromised user: `mfletcher`
All 29 TGS requests by encryption type: 19 are `0x12`, and **10 are `0x17`, all from one account
inside 316 milliseconds**:

```
11:36:00.637  mfletcher@ROOTME.LOCAL -> snielsen      0x17
11:36:00.669  mfletcher@ROOTME.LOCAL -> jdrake        0x17
11:36:00.703  mfletcher@ROOTME.LOCAL -> hrobertson    0x17
11:36:00.738  mfletcher@ROOTME.LOCAL -> joconnor      0x17
11:36:00.777  mfletcher@ROOTME.LOCAL -> svc_mssql     0x17
11:36:00.811  mfletcher@ROOTME.LOCAL -> zwheeler      0x17
11:36:00.845  mfletcher@ROOTME.LOCAL -> tmcconnell    0x17
11:36:00.882  mfletcher@ROOTME.LOCAL -> lrivas        0x17
11:36:00.916  mfletcher@ROOTME.LOCAL -> vkaufman      0x17
11:36:00.953  mfletcher@ROOTME.LOCAL -> twall         0x17
```

Three independent confirmations: the RC4 downgrade; 10 SPNs in 316 ms (scripted, not human); and
the "services" are all *user* accounts carrying an SPN — precisely the kerberoast target set.

### Step 2 — the encryption type: `0x17`
Read straight off the event (format per the `0x22` placeholder):

```json
"TicketEncryptionType": "0x17",
"TicketEncryptionTypeDescription": "RC4-HMAC",
"TicketOptions": "0x40810010",
"StatusDescription": "KDC_ERR_NONE"
```

### Step 3 — the login timestamp: `11:37:32.224_2025-05-09`
"The compromised user account" is **`svc_mssql`** — the account compromised *by* the roast, not
the account that ran it. It is the only one of the ten roasted SPNs that subsequently
authenticates, 55 s after its RC4 ticket was issued: cracked offline, then reused.

`svc_mssql` has **four** 4624 logons, so "first occurrence" is not the discriminator. Pairing each
4624 to its 4634 on `LogonId` and measuring session duration is:

| Logon | Host | LogonId | Duration | |
|---|---|---|---|---|
| 11:36:55.797 | SRVDC01 | 0x1d4dfac | 0.155 s | probe |
| 11:36:56.001 | SRVDC02 | 0x1a21ffe | 0.137 s | probe |
| 11:36:57.974 | WS01 | 0x1bf6f06 | 0.120 s | probe |
| **11:37:32.224** | **SRVDC01** | **0x1d4f3cb** | **13.525 s** | **real session** |

The first three are ~130 ms logon→logoff blips — the tool validating the cracked password against
each host. Only the fourth is a genuine session, ~100× longer, where the attacker actually
operated. That is the login.

---

## Full attack timeline

```
11:33:29.321  4776  SRVDC01  NTLM credential validation — mfletcher
11:33:29.322  4624  SRVDC01  Logon type 3 from 10.199.0.4      ] 38 ms probe:
11:33:29.359  4634  SRVDC01  Logoff                            ] credential confirmed
11:36:00.510  4776  SRVDC01  NTLM credential validation — mfletcher
11:36:00.513  4624  SRVDC01  Logon type 3 from 10.199.0.4
11:36:00.601  4768  SRVDC01  TGT issued for mfletcher — enc 0x17 (only non-AES TGT in the index)
11:36:00.637  4769  SRVDC01  ] 10 x TGS, RC4 0x17, 316 ms
   ...        4769  SRVDC01  ]    KERBEROASTING (T1558.003)
11:36:00.953  4769  SRVDC01  ]
11:36:00.969  4634  SRVDC01  Logoff
--- ~55 s offline cracking of the $krb5tgs$23$ hash ---
11:36:55.614  4624  SRVDC01  ANONYMOUS LOGON from 10.199.0.4   ] null-session enumeration
11:36:55.623  4624  SRVDC02  ANONYMOUS LOGON from 10.199.0.4   ]
11:36:55.797  4624  SRVDC01  svc_mssql  0.155 s   ] password validated
11:36:56.001  4624  SRVDC02  svc_mssql  0.137 s   ] against each
11:36:57.974  4624  WS01     svc_mssql  0.120 s   ] host in turn
11:37:32.224  4624  SRVDC01  svc_mssql 13.525 s   <== REAL SESSION (Step 3 flag)
11:37:45.749  4634  SRVDC01  Logoff
```

**Attacker infrastructure: 10.199.0.4.**

---

## Lesson

**Hunting kerberoasting.** Do not alert on 4769 volume; normal domains generate thousands. Alert
on **`TicketEncryptionType: 0x17` where the domain baseline is `0x12`**. Two cheap amplifiers:
many distinct `ServiceName` values from one `TargetUserName` in a few seconds, and `ServiceName`
resolving to a *user* object rather than a computer account (computer accounts end in `$` and
carry 120-char random passwords — nobody roasts those).

```
EventCode=4769 TicketEncryptionType=0x17 TicketOptions=0x40810010 ServiceName!=*$
| stats dc(ServiceName) as spns, values(ServiceName) by TargetUserName, _time span=1m
| where spns > 3
```

**The mistake worth keeping: "the login" is not the first logon.** I burned three attempts on
first-occurrence timestamps (mfletcher ×2, svc_mssql ×1). The correct move is to **pair 4624 to
4634 on `LogonId` and rank by session duration** — sub-second pairs are credential-validation
probes, multi-second ones are real sessions. An attacker script validates a fresh credential
against several hosts before using it, which manufactures several near-identical logons; only one
of them is the session that matters. I had already identified this exact pattern on mfletcher's
38 ms probe at 11:33:29 and failed to reapply it to svc_mssql.

**Other reflexes reinforced:**
1. **Follow the roast forward.** The roasted SPN list is a target list — diff it against later
   4624s. The one account that starts authenticating afterwards is the one that cracked. That is
   how `svc_mssql` fell out of ten candidates in seconds.
2. **Auth package + source subnet separate attacker from admin.** Every legitimate account here
   (`Administrator`, `rvillanueva`) uses **Kerberos from 10.98.98.x**; every attacker action —
   mfletcher, the ANONYMOUS LOGONs, svc_mssql — is **NTLM from 10.199.0.4**. A cheaper detection
   than the RC4 hunt, and a good second layer.
3. **Check event-ID cardinality per account** when a question implies a single answer, and read
   the platform's own config (`/api/opensearch-dashboards/settings`) — it pinned both the flag
   format and UTC, eliminating a whole class of timezone error.

**Defensive fixes:** strong (25+ char) or **gMSA**-managed passwords on every SPN account; disable
RC4 domain-wide via `msDS-SupportedEncryptionTypes`; strip unnecessary SPNs; never grant SPN
accounts Domain Admin.
