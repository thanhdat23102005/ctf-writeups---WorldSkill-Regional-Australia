# SOC AD - Kerberoasting (Root-Me PRO, SOC, medium, 350pts)

## Platform access
- SOC platform = **OpenSearch Dashboards** (`osd-name: soc-dashboards`) at https://soc.challenges.root-me.pro
- Auth via `?token=<JWT>` -> sets `security_authentication*` cookies. Saved to `cookies.txt`.
- Direct cluster APIs (`_cat`, `_mapping`) are 403 for our role, but **`_search` through the
  Dashboards console proxy works**:
  `POST /api/console/proxy?path=<index>/_search&method=POST` with header `osd-xsrf: true`
- Index: `index-be447e0099b7-winlogbeat` (index-pattern id `indexp-be447e0099b7-winlogbeat`)
- Field list obtained via `/api/index_patterns/_fields_for_wildcard?pattern=...` (416 fields)
- Gotcha: all string fields are `text`; **must aggregate on `.keyword`** subfields.
- Helper script: `q.sh` (pipes a JSON body to _search)

## Dataset profile
- 3341 docs, window **2025-05-09 11:30:00 -> 11:44:59 UTC** (15 min)
- Domain `ROOTME.local`. Hosts: SRVDC01/02, SRVAPP01/02/03, WS01-WS06
- Channels: Sysmon/Operational 2396, Security 864, System 37, PowerShell 34
- Key event IDs: 3(2216) 4688(186) 4689(175) 4624(169) 4634(142) 4672(128) 1(109)
  **4769(29)** 4768(6) 4776(6) 4770(8)

## Step 1 - identify the newly compromised user

Only 29 x 4769 (Kerberos TGS request) in the whole set. Pivot on `TicketEncryptionType`:

- **28 of 29 are `0x12` (AES256-HMAC-SHA1)** = normal modern Kerberos.
- **10 are `0x17` (RC4-HMAC)** and all belong to ONE account, in a 316 ms burst:

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
All on SRVDC01, Status 0x0 / KDC_ERR_NONE, TicketOptions 0x40810010.

### => ANSWER Step 1: `mfletcher`

Why it's kerberoasting and not noise:
- RC4 downgrade is deliberate — RC4 service tickets are crackable offline (hashcat -m 13100);
  AES256 is far more expensive. Every legit request in this environment uses 0x12.
- 10 distinct SPNs enumerated in 316 ms = scripted, not human.
- The requested "services" are **user accounts** (snielsen, jdrake, svc_mssql...), i.e. accounts
  with a registered SPN — exactly the kerberoast target set.

## Attack timeline for mfletcher (all on SRVDC01)
```
11:33:29.321  4776  NTLM credential validation, mfletcher      <- first appearance / cred test
11:33:29.322  4624  LogonType 3 (network), NTLM/NtLmSsp, from 10.199.0.4
11:33:29.359  4634  logoff
11:36:00.510  4776  NTLM credential validation, mfletcher
11:36:00.513  4624  LogonType 3, NTLM, from 10.199.0.4
11:36:00.601  4768  TGT requested for mfletcher (krbtgt)       <- gets TGT
11:36:00.637-.953  4769 x10, RC4 0x17                          <- KERBEROAST
11:36:00.969  4634  logoff
```
- **Attacker source IP: 10.199.0.4** (`related.ip`), auth over **NTLM LogonType 3** — remote,
  not an interactive workstation logon. Consistent with a tool run from an attacker box.

## Post-exploitation (likely Step 2/3 material)
`svc_mssql` — one of the roasted SPNs — starts authenticating **55 seconds later**, i.e. its
RC4 ticket was cracked offline and the password reused:
```
11:36:55.795  4776/4624 LogonType 3  svc_mssql @ SRVDC01
11:36:55.999  4776/4624 LogonType 3  svc_mssql @ SRVDC02
11:36:57.974  4624     LogonType 3  svc_mssql @ WS01     <- lateral movement
11:37:32.223  4776/4624 LogonType 3  svc_mssql @ SRVDC01
```
None of the other 9 roasted accounts show follow-on logons => svc_mssql is the cracked one.

## TODO
- [ ] Submit `mfletcher` for Step 1, unlock Steps 2 & 3
- [ ] Step 2 likely: which account was cracked (`svc_mssql`) — evidence already gathered
- [ ] Step 3 likely: what the attacker did with svc_mssql (check 4688/Sysmon 1 on WS01/SRVDC)

## Step 2 - encryption type  [CONFIRMED]
Answer format per placeholder `0x22` = raw `TicketEncryptionType` value.
### => ANSWER Step 2: `0x17`   (TicketEncryptionTypeDescription = "RC4-HMAC")
Why RC4 matters: 0x17 service ticket is encrypted with the service account's NTLM hash ->
`$krb5tgs$23$` -> hashcat -m 13100 (fast). 0x12/AES256 -> `$krb5tgs$18$` -> mode 19700,
far slower (AES + 4096-round PBKDF2 string-to-key). RC4 request in an AES domain = the tell.

etype reference: 0x1/0x3 DES | 0x11 AES128 (19600) | 0x12 AES256 (19700) | 0x17 RC4-HMAC (13100)

## Step 3 - exact login @timestamp
Format per placeholder `13:37:45.678_2011-11-01` => HH:MM:SS.mmm_YYYY-MM-DD, UTC as stored.

Exactly TWO 4624 "Logon" events exist for mfletcher in the whole index (both SRVDC01,
LogonType 3, NTLM/NtLmSsp, src 10.199.0.4):
  1. 2025-05-09T11:33:29.322Z  -> 4776 .321 / 4624 .322 / 4634 .359  (38 ms, isolated cred test)
  2. 2025-05-09T11:36:00.513Z  -> 4776 .510 / 4624 .513 / 4768 .601 / 4769 x10 / 4634 .969

### => ANSWER Step 3 (primary): `11:33:29.322_2025-05-09`   <- first use of stolen cred
### fallback if rejected:      `11:36:00.513_2025-05-09`   <- logon chained to the roast

### Step 3 attempts log
- [x] `11:33:29.322_2025-05-09`  -> WRONG (first 4624, the isolated cred-test probe)
- [ ] `11:36:00.513_2025-05-09`  -> NEXT: 2nd/final 4624 for mfletcher, chained to the roast
- [ ] `11:36:55.797_2025-05-09`  -> fallback: svc_mssql first 4624 (if "compromised account"
                                    means the roast VICTIM, not the account that ran it)
Verified exhaustively: 4624 terms agg over the whole index shows `mfletcher: 2` — those two
timestamps are the ONLY logons that account has. svc_mssql has 4 (11:36:55.797 SRVDC01,
11:36:56.001 SRVDC02, 11:36:57.974 WS01, 11:37:32.224 SRVDC01).
Steps 1 (`mfletcher`) and 2 (`0x17`) VALIDATED.

### Format confirmed via platform config (NOT a timezone trap)
GET /api/opensearch-dashboards/settings shows the challenge author pinned:
    dateFormat    = HH:mm:ss.SSS YYYY-MM-DD
    dateFormat:tz = UTC
    timepicker:timeDefaults = {"from":"2025-05-01","to":"2025-05-31"}
=> the flag IS the Discover "Time" column string with the space replaced by `_`,
   and it is UTC, so raw @timestamp values need no shifting. Format is correct;
   only the choice of EVENT is in question.
- [x] `11:36:00.513_2025-05-09`  -> WRONG (2nd 4624 mfletcher). BOTH mfletcher logons rejected
      => "the compromised user account" is NOT the roast operator; it is the roast VICTIM.
- [ ] `11:36:55.797_2025-05-09`  -> NEXT: svc_mssql first 4624 (SRVDC01, LT3 NTLM, 10.199.0.4)
- [ ] `11:36:57.974_2025-05-09`  -> fallback 1: svc_mssql onto WS01 (lateral movement)
- [ ] `11:36:00.601_2025-05-09`  -> fallback 2: mfletcher 4768 TGT, if "login" == Kerberos AS

### New finding: ANONYMOUS LOGON immediately before the cracked-cred use
11:36:55.614  4624  ANONYMOUS LOGON  SRVDC01  LT3 NTLM  from 10.199.0.4
11:36:55.623  4624  ANONYMOUS LOGON  SRVDC02  LT3 NTLM  from 10.199.0.4
11:36:55.795  4776  svc_mssql        SRVDC01
11:36:55.797  4624  svc_mssql        SRVDC01  LT3 NTLM  from 10.199.0.4
Null-session enumeration 180 ms before the attacker swaps in the cracked credential.

### Benign baseline (for contrast — do NOT confuse with the attack)
Administrator + rvillanueva both authenticate over **Kerberos** from 10.98.98.x (internal
server/workstation subnet). The attacker's traffic is exclusively **NTLM from 10.199.0.4**.
Auth package + source subnet alone separate attacker from legitimate admin activity here.
- [x] `11:36:55.797_2025-05-09`  -> WRONG (svc_mssql first 4624)
- [ ] `11:36:00.601_2025-05-09`  -> NEXT: mfletcher's 4768 (Kerberos TGT request)

### Why 4768, reasoned properly this time
Per-account event breakdown:
    mfletcher      4624x2, 4634x2, 4776x2, **4768x1**
    svc_mssql      4624x4, 4634x4, 4776x4   (no 4768 at all - attacker used NTLM w/ cracked pw)
    Administrator  4688x40, 4624x21, 4634x20, 4648x7, 4768x5
    rvillanueva    4688x11, 4624x2, 4634x1
1. UNIQUENESS: every previous guess came from a field with 2+ equally valid values. A single-
   answer step must come from a filter returning exactly ONE doc. mfletcher+4768 = 1 doc.
2. SEMANTICS: 4768 "A Kerberos authentication ticket (TGT) was requested" IS the domain login
   in Kerberos terms. 4624 = downstream session; 4776 = NTLM cred validation. Kerberos challenge
   => Kerberos login event.
3. CONSISTENCY WITH STEP 2: mfletcher's 4768 is enc=0x17 - the ONLY non-AES TGT in the entire
   index (all 5 Administrator TGTs are 0x12). Steps 2 and 3 point at the same event.
LESSON: "login" in a Windows log defaults to 4624 in my head; in a Kerberos context that reflex
is wrong. Check event-ID cardinality per account to find the unambiguous one.
- [x] `11:36:00.601_2025-05-09`  -> WRONG (mfletcher 4768)
- [X] **`11:37:32.224_2025-05-09` -> CORRECT** (svc_mssql 4th 4624, SRVDC01)

### THE ACTUAL DISCRIMINATOR: session duration (4624 -> 4634 paired on LogonId)
  11:36:55.797 -> 11:36:55.952  SRVDC01  0x1d4dfac    0.155s   probe
  11:36:56.001 -> 11:36:56.138  SRVDC02  0x1a21ffe    0.137s   probe
  11:36:57.974 -> 11:36:58.094  WS01     0x1bf6f06    0.120s   probe
  11:37:32.224 -> 11:37:45.749  SRVDC01  0x1d4f3cb   13.525s   <- REAL SESSION = "the login"
First three = tool validating the cracked password against each host (~130 ms each).
Fourth = the session where the attacker actually operated.
LESSON: "the login" != first logon. Pair 4624 to 4634 on LogonId and rank by duration;
credential-validation blips are sub-second, real sessions are seconds+. I had already spotted
this pattern on mfletcher's 38 ms probe at 11:33:29 and failed to reapply it to svc_mssql.
CHALLENGE SOLVED: mfletcher / 0x17 / 11:37:32.224_2025-05-09
