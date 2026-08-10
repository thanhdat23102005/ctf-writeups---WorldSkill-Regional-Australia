# SOC AD - LDAP Enumeration — notes

Platform: Root-Me Pro (SOC) | Category: SOC / Blue Team | Difficulty: Easy | 200 pts | ~30 min
Brief: "Kinda noisy" — volumetric alert from the DC, abnormal number of LDAP queries in a few seconds.
SIEM collects DC **Directory Service** channel + **Sysmon** from workstations.
Hint: "The pentest team was supposed to have finished yesterday. This might not be them."

## SIEM access

Entry URL sets cookies then redirects to `/app/data-explorer/discover`.
Header `osd-name: soc-dashboards` → **OpenSearch Dashboards**, not Kibana.

```bash
curl -s -i "https://soc.challenges.root-me.pro/?token=<JWT>" -c soc.cookies
```

- `_cat/indices` → 403 `security_exception` (no `cluster:monitor/state`). Index name not directly listable.
- Workaround: saved-objects API exposes the index pattern:
  ```bash
  curl -s -b soc.cookies "https://soc.challenges.root-me.pro/api/saved_objects/_find?type=index-pattern&fields=title&per_page=100" -H "osd-xsrf: true"
  ```
  → `index-87a8ae7d1d27-windows` (1184 docs)
- Query via console proxy (`q.sh` wrapper in `files/`):
  ```bash
  curl -s -b soc.cookies -X POST \
    "https://soc.challenges.root-me.pro/api/console/proxy?path=index-87a8ae7d1d27-windows%2F_search&method=POST" \
    -H "osd-xsrf: true" -H "Content-Type: application/json" --data '{"size":1,"query":{"match_all":{}}}'
  ```
- Gotcha: aggregations on text fields fail (fielddata disabled). Use `.keyword` subfields:
  `winlog.channel.keyword`, `host.hostname.keyword`. `winlog.event_id` is numeric — aggregates fine.

## Dataset shape

| Channel | Count | Event IDs |
|---|---|---|
| Security | 729 | 4624 (225), 4769 (200), 4768 (134), 4634 (100), 4776 (40), 4672 (30) |
| Microsoft-Windows-Sysmon/Operational | 365 | 1 (151), 3 (128), 22 (85), 11 (1) |
| Directory Service | 90 | 1644 (90) |

Hosts: DC01 (588), WS01 (159), SRV-APP01 (156), WS02 (142), SRV-FILE01 (139)
Domain: `rootme.local` / NetBIOS `ROOTME`. DC01 = 192.168.10.10.

Time range of all data: 2026-04-17.

## Step 1 — what tool was executed?

**Answer: `SharpHound.exe`**

### Path taken

1. Event **1644** = "expensive/inefficient LDAP search" on the DS channel. Its `event_data` carries
   `SearchFilter`, `StartingNode`, `Attributes`, `VisitedEntries`, `ReturnedEntries`, `TimeMilliseconds`,
   **`ClientIP`** (ip:port). That ClientIP is the pivot.
2. Pulled all 90 and bucketed by client IP:

   | ClientIP | count | character |
   |---|---|---|
   | 192.168.10.42 | 35 | **all inside a 61-second window** |
   | 192.168.10.60 | 28 | spread across the whole day, benign filters |
   | 192.168.10.70 | 19 | spread, benign |
   | 192.168.10.55 | 8 | spread, benign |

   Burst: `10:22:02` → `10:23:03` from **192.168.10.42**. That's the volumetric alert.
3. Filter sequence in the burst is a BloodHound collection fingerprint:
   ```
   (objectClass=domain) (objectCategory=computer) (&(samAccountType=805306368))
   (objectClass=group) (objectCategory=groupPolicyContainer) (objectCategory=organizationalUnit)
   (objectClass=container) (objectClass=trustedDomain)
   (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))   <- Kerberoastable
   (&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)) <- unconstrained deleg
   (msDS-AllowedToDelegateTo=*)                                                    <- constrained deleg
   (msDS-AllowedToActOnBehalfOfOtherIdentity=*)                                    <- RBCD
   (&(adminCount=1)(objectClass=user)) / (&(adminCount=1)(objectClass=group))      <- protected/AdminSDHolder
   (&(objectClass=group)(sAMAccountName=Domain Admins|Enterprise Admins|Schema Admins))
   (objectClass=pKICertificateTemplate) (objectClass=pKIEnrollmentService)
   (objectClass=certificationAuthority)                                            <- ADCS
   (objectClass=msDS-PasswordSettings) (objectClass=site) (objectClass=subnet) (objectClass=msWMI-Som)
   ```
4. Pivoted to Sysmon on 192.168.10.42 (= **WS01**) in that window:

   | Time | EID | Detail |
   |---|---|---|
   | 10:21:30–10:21:50 | 22 (DNS) | `C:\Users\jbernard\Downloads\SharpHound.exe` resolving `dc01.rootme.local` (×5) |
   | **10:22:00** | **1 (proc create)** | `"C:\Users\jbernard\Downloads\SharpHound.exe" -c All --zipfilename bloodhound.zip` |
   | 10:22:01–10:22:43 | 3 (net conn) | SharpHound.exe → 192.168.10.10:**389** (LDAP), ×8, new source port each time |
   | 10:22:50 | 11 (file create) | `C:\Users\jbernard\Downloads\bloodhound.zip` |

### Process-create details (the money event)

```json
{
  "Image": "C:\\Users\\jbernard\\Downloads\\SharpHound.exe",
  "CommandLine": "\"C:\\Users\\jbernard\\Downloads\\SharpHound.exe\" -c All --zipfilename bloodhound.zip",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "User": "ROOTME\\jbernard",
  "ProcessId": "6284", "ParentProcessId": "3120",
  "Hashes": "MD5=23F207E579CB45C88E9D7FF05620D05C",
  "CurrentDirectory": "C:\\Users\\jbernard\\"
}
```

Note the EID 11 is the **only** file-create event in the entire dataset — `bloodhound.zip`.
Nice single-event tell if you'd searched that way instead.

### Re: "this might not be them"

Not the pentest team: ran as **`ROOTME\jbernard`**, from that user's own `Downloads`, on **WS01**,
launched from an interactive `cmd.exe` — a day after the engagement was supposed to have ended.
Compromised user account / insider, not a sanctioned test box.

## Step 2 — source IP of the massive LDAP queries?

**Answer: `192.168.10.42`** (= WS01) — CONFIRMED CORRECT.

Same evidence as Step 1: `ClientIP` on all 35 burst 1644s, and `SourceIp` on the Sysmon EID 3
connections from SharpHound.exe to 192.168.10.10:389.

## Step 3 — which EID on the DC's Directory Service channel = a diagnosed LDAP query?

**Answer: `1644`** — CONFIRMED CORRECT.

Only EID present on that channel here (90/90). Provider `Microsoft-Windows-ActiveDirectory_DomainService`.
"Expensive / inefficient / slow LDAP search" — emitted only when the AD diagnostic
`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering` is raised (e.g. = 5).
Off by default → enabling it is the standard detection-engineering step for LDAP recon.
Thresholds tune via `Search Time Threshold (msecs)` and `Expensive Search Results Threshold`.

## Step 4 — LDAP filter characteristic of BloodHound GPO enumeration?

**Answer: `(objectCategory=groupPolicyContainer)`** (submitted, awaiting confirmation)

Two hits, both from 192.168.10.42 inside the burst:

| Time | Attributes |
|---|---|
| 10:22:11 | `gPCFileSysPath;name;displayName;gPCMachineExtensionNames;flags;versionNumber` |
| 10:22:58 | `objectGUID;displayName;gPCFileSysPath;flags;versionNumber;nTSecurityDescriptor` |

`gPCFileSysPath` = SYSVOL path of the GPO. Second pass pulls `nTSecurityDescriptor` → SharpHound
building ACL edges (GenericWrite / WriteDacl / WriteOwner on a GPO = GPO-abuse attack path).
Paired with `(objectCategory=organizationalUnit)` at 10:22:12 and 10:23:01 — GPO links need the OU tree.

Note the filter uses `objectCategory`, not `objectClass` — objectCategory is single-valued and indexed,
so it's the efficient form a real collector uses. Handy discriminator when writing detections.

## Leads for later steps (not yet chased)

- 10:35:36 — 4624 Kerberos LogonType 3 for **`svc-backup`** from 192.168.10.42, ~13 min after the collection.
  Looks like the follow-on: BloodHound path → service account.
- `svc-backup` and `svc-sql` are repeatedly targeted by `(sAMAccountName=...)` lookups from .60/.70 all day.
- 200× 4769 (TGS) / 134× 4768 (TGT) in the set — Kerberoasting would show as 4769 with RC4 encryption type.
- 10:17:52 — conhost/cmd running as `ROOTME\tmartin` but `CurrentDirectory: C:\Users\jbernard\`, IntegrityLevel High.
  Worth a second look if a step asks about lateral movement or account misuse.

## Files

- `files/all-events.json` — full 1184-doc dump
- `files/ds1644.json` — the 90 Directory Service events
- `files/q.sh` — query wrapper for the OpenSearch console proxy
