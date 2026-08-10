# SOC AD — SMB Share Enumeration (Root-Me Pro, SOC, Easy, 250pts)

Access: `https://soc.challenges.root-me.pro/?token=<JWT>` (token in `files/token.txt`, ~8h expiry)
Reachable **without** the WireGuard VPN — it's a public HTTPS Kibana/OpenSearch Dashboards.

## Recon of the SIEM

- Stack is **OpenSearch Dashboards** (redirects to `/app/data-explorer/discover`), not stock Kibana.
- Auth: hit the `?token=` URL with a cookie jar → get `security_authentication` + `security_authentication_jwt1` cookies.
- Cluster-level APIs are **denied** (`_cat/indices` → 403 `cluster:monitor/state`). Role is scoped to one tenant.
- Found the index via the saved-objects API instead:
  `GET /api/saved_objects/_find?type=index-pattern&fields=title`
  → index pattern `index-3581f3069079-windows`
- Query path that works: `POST /api/console/proxy?path=<urlenc>&method=GET|POST` with header `osd-xsrf: true`.
  Helper script: `os.sh`.

### Gotcha
String fields are mapped as `text` — aggregations fail with
`Text fields are not optimised for operations that require per-document field data`.
Use the `.keyword` subfield: `winlog.event_data.SubjectUserName.keyword`.

## Dataset

- **1348 docs**, single day: `2026-04-30 08:00:23Z` → `18:59:13Z`
- Event IDs: 4769(300) 4768(209) 4624(162) 1644(150) 1(131) 5145(117) 3(104) 4634(89) 5140(61) 4672(25)
- Schema is winlogbeat 8.12 ECS-ish: `winlog.event_id`, `winlog.event_data.*`, `winlog.computer_name`, `host.hostname`, `host.ip`, `user.name`.

### Host / IP inventory
| Host | IP | Role |
|---|---|---|
| DC01 | 192.168.10.10 | Domain controller |
| SRV-APP01 | 192.168.10.60 | App server |
| SRV-FILE01 | 192.168.10.70 | File server |
| SRV-WEB01 | 192.168.10.80 | Web server |
| WS01 | 192.168.10.42 | Workstation |
| **WS02** | **192.168.10.55** | Workstation — **attacker source** |
| WS03 | 192.168.10.56 | Workstation |

## Finding the enumeration

Aggregated EID **5140** (network share object accessed) + **5145** (detailed file share access check)
by `SubjectUserName.keyword`, ordered by **cardinality of ShareName** — distinct shares is the
discriminator, not raw event count.

| user | events | distinct shares | window | src |
|---|---|---|---|---|
| **rthomas** | **53** | **14** | **10:34:12→10:35:06 (54s)** | 192.168.10.55 |
| admin.ti | 18 | 2 | 6h50m | .56 |
| cleblanc | 18 | 2 | 4h08m | .56 |
| jmartin | 18 | 2 | 7h32m | .55 |
| mdurand | 18 | 2 | 7h30m | .56 |
| pdupont | 15 | 2 | 5h58m | .55 |
| tmoreau | 12 | 2 | 7h05m | .55 |
| agarcia / lhernandez / nwilson / svc-backup | 6–8 | 1 | hours | — |

Every legit user: 1–2 shares over hours. rthomas: 14 shares in under a minute. Unambiguous.

## The burst (10:34:12 → 10:35:06)

Three hosts swept in sequence, `IPC$` first on each (session setup / share listing),
then admin shares, then every named share:

- **SRV-FILE01** — IPC$, C$, ADMIN$, Public, HR, Finance, IT, Projects, Backups, Users
- **SRV-APP01** — IPC$, C$, AppData, Logs
- **DC01** — IPC$, SYSVOL, NETLOGON

Sensitive files touched: `IT\admin_creds.csv`, `IT\vpn_config.zip`, `HR\employee_list.xlsx`,
`Finance\budget_Q1.xlsx`, `Users\access_matrix.xlsx`, `NETLOGON\logon_script.bat`, `SYSVOL\Policies.xml`.

## Attribution — the tool

Sysmon **EID 1** on WS02, 2 seconds before the first share hit:

```
10:34:10  WS02.rootme.local  ROOTME\rthomas  C:\Python311\python.exe
CMD: python.exe -m manspider --dir /home/rthomas/loot --threads 10 \
     -u rthomas -p "***" --domain rootme.local -t SRV-FILE01,SRV-APP01,DC01
```

**manspider** (blacklanternsecurity/MANSPIDER) — SMB share spider that crawls shares and
downloads files matching patterns. `--threads 10` explains the sub-second share hits.

Sysmon **EID 3** corroborates — `python.exe` → 445/tcp on all three targets at 10:34:11:
`192.168.10.70:445`, `192.168.10.60:445`, `192.168.10.10:445`.

**EID 4624** — three Type-3 (network) logons for rthomas at the *same second* 10:34:11 on
SRV-FILE01, SRV-APP01 and DC01, all from 192.168.10.55. Parallel auth = automation.

## Answers

- **Step 1 — user account used for the enumeration: `rthomas`** ✅ accepted
- **Step 2 — IP the enumeration was launched from: `192.168.10.55`** (= WS02.rootme.local)
  All 53 burst events carry that single `IpAddress`; matches the host that spawned manspider.
- **Step 3 — time (UTC) the enumeration began: `10:34:12`** (format `hh:mm:ss`)
  First EID 5140, `\\*\IPC$` on SRV-FILE01, `2026-04-30T10:34:12.000Z`. Index timestamps are
  already UTC (`Z` suffix) — no TZ conversion needed.
  *Alternate if rejected:* `10:34:10` = Sysmon EID 1 `manspider` process launch, 2s earlier.
- **Step 4 — sensitive file discovered: `admin_creds.csv`**
  Read from `\\SRV-FILE01\IT` at `10:34:33`, `AccessMask 0x120089` (read data + attributes).
  Appears **exactly once in all 1348 events** — only rthomas ever touched it, so it is
  attacker-discovered rather than routine access. 34 distinct files were swept in total;
  `vpn_config.zip` is the runner-up but `admin_creds.csv` is the unambiguous credential store.

All four steps solved. Not needed in the end: the 150 EID-1644 LDAP events (red herring /
background AD noise), and the Kerberos 4768/4769 traffic.

## Dead ends / notes
- `1644` (150 events, LDAP expensive-search on DC01) not yet examined — may matter for a later
  step about AD recon preceding the SMB sweep.
- rthomas has plenty of *benign-looking* activity all day from several IPs (.42, .56, .60, .70, .80);
  only the 10:34 window from .55/WS02 is the enumeration.
