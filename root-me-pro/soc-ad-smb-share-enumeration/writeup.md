# SOC AD — SMB Share Enumeration

**Platform:** Root-Me Pro · **Category:** SOC / Blue Team · **Difficulty:** Easy · **Points:** 250
**Date solved:** 2026-08-09 · **Dataset date:** 2026-04-30

## Challenge

> The SOC team received an alert from the file server: an abnormal volume of SMB accesses was
> detected over a short period. A user account appears to have accessed an unusual number of
> shares within minutes, including shares they had never consulted before.
>
> The SIEM collects Windows Security Events from the entire environment: workstations, file
> servers, and domain controller.

Four steps: the account used, the source IP, the start time (UTC), and the sensitive file found.

## Answers

| Step | Question | Answer |
|---|---|---|
| 1 | Which user account was used for the enumeration? | `rthomas` |
| 2 | From which IP address was it launched? | `192.168.10.55` |
| 3 | At what time (UTC) did it begin? | `10:34:12` |
| 4 | Name of the sensitive file discovered? | `admin_creds.csv` |

## Approach

### 1. Getting at the data

The challenge hands you a JWT-bearing URL. It is a **public HTTPS host — no WireGuard needed**,
which is unusual for Root-Me Pro and worth checking before bringing the VPN up.

```bash
curl -s -c cookies.txt -L "https://soc.challenges.root-me.pro/?token=$TOK"
```

The redirect to `/app/data-explorer/discover` identifies the stack as **OpenSearch Dashboards**,
not stock Kibana. The token exchange drops two session cookies (`security_authentication`,
`security_authentication_jwt1`).

Rather than click through Discover, I drove the backend from the CLI through the console proxy:

```bash
curl -s -b cookies.txt -X POST \
  "https://soc.challenges.root-me.pro/api/console/proxy?path=<urlencoded>&method=GET" \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' --data-binary '<query>'
```

The `osd-xsrf: true` header is mandatory — OpenSearch Dashboards rejects the POST without it.

**Two obstacles worth remembering:**

*Cluster APIs are blocked.* `_cat/indices` returns 403 `no permissions for [cluster:monitor/state]`
— the CTF role is scoped to a single tenant. The index name comes from the saved-objects API instead:

```bash
curl -s -b cookies.txt "…/api/saved_objects/_find?type=index-pattern&fields=title"
# → index-3581f3069079-windows
```

*Aggregations fail on string fields.* Every `winlog.event_data.*` field is mapped as `text`:

```
Text fields are not optimised for operations that require per-document field data…
```

Fix is the `.keyword` subfield — `winlog.event_data.SubjectUserName.keyword`.

### 2. Profiling the dataset

1348 documents, one day (`08:00:23Z` → `18:59:13Z`), winlogbeat 8.12 schema.

```
4769(300) 4768(209) 4624(162) 1644(150) 1(131) 5145(117) 3(104) 4634(89) 5140(61) 4672(25)
```

The two that matter for SMB share access:

- **5140** — a network share object was accessed
- **5145** — a network share object was checked for desired access (per-file detail)

Host inventory built from `host.hostname` / `host.ip`:

| Host | IP | Role |
|---|---|---|
| DC01 | 192.168.10.10 | Domain controller |
| SRV-APP01 | 192.168.10.60 | App server |
| SRV-FILE01 | 192.168.10.70 | File server |
| SRV-WEB01 | 192.168.10.80 | Web server |
| WS01 | 192.168.10.42 | Workstation |
| **WS02** | **192.168.10.55** | **Attacker source** |
| WS03 | 192.168.10.56 | Workstation |

### 3. Finding the account (Step 1)

The key insight: **rank users by distinct-share cardinality, not raw event count.** A chatty
legitimate user can generate plenty of 5145s against one share; an enumerator hits *many
different* shares in a *tight window*.

```json
{"size":0,
 "query":{"terms":{"winlog.event_id":[5140,5145]}},
 "aggs":{"users":{
   "terms":{"field":"winlog.event_data.SubjectUserName.keyword","size":50,
            "order":{"distinct_shares":"desc"}},
   "aggs":{"distinct_shares":{"cardinality":{"field":"winlog.event_data.ShareName.keyword"}},
           "first":{"min":{"field":"@timestamp"}},
           "last":{"max":{"field":"@timestamp"}}}}}}
```

| user | events | distinct shares | window |
|---|---|---|---|
| **rthomas** | **53** | **14** | **54 seconds** |
| admin.ti | 18 | 2 | 6h50m |
| jmartin | 18 | 2 | 7h32m |
| mdurand | 18 | 2 | 7h30m |
| *(7 others)* | 6–18 | 1–2 | hours |

Every legitimate account: 1–2 shares spread across the working day. `rthomas`: **14 shares in
54 seconds.** No ambiguity.

### 4. Source IP and start time (Steps 2 & 3)

All 53 burst events carry a single `IpAddress` — **192.168.10.55** (WS02). The first is:

```
2026-04-30T10:34:12.000Z  EID 5140  \\*\IPC$  SRV-FILE01  src=192.168.10.55
```

Index timestamps are already UTC (`Z` suffix), so no timezone conversion — **10:34:12**.

### 5. The sensitive file (Step 4)

34 distinct files were touched during the sweep. Querying `RelativeTargetName` for
`admin_creds.csv` returns **exactly one hit in the whole 1348-event dataset**:

```
2026-04-30T10:34:33.000Z  rthomas  src=192.168.10.55  \\*\IT  mask=0x120089
```

`AccessMask 0x120089` = read data + read attributes + read control. No legitimate user ever
opened this file — it is genuinely attacker-*discovered*, which is what makes it the answer over
near-misses like `vpn_config.zip` or `access_matrix.xlsx`.

## The activity

The sweep hit three hosts in sequence, **`IPC$` first on each** (session setup / share listing via
`srvsvc`), then admin shares, then every named share:

- **SRV-FILE01** — IPC$, C$, ADMIN$, Public, HR, Finance, IT, Projects, Backups, Users
- **SRV-APP01** — IPC$, C$, AppData, Logs
- **DC01** — IPC$, SYSVOL, NETLOGON

Sensitive material exposed: `IT\admin_creds.csv`, `IT\vpn_config.zip`, `HR\employee_list.xlsx`,
`Finance\budget_Q1.xlsx`, `Users\access_matrix.xlsx`, `NETLOGON\logon_script.bat`,
`SYSVOL\Policies.xml`.

### Attribution — the tool

Although not asked, Sysmon **EID 1** on WS02 names it outright, 2 seconds before the first share hit:

```
10:34:10  WS02.rootme.local  ROOTME\rthomas  C:\Python311\python.exe
CMD: python.exe -m manspider --dir /home/rthomas/loot --threads 10 \
     -u rthomas -p "***" --domain rootme.local -t SRV-FILE01,SRV-APP01,DC01
```

**[manspider](https://github.com/blacklanternsecurity/MANSPIDER)** — an SMB share spider that
crawls shares and pulls files matching patterns. `--threads 10` explains the sub-second spacing.

Two independent corroborations:

- **Sysmon EID 3** — `python.exe` → `192.168.10.70:445`, `192.168.10.60:445`, `192.168.10.10:445`,
  all at 10:34:11.
- **EID 4624** — three Type-3 (network) logons for rthomas in the *same second* (10:34:11) on
  SRV-FILE01, SRV-APP01 and DC01, all from 192.168.10.55. Parallel authentication to three hosts
  at once is not human behaviour.

## Detection logic

The generalisable rule — alert on distinct-share cardinality per account per short window:

```
EventID:(5140 OR 5145)
| stats dc(ShareName) as shares, min(_time) as first, max(_time) as last by SubjectUserName
| where shares >= 5 AND (last - first) < 300
```

Strong supporting signals:

- `IPC$` accessed immediately before a run of other shares on the same host (share listing).
- `C$` / `ADMIN$` accessed by a non-admin account.
- `pagefile.sys` / `hiberfil.sys` in `RelativeTargetName` — nobody opens these by hand; a
  spider hitting `C$` trips over them because they sit at the filesystem root.
- Multiple 4624 Type-3 logons for one account across several hosts within the same second.

## Lessons

1. **Cardinality beats volume for enumeration detection.** Sorting by event count would have
   surfaced rthomas only fourth or so. `cardinality` on the share name over a short window is
   the discriminator — the behavioural signature is *breadth*, not *volume*.
2. **`IPC$` first is the enumeration tell.** Any tool that lists shares (`net view`, smbclient
   `-L`, CrackMapExec/NetExec, manspider) binds `IPC$` to reach `srvsvc` before touching real
   shares. `IPC$` followed by a fan-out across shares on the same host = enumeration.
3. **Filesystem artefacts leak tool behaviour.** `pagefile.sys` and `hiberfil.sys` in the 5145
   stream are a fingerprint of an automated crawl of `C$`, not of a user.
4. **Correlate the security log with Sysmon.** 5140/5145 tell you *what* was accessed; Sysmon
   EID 1 gave the exact command line, and EID 3 the 445/tcp connections. Three independent
   angles on the same 54 seconds.
5. **Drive the SIEM by API.** With text-mapped fields and a locked-down role, a handful of
   `_search` aggregations through `/api/console/proxy` was far faster than the Discover UI —
   and reproducible. Remember `osd-xsrf: true` and `.keyword`.
6. **Same-second logons across hosts = automation.** Humans cannot authenticate to three
   servers simultaneously; the 10:34:11 triple-4624 alone justifies an alert.
