# Root-Me — Command & Control - level 2 (ch2, Forensic)

**Points:** 15 · **Category:** Memory analysis · **Flag format:** the workstation's hostname

## Challenge
> Congratulations Berthier, thanks to your help the computer has been identified.
> You have requested a memory dump but before starting your analysis you wanted to
> take a look at the antivirus' logs. Unfortunately, you forgot to write down the
> workstation's hostname. But since you have its memory dump you should be able to
> get it back!
>
> The validation flag is the workstation's hostname.
> The uncompressed memory dump md5 hash is `e3a902d4d44e0f7bd9cb29865e0a15de`.

We're given `ch2.tbz2`.

## Approach

### 1. Unwrap and verify
```
tar -tjf ch2.tbz2          # -> ch2.dmp
tar -xjf ch2.tbz2
md5sum ch2.dmp             # e3a902d4d44e0f7bd9cb29865e0a15de  ✓ matches statement
```
`ch2.dmp` is a **512 MB raw memory dump** (`file` says just `data` — no crashdump
header, so it's a flat physical-memory image, not a `.crash`/hiberfil).

### 2. Fingerprint the OS
The header is all zeroes, so identify it from content instead:

```
strings -a ch2.dmp | grep -iE "windows (xp|2003|vista|7|server)" | sort -u
```
```
StrgWindows 7 Enterprise 6.1
StrgWindows 7 Enterprise 7600
Windows 7 Enterprise, 32-bit  (Build 7600)
```

**Windows 7 Enterprise, 32-bit, build 7600 (RTM).** Confirmed by Volatility:

```
vol -f ch2.dmp banners.Banners
# 0x291d8dc   ntkrpamp.pdb|5B308B4ED6464159B87117C711E7340C|2
```

`ntkrpamp` = **n**t **k**e**r**nel, **PA**E, **m**ulti**p**rocessor — consistent
with 32-bit PAE Windows 7.

### 3. The Volatility route (and why it stalled)
The textbook solution is the registry:

```
vol -f ch2.dmp windows.registry.printkey \
    --key "ControlSet001\\Control\\ComputerName\\ComputerName"
```

That never ran. Volatility 3 (2.28.0) reported:

```
Unsatisfied requirement plugins.Info.kernel.layer_name
Unsatisfied requirement plugins.Info.kernel.symbol_table_name
```

Worth being precise about the cause, because the error message conflates two
things. The symbols were **not** the problem — after fetching the 801 MB pack:

```
unzip -l symbols/windows.zip | grep 5B308B4ED6464159B87117C711E7340C
#  windows/ntkrpamp.pdb/5B308B4ED6464159B87117C711E7340C-2.json.xz   ← present
```

The exact GUID is there. What failed is the layer *below* it: the automagic
couldn't locate a valid DTB / self-referential page directory, so it never built
the Intel address-translation layer — and with no virtual-address space, the
symbol table has nothing to bind to. A 2013-era acquisition tool on 32-bit PAE is
a well-known source of this friction with modern Volatility 3.

Rather than fight the layer reconstruction, note what the task actually needs.

### 4. Pivot: carve the hostname from raw memory
We don't need reconstructed virtual memory. A Windows hostname is written into
memory over and over — process environment blocks, event-log records, RPC
endpoint names, SMB/NetBIOS bindings, UNC paths. Any one of those is a plain
string sitting in the physical image.

The catch: **Windows stores nearly all of this as UTF-16LE**, which plain
`strings` misses because every character is followed by a NUL byte. Use `-el`
(16-bit little-endian):

```
strings -a -el ch2.dmp | grep -i "COMPUTERNAME=" | sort -u
```
```
COMPUTERNAME=WI
COMPUTERNAME=WIN-ETSA9
COMPUTERNAME=WIN-ETSA91RKC
COMPUTERNAME=WIN-ETSA91RKCFP        ← full value
```

(The short hits are partially-overwritten or truncated copies in freed pages —
normal in a memory image. The longest consistent value is the real one.)

### 5. Corroborate before trusting it
One string is a guess; five independent kernel structures agreeing is an answer.

```
strings -a -el ch2.dmp | grep -i "WIN-ETSA" | sort -u
```

| Source structure | Evidence in the dump |
|---|---|
| Process environment block | `COMPUTERNAME=WIN-ETSA91RKCFP` |
| Windows Event Log XML | `<Computer>WIN-ETSA91RKCFP</Computer>` |
| NetBIOS / SMB binding | `\Device\NetbiosSmbWIN-ETSA91RKCFPWORKGROUP` |
| NetBT over TCP/IP | `\Device\NetBT_Tcpip_{A13A8FB8-…}WIN-ETSA91RKCFPWORKGROUP` |
| Local RPC endpoints | `calrpc:WIN-ETSA91RKCFP[LSMApi]`, `[plugplay]` |
| WMI namespace path | `\\WIN-ETSA91RKCFP\ROOT\CIMV2:__Win32Provider` |
| Printer UNC path | `\WIN-ETSA91RKCFP\HP LaserJet 1018` |
| Logon / net env | `SERVER=\\WIN-ETSA91RKCFP`, `DOMAIN=WIN-ETSA91RKCFP` |

Occurrence counts: **393** ASCII hits, **1754** UTF-16LE hits — note how the
UTF-16 pass finds ~4.5× more. That ratio is the whole argument for `-el`.

Two sanity checks that it isn't truncated:
- `WIN-ETSA91RKCFP` is **exactly 15 characters** — the NetBIOS name limit.
- It matches Windows' auto-generated installer format: `WIN-` + 11 random
  alphanumerics = 15. So the machine was never manually renamed.

## Flag
```
WIN-ETSA91RKCFP
```

## Bonus findings
The dump answers more than it was asked, which is useful context for the rest of
the Command & Control series:

- **Primary user:** `John Doe` — `C:\Users\John Doe\`
- **The antivirus log the statement mentions** is in there, matching the
  `WIN-ETSA91RKCFP/John Doe` account against a network printer:
  ```
  <COPIER on S-CI-PRT06#:7> <WIN-ETSA91RKCFP\John Doe> <0> <0>) = rejected
  1/12/2013  12:25:11 PM  00000410:   OS Windows 7 Workstation
  ```
- **Workgroup:** `WORKGROUP` (not domain-joined)
- **Installed software:** LibreOffice 3 (`AppData\Roaming\LibreOffice\3`)
- **Timeframe:** activity around `12.01.2013`, dump dated 29 Jan 2013

## Lesson
- **`strings -el` is mandatory on Windows images.** Windows is UTF-16LE
  internally; a plain `strings` pass silently hides most of the interesting
  data. Here it was the difference between 393 and 1754 hits.
- **A failed Volatility profile is not a dead end.** Distinguish *symbols
  missing* from *translation layer failed* — they produce the same error text but
  have different fixes, and neither blocks raw carving. For flat physical dumps,
  string carving needs no address translation at all.
- **Host identity is massively redundant in memory.** Environment blocks, event
  logs, RPC endpoints, and NetBIOS bindings all independently carry the hostname,
  so it survives even heavily corrupted or partial acquisitions.
- **Corroborate across independent structures.** A single string could be a
  stale, truncated, or attacker-planted artifact; agreement across the event log,
  NetBIOS binding, and PEB is what makes it evidence.
- **Length is a checksum.** 15 chars = NetBIOS cap, and `WIN-` + 11 = an
  untouched default install name — both confirm nothing was cut off.
