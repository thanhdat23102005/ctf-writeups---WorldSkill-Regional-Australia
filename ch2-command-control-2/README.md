# Root-Me — Command & Control - level 2 (ch2)

Forensic / memory-analysis challenge writeup. A 512 MB Windows 7 raw memory dump
whose workstation hostname must be recovered.

**Flag:** `WIN-ETSA91RKCFP`

## Contents
- [`writeup.md`](writeup.md) — full walkthrough (approach → carving → flag → lesson)
- [`notes.md`](notes.md) — raw working notes
- `files/`
  - `fetch.sh` — downloads `ch2.tbz2` and extracts + verifies `ch2.dmp`
  - `ch2.tbz2` (185 MB), `ch2.dmp` (512 MB) — too large for GitHub, git-ignored
    (run `fetch.sh`)

## TL;DR
`ch2.tbz2` → `ch2.dmp`, a 512 MB flat physical memory image of **Windows 7
Enterprise 32-bit build 7600**. Volatility 3 has the right kernel symbols
(`ntkrpamp.pdb/5B308B4E…`) but fails to build the Intel translation layer, so
`windows.registry.printkey` is unavailable. No matter — the hostname doesn't need
address translation. `strings -a -el` (UTF-16LE!) recovers
`COMPUTERNAME=WIN-ETSA91RKCFP`, corroborated by the event log
(`<Computer>`), NetBIOS/SMB bindings, RPC endpoints and WMI paths.

## Note on the artifacts
Unlike `ch39-deleted-file/`, the original download is **not** committed here —
`ch2.tbz2` is 185 MB, over GitHub's 100 MB per-file hard limit. `files/fetch.sh`
re-downloads it from Root-Me and verifies the md5 published in the statement
(`e3a902d4d44e0f7bd9cb29865e0a15de`).
