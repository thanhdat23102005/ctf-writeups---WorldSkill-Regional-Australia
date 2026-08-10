# ch2 — Command & Control - level 2 (Root-Me, Forensic)

## Challenge
- Memory dump of a workstation; recover its hostname. Flag = the hostname.
- 15 points, category "Memory analysis", author Thanat0s.
- File: https://static.root-me.org/forensic/ch2/ch2.tbz2  (185 MB)
- md5 of uncompressed dump (given in statement): e3a902d4d44e0f7bd9cb29865e0a15de — verified OK

## Steps
1. `tar -xjf ch2.tbz2` -> `ch2.dmp`, 512 MB, mtime 2013-01-29.
   `file ch2.dmp` -> just "data"; first 16 bytes all zero => flat physical dump,
   not a Windows crashdump (no PAGEDUMP/PAGEDU64 magic).
2. OS fingerprint via strings: "Windows 7 Enterprise, 32-bit (Build 7600)",
   "StrgWindows 7 Enterprise 6.1" / "7600".
3. No volatility on the box. `pip3 install volatility3 --break-system-packages`
   -> vol 2.28.0 at ~/.local/bin/vol.
4. `vol -f ch2.dmp banners.Banners`
   -> ntkrpamp.pdb|5B308B4ED6464159B87117C711E7340C|2  (at 0x291d8dc, 0x1dc86a24)
   ntkrpamp = NT kernel, PAE, multiprocessor -> 32-bit PAE Win7. Consistent.
5. `windows.info` fails:
   "Unsatisfied requirement plugins.Info.kernel.layer_name"
   "Unsatisfied requirement plugins.Info.kernel.symbol_table_name"
6. Downloaded symbol pack (801 MB) to
   ~/.local/lib/python3.13/site-packages/volatility3/symbols/windows.zip
   -> `unzip -l` CONFIRMS windows/ntkrpamp.pdb/5B308B4ED6464159B87117C711E7340C-2.json.xz exists.
   So symbols are NOT the issue. The Intel translation layer fails to build
   (DTB / self-referential PDE not found by automagic) -> symbol table has no
   layer to bind to, hence BOTH requirements report unsatisfied.
   => registry plugins (printkey on ControlSet001\Control\ComputerName\ComputerName)
      are unavailable. Not worth fighting; the answer doesn't need translation.
7. Pivot to raw carving. KEY POINT: Windows is UTF-16LE internally, so use
   `strings -a -el` (plain strings misses most of it).
   `strings -a -el ch2.dmp | grep -i "COMPUTERNAME="` ->
     COMPUTERNAME=WI
     COMPUTERNAME=WIN-ETSA9
     COMPUTERNAME=WIN-ETSA91RKC
     COMPUTERNAME=WIN-ETSA91RKCFP     <- full
   (short ones = partially overwritten copies in freed pages)
8. Corroboration — `strings -a -el ch2.dmp | grep -i "WIN-ETSA"`:
   - PEB env:      COMPUTERNAME=WIN-ETSA91RKCFP, SERVER=\\WIN-ETSA91RKCFP, DOMAIN=WIN-ETSA91RKCFP
   - Event log:    <Computer>WIN-ETSA91RKCFP</Computer>
   - NetBIOS/SMB:  \Device\NetbiosSmbWIN-ETSA91RKCFPWORKGROUP
   - NetBT/TCPIP:  \Device\NetBT_Tcpip_{A13A8FB8-FEBF-4DCB-AA4B-C2115B299A5C}WIN-ETSA91RKCFPWORKGROUP
   - RPC:          calrpc:WIN-ETSA91RKCFP[LSMApi], [plugplay], [OLE....]
   - WMI:          \\WIN-ETSA91RKCFP\ROOT\CIMV2:__Win32Provider
   - Printer:      \WIN-ETSA91RKCFP\HP LaserJet 1018#:6,LocalOnly,DrvConvert
9. Counts: ascii 393 hits / utf16 1754 hits (~4.5x more with -el).
10. Sanity: len("WIN-ETSA91RKCFP") == 15 == NetBIOS limit, and matches the
    Windows auto-generated pattern "WIN-" + 11 alnum => not truncated, never renamed.

## Key insight
Don't need Volatility to reconstruct virtual memory for this. The hostname is
replicated across PEB env blocks, event log records, RPC endpoint names and
NetBIOS bindings — plain-text (UTF-16LE) in the physical image. `strings -el`
plus cross-structure corroboration is sufficient and more robust.

## Bonus / context for the C&C series
- User: John Doe  (C:\Users\John Doe\)
- Workgroup: WORKGROUP (not domain-joined)
- AV/printer log: <COPIER on S-CI-PRT06#:7> <WIN-ETSA91RKCFP\John Doe> <0> <0>) = rejected
                  1/12/2013  12:25:11 PM  00000410:   OS Windows 7 Workstation
- LibreOffice 3 installed; activity around 12.01.2013; dump dated 2013-01-29.

## Flag
WIN-ETSA91RKCFP
