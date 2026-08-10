# RAM Analysis - Windows - Password (Root-Me Pro, Forensic, Easy, 200pts)

## Target
- memory.zip -> memory.raw (5 GiB)
- SHA-256 memory.raw = 2c7de754879f6a13bd27b050d3e32c7f091c91eac42283dd5f980a080358cfcd  ✅ verified

## Recon
- `vol -f memory.raw windows.info`
  - Windows 10 x64 (NtMajor 10 / Minor 0), SystemTime 2025-12-29
- `vol -f memory.raw windows.hashdump`
  ```
  Administrateur      500  ...31d6cfe0d16ae931b73c59d7e0c089c0  (empty)
  Invité              501  ...31d6...                            (empty)
  DefaultAccount      503  ...31d6...                            (empty)
  WDAGUtilityAccount  504  ...cf54a761f756dc78a7f06a9ea6c79913  (system acct)
  Martin              1001 ...da2b7d3d1b7ed432a39afc74989ff56c   <-- target
  ```

## Crack
- Target NT hash: da2b7d3d1b7ed432a39afc74989ff56c (user Martin)
- hashcat had no OpenCL platform on this VM -> used john CPU
- `john --format=nt --wordlist=rockyou.txt martin.hash`
- Cracked instantly: **Shadow**
- Verified: NTLM("Shadow") = da2b7d3d1b7ed432a39afc74989ff56c ✅

## Flag
Shadow
