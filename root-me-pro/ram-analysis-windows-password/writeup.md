# RAM Analysis - Windows - Password

- **Platform / Category:** Root-Me Pro — Forensic (Windows authentication)
- **Difficulty / Points:** Easy — 200
- **Flag:** `Shadow`

## Challenge
We're given `memory.zip` containing a 5 GiB Windows RAM dump (`memory.raw`,
SHA-256 `2c7de754...358cfcd`). The brief says the user was exposed in a public
data breach and may have reused a leaked password. Goal: recover the user's
password.

## Approach
1. Verified the download: `sha256sum memory.raw` matched the provided digest.
2. Profiled the image with Volatility 3: `windows.info` → Windows 10 x64.
   (Vol3 auto-downloaded matching `ntkrnlmp.pdb` symbols from Microsoft; cached
   afterwards so later plugins run fast.)
3. Dumped the on-disk credentials from the SAM/SYSTEM hives held in memory:
   `windows.hashdump`. Every built-in account had the empty-password NT hash
   (`31d6...`) except user **Martin** (RID 1001) with NT hash
   `da2b7d3d1b7ed432a39afc74989ff56c`.
4. Cracked Martin's NTLM against `rockyou.txt`.

## Vulnerability
Not a software bug — a credential-hygiene failure. The account password was a
weak, dictionary word (and, per the brief, one that appears in public breach
corpora). NTLM stores no salt, so any wordlist hit cracks instantly.

## Solution
```bash
# 1. Verify
sha256sum memory.raw
# 2. OS profile
vol -f memory.raw windows.info
# 3. Dump hashes
vol -f memory.raw windows.hashdump
#   Martin  1001  ...:da2b7d3d1b7ed432a39afc74989ff56c:::
# 4. Crack (hashcat had no OpenCL on this VM, so john on CPU — NTLM is trivial)
echo da2b7d3d1b7ed432a39afc74989ff56c > martin.hash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt martin.hash
john --format=nt --show martin.hash      # -> Shadow
```
Verification: `NTLM("Shadow") = da2b7d3d1b7ed432a39afc74989ff56c`.

## Flag
```
Shadow
```

## Lesson
- `windows.hashdump` in Vol3 reconstructs the SAM by combining the SAM and
  SYSTEM hives (bootkey) straight from RAM — no need to carve the hives out.
- The empty-password NT hash is `31d6cfe0d16ae931b73c59d7e0c089c0`; recognising
  it lets you skip cracking the default/disabled accounts and go straight to the
  real user (the RID ≥ 1000 account).
- NTLM is unsalted MD4 → mode `1000` in hashcat, `--format=nt` in john. When no
  GPU/OpenCL is available, NTLM still cracks a full rockyou pass in seconds on CPU.
