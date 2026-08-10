# RAM Analysis - Windows - Files

**Platform:** Root-Me Pro
**Category:** Forensic
**Difficulty:** Medium
**Points:** 400

## Challenge
A Windows 11 memory dump (`memory.raw`, 5GB) is provided. Prompt: "We are confident that the user stored their passwords securely. Will you be able to recover all their secrets?"

## Approach
1. Verified the provided SHA-256 against the downloaded/extracted `memory.raw` before analysis.
2. `vol -f memory.raw windows.info` to confirm OS/profile (Windows 10/11 build 22000, x64) and that Volatility 3's automatic symbol detection worked without manual profile setup.
3. `vol -f memory.raw windows.pslist` to enumerate running processes. Found `KeePass.exe` running with `C:\Users\Martin\Documents\Database.kdbx` open as a command-line argument — the obvious target given the "passwords stored securely" hint.
4. A decoy process `Defender.exe` running from `Downloads\` (masquerading as Windows Defender) was noted but turned out to be a red herring, not needed for the solve.
5. `vol -f memory.raw windows.filescan | grep -i kdbx` to get the in-memory FileObject offset for `Database.kdbx`, and swept the wider filescan output for anything else unusual in the user's folders — turned up `Documents\Not my secret.txt`, a deliberately baiting filename.
6. `vol -f memory.raw -o dumped windows.dumpfiles --virtaddr <offset>` to carve both `Database.kdbx` and `Not my secret.txt` out of the cached file pages in RAM.
7. `Not my secret.txt` contained a diceware-style passphrase: `Baby-Cake8-Potatoes-Listen-Hunt-Feed` — despite the filename claiming otherwise, this was in fact the KeePass master password.
8. Local `keepass2john` didn't support the KDBX4 format the file used, and `keepassxc-cli` wasn't installed (and `sudo apt install` needed an interactive password not available in this session) — installed `pykeepass` via `pip install --break-system-packages pykeepass` instead and opened the vault programmatically.
9. The vault opened cleanly with the recovered passphrase and contained one real entry ("Root-Me") alongside KeePass's two default sample entries.

## Vulnerability / Weakness
The user "secured" their KeePass master password by writing it in a plaintext file on disk (`Not my secret.txt`), rather than memorizing it or using a hardware/key-file second factor. Because the file was open/cached, it — along with the unlocked database — was fully recoverable from a RAM snapshot. Security theater: a strong diceware passphrase is worthless if it's stored next to the vault it protects.

## Solution
```bash
# Extract KeePass DB and hint file from memory
vol -f memory.raw windows.filescan > filescan.txt
grep -i kdbx filescan.txt        # -> 0x800c0c4a66a0
grep -i "not my secret" filescan.txt   # -> 0x800c0d470210

vol -f memory.raw -o dumped windows.dumpfiles --virtaddr 0x800c0c4a66a0
vol -f memory.raw -o dumped windows.dumpfiles --virtaddr 0x800c0d470210

cat "dumped/file.....Not my secret.txt.dat"
# -> Baby-Cake8-Potatoes-Listen-Hunt-Feed

pip install --break-system-packages pykeepass
python3 -c "
from pykeepass import PyKeePass
kp = PyKeePass('dumped/file.....Database.kdbx.dat', password='Baby-Cake8-Potatoes-Listen-Hunt-Feed')
for e in kp.entries:
    print(e.title, e.username, e.password)
"
```

## Flag
```
RM{da39a3ee5e6b4b0d3255bfef95601890afd80709}
```

## Lesson
When a memory forensics challenge stresses that a user "stored passwords securely," check for the password manager process itself (cmdline reveals the open DB path), then sweep `windows.filescan` broadly across the user's profile — not just for the vault file, but for oddly-named files nearby. Attackers (and challenge authors) love hiding secrets in files with ironic/misleading names ("Not my secret.txt" *is* the secret). `windows.dumpfiles --virtaddr <offset>` is the general technique for carving any cached file straight out of a memory image, not just credential stores — useful for recovering deleted/in-use documents, browser artifacts, or exfil staging files. Keep `pykeepass` (or `keepassxc-cli`) handy for parsing KDBX4, since older `john`/`keepass2john` builds may not support it.
