# RAM Analysis - Windows - Files (Root-Me Pro, Forensic, 400pts)

## Setup
- Downloaded memory.zip -> unzipped to memory.raw
- Verified SHA-256: 2c7de754879f6a13bd27b050d3e32c7f091c91eac42283dd5f980a080358cfcd -- MATCH
- vol -f memory.raw windows.info -> Windows 10/11 build 22000, x64, KeNumberProcessors 2

## Enumeration
- windows.pslist -> notable processes:
  - PID 392  KeePass.exe   "C:\Program Files\KeePass Password Safe 2\KeePass.exe" "C:\Users\Martin\Documents\Database.kdbx"
  - PID 7316 Defender.exe  "C:\Users\Martin\Downloads\Defender.exe"  (masquerading name, not real MS Defender - red herring, not needed for solve)
  - PID 968  firefox.exe (many content procs)
  - PID 6668 regedit.exe
  - PID 3176 DumpIt.exe (the capture tool itself)

- windows.filescan | grep -i kdbx -> FileObject for Database.kdbx at 0x800c0c4a66a0
- windows.filescan also showed: \Users\Martin\Documents\Not my secret.txt  (obvious troll name -> worth dumping)
- No logins.json cached for Firefox (only places/cookies/cert9/key4 db files present, not the actual creds -- not the intended path)

## Extraction
```
vol -f memory.raw -o dumped windows.dumpfiles --virtaddr 0x800c0c4a66a0   # Database.kdbx
vol -f memory.raw -o dumped windows.dumpfiles --virtaddr 0x800c0d470210   # Not my secret.txt
```
- Database.kdbx dumped as 4096 bytes -- looked truncated at first glance but turned out to be the complete file (small DB, default sample entries + 1 real one)
- Not my secret.txt dumped cleanly, contents:
  ```
  Baby-Cake8-Potatoes-Listen-Hunt-Feed
  ```
  (diceware-style passphrase -- the "not my secret" name is a troll; it IS the KeePass master password)

## Opening the vault
Installed pykeepass (`pip install --break-system-packages pykeepass`) since local keepass2john didn't support KDBX4 and keepassxc-cli wasn't installed (sudo apt blocked - no interactive sudo password available in this environment despite CLAUDE.md documenting passwordless sudo on the real VM).

```python
from pykeepass import PyKeePass
kp = PyKeePass('Database.kdbx', password='Baby-Cake8-Potatoes-Listen-Hunt-Feed')
for e in kp.entries:
    print(e.title, e.username, e.password, e.url, e.notes)
```

Entries:
- Sample Entry / Sample Entry #2 -> default KeePass demo entries
- **Root-Me** / Martin123 / `RM{da39a3ee5e6b4b0d3255bfef95601890afd80709}`

## Flag
`RM{da39a3ee5e6b4b0d3255bfef95601890afd80709}`
