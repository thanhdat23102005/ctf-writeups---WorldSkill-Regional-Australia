#!/usr/bin/env python3
"""Run a batch of commands over ONE persistent SSH connection (banner resets
happen if we reconnect too fast, so keep one session alive and pipe commands
through a login shell)."""
import sys, time, paramiko

HOST, PORT = "sockets.challenges.root-me.pro", 32231
USER, PASS = "root", "bOJEL#KPya5^e6NE$BDY@Znw1"

script = sys.stdin.read()

for attempt in range(6):
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(HOST, port=PORT, username=USER, password=PASS,
                  look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=30)
        break
    except Exception as e:
        print(f"[retry {attempt}] {e}", file=sys.stderr)
        time.sleep(4)
else:
    sys.exit("could not connect")

_, out, err = c.exec_command(script, timeout=180)
o = out.read().decode(errors="replace")
e = err.read().decode(errors="replace")
print(o, end="")
if e.strip():
    print("--- STDERR ---\n" + e, end="")
c.close()
