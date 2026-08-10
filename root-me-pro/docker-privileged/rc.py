#!/usr/bin/env python3
"""Run a command on the challenge container over SSH, retrying the flaky banner reset."""
import sys, time, paramiko

HOST, PORT = "sockets.challenges.root-me.pro", 32231
USER, PASS = "root", "bOJEL#KPya5^e6NE$BDY@Znw1"

cmd = sys.stdin.read() if len(sys.argv) < 2 else " ".join(sys.argv[1:])

last = None
for attempt in range(15):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST, port=PORT, username=USER, password=PASS,
                  look_for_keys=False, allow_agent=False, timeout=20,
                  banner_timeout=20, auth_timeout=20)
    except Exception as ex:                 # banner reset / transient refusal
        last = ex
        c.close()
        time.sleep(4)
        continue
    _, out, err = c.exec_command(cmd, timeout=180)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    print(o, end="")
    if e.strip():
        print("--- STDERR ---\n" + e, end="")
    c.close()
    sys.exit(0)

print(f"[!] failed after 15 attempts: {last}", file=sys.stderr)
sys.exit(1)
