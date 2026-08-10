#!/usr/bin/env python3
import sys, paramiko

HOST, PORT, USER, PW = "sockets.challenges.root-me.pro", 32137, "user", "password"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, port=PORT, username=USER, password=PW, look_for_keys=False, allow_agent=False)

def run(cmd, timeout=30):
    print(f"\n$ {cmd}")
    _, out, err = c.exec_command(cmd, timeout=timeout, get_pty=True)
    o = out.read().decode(errors="replace"); e = err.read().decode(errors="replace")
    print(o.strip())
    if e.strip(): print("[stderr]", e.strip())
    return o + e

for cmd in sys.argv[1:] or ["id", "hostname", "sudo --version | head -1", "sudo -l"]:
    run(cmd)
c.close()
