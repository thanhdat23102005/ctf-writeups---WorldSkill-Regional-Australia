#!/usr/bin/env python3
import sys, paramiko

HOST = "sockets.challenges.root-me.pro"
PORT = 32165
USER = "user"
PASS = "password"

def run(cmd, timeout=20):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=timeout, allow_agent=False, look_for_keys=False)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    code = stdout.channel.recv_exit_status()
    client.close()
    return code, out, err

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    code, out, err = run(cmd)
    print(out, end="")
    if err:
        print(err, file=sys.stderr, end="")
    sys.exit(code)
