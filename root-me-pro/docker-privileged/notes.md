# Docker - Privileged (Root-Me PRO, System, Easy, 200pts)

Subtitle: `--give-me-privileges`
Vuln tag: Docker - Container Escape

## Access
ssh -p 32231 root@sockets.challenges.root-me.pro
Password: bOJEL#KPya5^e6NE$BDY@Znw1
(Public endpoint — no VPN required)

## Plan
1. Confirm privileged: capsh --print / CapEff / ls /dev
2. Mount host disk (fdisk -l -> mount /dev/sdX /mnt/host)
3. Fallback: cgroup v1 release_agent escape
4. Fallback: /proc/sys/kernel/core_pattern

Flag format: RM{...}

## Log
