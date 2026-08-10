# Linux Privesc - Crontab

**Platform**: Root-Me Pro
**Category**: System / Privilege Escalation
**Difficulty**: Easy
**Points**: 200

## Challenge
> A system administrator has set up a cron job to run a backup script regularly. Find a way
> to exploit this configuration to gain root access. The flag is located in `/root/flag.txt`.

Access: `ssh -p 32165 user@sockets.challenges.root-me.pro` (password: `password`)

## Approach
1. Logged in as low-privileged `user` (uid=1000, groups=user).
2. Checked `/etc/crontab` for scheduled jobs — found a root-owned job running every minute:
   ```
   * * * * * root /opt/scripts/backup.sh
   ```
3. Inspected `/opt/scripts/backup.sh` permissions:
   ```
   drwxrwxr-x 2 root user  /opt/scripts
   -rwxrwxr-x 1 root user  /opt/scripts/backup.sh
   ```

## Vulnerability
The script executed by root's crontab is group-writable, and the group (`user`) is our own
primary group. This means any local unprivileged member of `user` can rewrite the contents
of a script that root executes automatically once a minute — a direct path from arbitrary
file write to arbitrary code execution as root.

## Solution
1. Backed up the original script.
2. Appended a payload to `backup.sh` that copies `/root/flag.txt` to a world-readable path
   and (for a persistent root shell) drops a SUID-root copy of bash:
   ```bash
   cp /root/flag.txt /tmp/.flag_out 2>/dev/null; chmod 644 /tmp/.flag_out 2>/dev/null
   cp /bin/bash /tmp/.rootbash 2>/dev/null; chmod 4755 /tmp/.rootbash 2>/dev/null
   ```
3. Removed the script's pre-existing `exit 0` line, which otherwise would have short-circuited
   execution before reaching the appended payload.
4. Waited for the next cron tick (within 60 seconds).
5. Root's cron executed the modified script; retrieved the flag from `/tmp/.flag_out`.
6. Restored the original script content afterward.

## Flag
```
RM{8406f97b8ff4434d7cea6480a2d36353}
```

## Lesson
Never grant write access (directly or via group membership) to a script — or its containing
directory — that a higher-privileged scheduled task will execute. This is a textbook
"writable cron job" privesc: enumerate `/etc/crontab`, `/etc/cron.d/*`, and any scripts they
invoke, then check `ls -la` on each for group/world write bits against a group you belong to.
GTFOBins-style thinking applies even without a listed binary — if you can write what root
runs, you *are* root within one cron interval.

Also worth noting: after modifying a script for exploitation, read the whole file for
early `exit`/`return` statements that could prevent your appended payload from running.
