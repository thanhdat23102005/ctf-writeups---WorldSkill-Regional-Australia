# SOC - The crisis (Root-Me Pro, SOC/Hard, 650pts)

## Files
- `files/Crisis-Network-Scheme.jpg` (viewed inline, not saved locally — re-download if needed)
- `files/soc-the-crisis-capture.pcap` (copied from upload)

## Network scheme (from diagram)
- FW1 (edge): eth0 200.98.X.Y (internet) / eth1 172.16.201.254 → VLAN DMZ
- VLANs (bars): DMZ 172.16.201.0/24, Users 192.168.99.0/24, Servers 192.168.100.0/24, Admin 192.168.10.0/24, Bastion 172.16.200.0/24
- FW2 (core, 5 legs): eth0 172.16.201.1 (DMZ), eth1 192.168.99.1 (Users), eth2 192.168.100.1 (Servers), eth3 192.168.10.1 (Admin), eth4 172.16.200.1 (Bastion)
- FW3 (2 legs): eth0 172.16.200.254 (Bastion), eth1 192.168.98.254 → VLAN Backups 192.168.98.0/24

## Step 1 — routers between Admin VLAN and Backups VLAN
Admin (192.168.10.0/24) only attaches to FW2. Backups (192.168.98.0/24) only attaches to FW3.
Path: Admin host → FW2 (gateway 192.168.10.1) → Bastion VLAN (172.16.200.0/24) → FW3 (172.16.200.254) → Backups host.
FW1 not involved (no internet/DMZ hop needed for internal Admin↔Backups traffic).

**Answer: 2** (FW2 + FW3)

## Step 2 — capture origin (ip:interface)
- Classic pcap (magic d4c3b2a1), no pcapng interface metadata — must deduce from traffic.
- Only 2 MACs in whole file: a2:3f:ef:24:5d:83 = 172.16.200.1 (FW2 Bastion leg, eth4), 52:54:00:91:dd:6b = 172.16.200.2.
- 100% of IP packets involve 172.16.200.2 as src or dst (checked via `ip and not ip.addr==172.16.200.2` -> 0 results). Classic signature of capturing on that host's own single NIC.
- 172.16.200.2 = Debian 12 (SSH banner OpenSSH_9.2p1 Debian-2+deb12u7), qemu-ga process in ps.txt confirms QEMU/KVM VM (MAC OUI 52:54:00 matches).
- It's the FTP server (banner "ROOTMEPRO.local File Transfert service.") being credential-sprayed from 192.168.99.5/.4, plus a backdoor listener on tcp/1234 and files being pulled via FTP (backup.zip, business.pptx, notes.png, secret.key, tgonzales.kdbx, ps.txt, ss.txt) — the compromised bastion host, natural place for IR to tcpdump.
- Single NIC + diagram convention (all routers eth0-eth4) => eth0.

First guess 172.16.200.2:eth0 -> WRONG (rejected by platform).
Revised: the diagram from Step 1 explicitly labels 172.16.200.1 as FW2's eth4 (Bastion leg). All captured traffic is the Bastion-side conversation between 172.16.200.1 (FW2 eth4) and 172.16.200.2, which by definition transits FW2's eth4 — use the labeled interface from the diagram instead of guessing an ifname on the unlabeled host.

**Answer (revised): 172.16.200.1:eth4**

## Artifacts pulled from pcap (ftp-data export objects, for later steps)
files/extracted/: backup.zip, business.pptx, notes.png, ps.txt, secret.key, ss.txt, tgonzales.kdbx (KeePass DB!)
- ss.txt snapshot only shows port 22 listening (no FTP/backdoor) — likely taken at different time / decoy, doesn't show current listeners.
- ps.txt: normal Debian boot process list, webadm user, nothing unusual, no tcpdump proc visible.
- secret.key: 128 bytes raw binary — possibly AES key for something later.
- tgonzales.kdbx: KeePass DB, will need password/keyfile to open — candidate for later step.

## Step 3 — machine already controlled by attacker before attacking the server
My first guess (192.168.99.4, quiet immediate valid FTP login at t=0) was WRONG.
**Confirmed answer: 192.168.99.5**
Note for later: .5 is the attacker's pre-existing foothold (does the ping sweep, full port scan at t=91.687, FTP credential spray, and repeated connections to the tcp/1234 backdoor). .4's quiet valid FTP login at t=0 with temp/temp is something else (legit/admin account or separate actor) — don't conflate "logs in immediately with working creds" with "attacker-controlled pivot"; go with who actively scans/attacks.

## Step 4 — compromised FTP user + first unauthorized auth time
Attacker 192.168.99.5 sprayed usernames (root, admin, test, guest, amanda, andrew, samantha, summer, sweety, spongebob, joseph, junior, ...) with matching user=pass guesses against 172.16.200.2:21.
Frame 18732/18735/18736: USER temp / PASS temp / 230 Login successful — first success (port 46582).
frame.time_epoch = 1759698208.825102 -> UTC = 2025-10-05T21:03:28.825102Z
(local capture display was -0400/EDT: 2025-10-05T17:03:28.825 -0400, matches)
Note: "temp" is the SAME account 192.168.99.4 used legitimately at t=0 — attacker guessed/cracked it via credential spray.
A second successful login also occurs later (frame ~18945, port 59618, 17:04:06.456 -0400) — not needed for this step (first only).

**Answer: user=temp, @timestamp=2025-10-05T21:03:28.825Z**

## Step 5 — leaked secret value
FTP RETR (files actually stolen, downloaded FROM server) by both 192.168.99.4 and .5 after temp/temp auth:
  tgonzales.kdbx, secret.key, notes.png  <- real/identical content both times (md5 matched)
STOR (uploaded TO server, decoys/junk, not stolen): business.pptx ("just noise :)"), backup.zip (3 "nope" files), ss.txt
notes.png is a decoy too — literally ASCII text "muahahaha..." repeated, not a real PNG (canary/troll file).
secret.key (128 bytes) = KeePass KEYFILE for tgonzales.kdbx (not password). Opened with pykeepass:
  PyKeePass('tgonzales.kdbx', keyfile='secret.key')  -- no password needed, opened clean.
Entry "Secret" / username "Congrats :)" / password = the flag.
Also captured other creds/emails in the DB (tgonzales / Tg0nz4lesRMP_2025, hhenry, thierry.gonzales@google.local, etc.) — keep in back pocket in case later steps need FTP/SSH creds beyond temp.

**Answer: RM{fb153a2651309aa84d0555847ed5304d}**

## Step 6 — exfiltrated file + secret
FTP DELE commands found (192.168.99.4 doing cleanup after both sides downloaded kdbx/secret.key/notes.png: `DELE *`, `DELE notes.png`, `DELE secret.key`, `DELE tgonzales.kdbx`) — not the answer, just evidence of anti-forensics.
Port 1234 traffic = REAL encrypted OpenSSH (SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u6/u7, full KEX negotiation) — this is where "attacker executed commands" (using creds cracked from kdbx, e.g. hhenry's "Shares" entry pass 32Mac9U4u43D7ss6RX). Cannot decrypt without keys — not the exfil channel we needed to crack.
DNS traffic (1676 frames, huge volume) was the giveaway: 829 queries from 172.16.200.2 -> 8.8.8.8 for names like:
  <hexindex>.<63-hex-char-chunk>.kj7pxkfjarosgjnoasxiqb07uy0pohc6.oastify.com
(oastify.com = Interactsh/Burp Collaborator-style catch-all domain -> DNS exfil beacon).
Indices run 0x0 to 0x33c (829 total, none missing count-wise), each label carrying a 63-hex-char slice of a file (label max = 63 octets, deliberately maxed out).
Concatenating chunks 0..0x33b (828 * 63 = 52164 hex chars, even) + reconstructed final chunk gives the full file.
Final captured chunk (0x33c) was truncated at 63 chars; its tail overlapped 27 hex chars with the start of the given "lost" hex (5c1e6f41c3c148aa966c52c2fc1...) -> true last chunk = captured[:-27] + given (100 hex chars).
Result: 26132 bytes, magic `52 49 46 46 0c 66 00 00 57 45 42 50` = RIFF/WEBP, VP8, 734x485 — RIFF size field (0x0000660c=26124, +8=26132) matches byte-for-byte, confirming correct reconstruction.
Rendered with PIL -> image of a man with a speech bubble "You found me... Congrats!" and red text "Secret: 5922b1381db80769".
Reconstruction script + image saved: files/extracted/exfil_dns.webp, files/extracted/exfil_dns.png

**Answer: 5922b1381db80769** (submitted plain; format shown in-image had no RM{} wrapper, unlike step 5's flag)

## Next
- Step 7+ TBD.
