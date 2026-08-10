# CTF archive — Root-Me / Root-Me Pro

28 challenges. **19 with full writeups**, 8 notes-only, 1 work-in-progress.

Each folder holds `notes.md` (running log), `writeup.md` (final self-contained writeup),
and any `solve.py` / helper scripts. Where a challenge was solved across two sessions the
second is kept as `notes-session2.md` / `solve-session2.py`. Large artefacts (pcaps, memory
dumps, disk images) and platform session cookies are gitignored — see each writeup for how
to regenerate them.

## Root-Me Pro

| Challenge | Status | Category | Pts |
|---|---|---|---|
| [`analyse-pcap-iot-rtp-video-capture`](root-me-pro/analyse-pcap-iot-rtp-video-capture/) | 📝 notes only | Network | 500 |
| [`api-mass-assignment`](root-me-pro/api-mass-assignment/) | ✅ done | Web | 200 |
| [`ble-2fa-bypass`](root-me-pro/ble-2fa-bypass/) | ✅ done | Web | 450 |
| [`disk-analysis-windows-registers`](root-me-pro/disk-analysis-windows-registers/) | 🚧 WIP |  |  |
| [`docker-socket`](root-me-pro/docker-socket/) | ✅ done | Soc |  |
| [`encryption-known-plaintext2`](root-me-pro/encryption-known-plaintext2/) | ✅ done | cryption | 150 |
| [`encryption-symmetric-bf`](root-me-pro/encryption-symmetric-bf/) | ✅ done | cryption |  |
| [`linux-privesc-crontab`](root-me-pro/linux-privesc-crontab/) | ✅ done | Privesc |  |
| [`linux-privesc-module-hijacking`](root-me-pro/linux-privesc-module-hijacking/) | ✅ done | Privesc | 300 |
| [`protocol-smtp-analyze`](root-me-pro/protocol-smtp-analyze/) | 📝 notes only | Network | 200 |
| [`ram-analysis-linux-network`](root-me-pro/ram-analysis-linux-network/) | ✅ done | Network | 200 |
| [`ram-analysis-windows-files`](root-me-pro/ram-analysis-windows-files/) | ✅ done | Forensic |  |
| [`ram-analysis-windows-password`](root-me-pro/ram-analysis-windows-password/) | ✅ done | Forensic |  |
| [`soc-ad-dcsync-attack`](root-me-pro/soc-ad-dcsync-attack/) | ✅ done | SOC |  |
| [`soc-ad-kerberoasting`](root-me-pro/soc-ad-kerberoasting/) | ✅ done | SOC | 350 |
| [`soc-ad-ldap-enumeration`](root-me-pro/soc-ad-ldap-enumeration/) | 📝 notes only | SOC | 200 |
| [`soc-ad-smb-share-enumeration`](root-me-pro/soc-ad-smb-share-enumeration/) | ✅ done | SOC |  |
| [`soc-the-crisis`](root-me-pro/soc-the-crisis/) | 📝 notes only | SOC | 650 |
| [`soc-web-blind-sqli`](root-me-pro/soc-web-blind-sqli/) | ✅ done | SOC |  |
| [`soc-web-file-read`](root-me-pro/soc-web-file-read/) | 📝 notes only | SOC |  |
| [`soc-web-file-upload-config`](root-me-pro/soc-web-file-upload-config/) | 📝 notes only | SOC |  |
| [`soc-web-injection-sql`](root-me-pro/soc-web-injection-sql/) | 📝 notes only | SOC | 200 |
| [`sql-injection-error`](root-me-pro/sql-injection-error/) | ✅ done | Web | 400 |
| [`ssti-python-filter-bypass`](root-me-pro/ssti-python-filter-bypass/) | ✅ done | Web | 450 |
| [`ssti-python-introduction`](root-me-pro/ssti-python-introduction/) | ✅ done | Web | 300 |

## Root-Me

| Challenge | Status | Category | Pts |
|---|---|---|---|
| [`ch2-command-control-2`](root-me/ch2-command-control-2/) | ✅ done | Forensic |  |
| [`ch39-deleted-file`](root-me/ch39-deleted-file/) | ✅ done | Forensic |  |
| [`xss-reflected-uri`](root-me/xss-reflected-uri/) | 📝 notes only | Web | 450 |

---

**Private repo** — contains working flags and solutions for challenges that are still live.
Not to be published: Root-Me's rules prohibit public disclosure of solutions.
