# TODO

- [x] Turn ~/ctf into a git repo and push it (writeups/notes archive).
      Done 2026-08-10: repo consolidated into `root-me/` + `root-me-pro/`,
      pushed to github.com/thanhdat23102005/ctf-writeups (**private**).
      Large artefacts (`files/`, `dump/`, pcaps, dumps) and Root-Me Pro
      session cookies are gitignored.

## Writeups still owed (notes exist, no writeup.md yet)

- [ ] root-me-pro/analyse-pcap-iot-rtp-video-capture
- [ ] root-me-pro/soc-ad-ldap-enumeration
- [ ] root-me-pro/soc-the-crisis
- [ ] root-me-pro/soc-web-file-read
- [ ] root-me-pro/soc-web-file-upload-config
- [ ] root-me-pro/soc-web-injection-sql
- [ ] root-me-pro/sql-injection-error (has writeup; second session notes to fold in)
- [ ] root-me/protocol-smtp-analyze
- [ ] root-me/xss-reflected-uri (two sessions of notes, no writeup yet)

## In progress

- [ ] root-me-pro/ssti-python-filter-bypass — scripts only, no notes yet
- [x] root-me-pro/ssti-python-introduction — done
- [ ] root-me-pro/disk-analysis-windows-registers — files extracted, nothing written

## Housekeeping

- [ ] Revoke the PAT pasted into chat on 2026-08-10 and reissue a fresh one
      into ~/.config/ctf-writeups/token
- [ ] tools/push-to-repo.py has a gitignore bug: fnmatch patterns only match at
      the top level, so nested `files/` and `dump/` dirs are NOT excluded.
      Use plain `git push` instead, or fix the matcher.
