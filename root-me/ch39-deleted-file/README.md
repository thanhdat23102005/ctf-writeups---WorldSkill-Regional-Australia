# Root-Me — Deleted file (ch39)

Forensic challenge writeup. A "USB drive" image with a deleted PNG whose owner
must be identified.

**Flag:** `javier_turcot`

## Contents
- [`writeup.md`](writeup.md) — full walkthrough (approach → recovery → flag → lesson)
- [`notes.md`](notes.md) — raw working notes
- `files/`
  - `ch39.gz` — original challenge download
  - `ANONYME_recovered.png` — the recovered deleted file
  - `regenerate.sh` — rebuilds `ch39` (tar) and `usb.image` from `ch39.gz`
  - `ch39`, `usb.image` — large derived artifacts, git-ignored (run `regenerate.sh`)

## TL;DR
`ch39.gz` → tar → FAT16 `usb.image`. Root dir has a deleted entry `ANONYME.PNG`
(first byte `0xE5`). Carve it from its start cluster → valid PNG whose XMP
metadata holds `<dc:creator>Javier Turcot</dc:creator>`.
