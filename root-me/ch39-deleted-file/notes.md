# ch39 — Deleted file (Root-Me, Forensic)

## Challenge
- USB drive found in library; find the owner. Flag = owner identity, `firstname_lastname`.
- File: https://static.root-me.org/forensic/ch39/ch39.gz
- sha256: cd9f4ada5e2a97ec6def6555476524712760e3d8ee99c26ec2f11682a1194778 (verified OK)

## Steps
1. `gunzip` -> `ch39` = POSIX tar (GNU) -> `tar xf` -> `usb.image` (32 MB).
2. `file usb.image` -> DOS/MBR FAT16 filesystem, label "USB".
3. Sleuthkit/mount unavailable (RHEL box, no sudo pw, no pip). Parsed FAT16 by hand in Python.
4. FAT16 geometry: bps=512, spc=4, reserved=4, nFAT=2, sec/FAT=64, root entries=512.
   - root dir @ (4 + 2*64)*512 = 67584
   - data region @ 67584 + 512*32 = 83968  (cluster 2)
5. Root dir entries:
   - `USB` (volume label)
   - `åNONYME.PNG` — first byte 0xE5 = DELETED. Original name `ANONYME.PNG`
     (anonyme = anonymous, FR). start cluster 3, size 246064.
6. Carve: offset = 83968 + (3-2)*4*512 = 86016; read 246064 bytes.
   - Valid PNG (magic 89504E47..., ends with IEND). 400x300 RGB. File was contiguous, so no FAT chain needed.
7. Image = photo of trees/sky (no visible name). BUT XMP metadata:
   `<dc:creator><rdf:li>Javier Turcot</rdf:li></dc:creator>`

## Key insight
Filename "ANONYME" is a decoy — the real identity is hidden in the deleted PNG's XMP creator metadata.

## Flag
javier_turcot
