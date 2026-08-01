# Root-Me — Deleted file (ch39, Forensic)

**Level:** Easy · **Flag format:** `firstname_lastname`

## Challenge
> Your cousin found a USB drive in the library. Find the owner of the stick.
> The flag is the owner's identity in the form `firstname_lastname`.

We're given `ch39.gz`.

## Approach

### 1. Unwrap the layers
```
gunzip ch39.gz            # -> ch39
file ch39                 # POSIX tar archive (GNU)
tar xf ch39               # -> usb.image  (32 MB)
file usb.image            # DOS/MBR FAT16 filesystem, label "USB"
```
So the "USB drive" is a raw **FAT16** disk image.

### 2. Find the deleted file
Normally you'd run `fls`/`icat` (Sleuth Kit). None of that (nor mount/sudo) was
available here, so we parse the FAT16 directory ourselves. FAT16 layout:

```
root dir  = (reserved + numFAT * secPerFAT) * bytesPerSec = (4 + 2*64)*512 = 67584
data area = root dir + rootEntries*32       = 67584 + 512*32          = 83968   (cluster 2)
```

Walking the 32-byte root directory entries gives:

| name          | attr | cluster | size   | state   |
|---------------|------|---------|--------|---------|
| `USB`         | 0x08 | –       | –      | volume label |
| `åNONYME.PNG` | 0x20 | 3       | 246064 | **DELETED** |

A directory entry whose first byte is `0xE5` (`å`) is a **deleted file** — FAT
doesn't wipe data, it just marks the slot free. The original name was
`ANONYME.PNG` ("anonyme" = *anonymous* — a deliberate taunt).

### 3. Recover (carve) the PNG
The file starts at cluster 3, and its data was still intact and contiguous, so
we read `size` bytes straight from the cluster offset:

```
offset = data_area + (cluster - 2) * secPerClus * bytesPerSec
       = 83968 + (3 - 2) * 4 * 512 = 86016
```

The carved bytes start with `89 50 4E 47 …` and end with `IEND` — a complete,
valid 400×300 PNG.

### 4. Identify the owner
The image itself is just a photo of trees and sky — no name. But the PNG carries
**XMP metadata**:

```xml
<dc:creator>
  <rdf:li>Javier Turcot</rdf:li>
</dc:creator>
```

The "anonymous" filename is a red herring; the author is embedded in metadata.

## Flag
```
javier_turcot
```

## Lesson
- **Deleted ≠ gone.** On FAT, deleting a file only flips the first name byte to
  `0xE5` and frees the clusters; the data survives until overwritten. Recovering
  it can be as simple as reading the original cluster range.
- **Check metadata, not just pixels.** EXIF/XMP creator/author fields routinely
  leak identities — the intended answer here lived entirely in `dc:creator`.
- **Standard tooling:** `fls -rd usb.image` then `icat usb.image <inode>` does the
  same recovery in two commands when Sleuth Kit is available.
