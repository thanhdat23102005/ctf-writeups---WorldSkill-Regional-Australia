# Encryption - Known Plaintext 2 (Root-Me Pro, Cryptanalysis, Easy, 150pts)

## Challenge
"Do you know me?" — a file encrypted with classical repeating-key XOR.
Hints: (1) classical XOR, (2) common file type, (3) key size should suit you.

## Approach
1. Estimated XOR key length via normalized Hamming distance between successive
   blocks. Distances dipped at every multiple of 5 → key length = 5
   ("key size should suit you" = 5 chars).
2. "Common file type" = known-plaintext magic bytes. Column frequency analysis
   (assume most-common byte per column = space 0x20) produced near-readable
   `%PDF-...`, `ReportLab`, `obj`/`endobj`.
3. Used crib `%PDF-1.` to recover the exact key.

## Vulnerability
Repeating-key XOR with a known/guessable plaintext (file magic header) fully
leaks the key.

## Solution
- Key length 5, key = `1c 27 98 51 2f`.
- `plain[i] = cipher[i] XOR key[i % 5]` → valid PDF 1.3 (ReportLab), but with an
  internal `/Encrypt` (empty-password PDF standard encryption), so strings/streams
  stayed garbled until the PDF layer was decrypted.
- `mutool draw -F txt decoded.pdf` rendered the page text.

## Flag
RM{4a8a5bd8453fbdfbe51aa480676df4bb}

## Lesson
- Multiples-of-N Hamming dip => key length N (base = smallest such N).
- Known-plaintext XOR: file magic is free plaintext. `%PDF-1.` for PDFs.
- ReportLab PDFs often carry empty-password standard encryption; use `mutool`
  (or pikepdf/qpdf with empty pw) rather than raw `strings`.
