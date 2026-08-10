# Encryption - Symmetric - BF (Root-Me Pro)

## Challenge
"All about brute force" — encrypted file secret.txt.gpg, find password to decrypt, get flag.

## Recon
- Downloaded secret.txt.gpg (184 bytes)
- `file`: GPG symmetrically encrypted data (AES256 cipher)
- Extracted john-crackable hash with `gpg2john`:
  - s2k-count (cost1) = 65011712 (high iteration count, S2K, so cracking will be slower than usual)
  - hash algo = SHA1 (cost2=2)
  - cipher = AES256 (cost3=9)

## Approach
- Title explicitly says "brute force" -> proceeding directly to wordlist attack per CLAUDE.md brute-force policy exception (challenge obviously calls for it).
- `gpg2john secret.txt.gpg > secret.hash`
- Note: /usr/share/wordlists/rockyou.txt was NOT pre-extracted (only .gz present), and passwordless sudo did NOT work in this env despite CLAUDE.md claim. Worked around by gunzip -c (file is world-readable) into local files/rockyou.txt.
- `john --wordlist=rockyou.txt secret.hash` (running in background, high s2k-count makes this slow)

## Status — SOLVED
- Passphrase: `panicatthedisco` (found after 5:53 at ~33 c/s, ~11k candidates deep in rockyou)
- Decrypt: `echo -n panicatthedisco | gpg --batch --passphrase-fd 0 -d secret.txt.gpg`
- Flag: `RM{98efdafb3f6e1a8f0d752f2164410942}`
