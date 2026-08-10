# Root-Me — Encryption / Symmetric / BF ("All about brute force")

## Challenge
- Category: Cryptanalysis — Symmetric
- Description: An encrypted file `secret.txt.gpg`. Find the password to decrypt it and provide the flag inside.

## Approach
1. Downloaded the file, ran `file secret.txt.gpg` → `GPG symmetrically encrypted data (AES256 cipher)`.
2. Extracted the john-crackable hash:
   ```
   gpg2john secret.txt.gpg > secret.hash
   ```
   The hash header showed:
   - s2k-count = 65,011,712 (very high iteration count, so each candidate is expensive)
   - hash algo = SHA1
   - cipher = AES256
3. Challenge title explicitly calls for brute force — proceeded with wordlist attack against the (frequency-sorted) `rockyou.txt`:
   ```
   john --wordlist=rockyou.txt secret.hash
   ```
   Rate was only ~33 candidates/sec (S2K makes each candidate cost 65M SHA1 rounds), but rockyou is sorted by frequency so common passwords are tried first.
4. After ~5 min 53 s (~11,000 candidates), john cracked it:
   ```
   panicatthedisco  (?)
   ```
5. Decrypted the file:
   ```
   echo -n "panicatthedisco" | gpg --batch --yes --passphrase-fd 0 --decrypt secret.txt.gpg
   ```
   Output:
   ```
   Well done! You have successfully decrypted this file! Here is the flag: RM{98efdafb3f6e1a8f0d752f2164410942}
   ```

## Vulnerability
The file was symmetrically encrypted with a weak, human-memorable passphrase present in a common leaked-password list. GPG's high S2K iteration count slows brute force but does not stop it when the passphrase is a known weak password.

## Solution (one-liner recap)
```
gpg2john secret.txt.gpg > h
john --wordlist=/usr/share/wordlists/rockyou.txt h        # → panicatthedisco
echo -n panicatthedisco | gpg --batch --passphrase-fd 0 -d secret.txt.gpg
```

## Flag
```
RM{98efdafb3f6e1a8f0d752f2164410942}
```

## Lessons
- Symmetrically encrypted GPG files → `gpg2john` → `john --format=gpg`. There is no hashcat mode for GPG *symmetric* files (17010/17020 are for private keys).
- S2K iteration counts (often 65M+ by default in modern gpg) throttle crack rate to a few dozen/sec on CPU. GPU offers little benefit because the SHA1 chain is inherently serial.
- rockyou.txt is frequency-sorted — for slow hashes, always run against it directly rather than shuffling.
- Passphrases like band/song/movie names are common in leaked lists; a strong symmetric passphrase must be random, not memorable.
- On this Kali box, `/usr/share/wordlists/rockyou.txt.gz` is not pre-extracted; passwordless `sudo` didn't actually work in this shell env, so extracted with `gunzip -c` into the local challenge folder (the .gz is world-readable).
