#!/usr/bin/env bash
# Re-download the original challenge archive and rebuild the memory dump.
# The artifacts are git-ignored: ch2.tbz2 is 185 MB and ch2.dmp is 512 MB,
# both over GitHub's 100 MB per-file limit.
set -e
cd "$(dirname "$0")"

URL="https://static.root-me.org/forensic/ch2/ch2.tbz2"
EXPECTED="e3a902d4d44e0f7bd9cb29865e0a15de"   # md5 of ch2.dmp, per the statement

[ -f ch2.tbz2 ] || curl -# -o ch2.tbz2 "$URL"
tar -xjf ch2.tbz2                                # ch2.tbz2 -> ch2.dmp

ACTUAL=$(md5sum ch2.dmp | cut -d' ' -f1)
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "md5 MISMATCH: got $ACTUAL, expected $EXPECTED" >&2
    exit 1
fi
echo "Rebuilt: ch2.dmp (md5 $ACTUAL, verified)"
