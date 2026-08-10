#!/usr/bin/env bash
# Rebuild the derived artifacts from the original challenge download.
set -e
cd "$(dirname "$0")"
gunzip -kf ch39.gz          # ch39.gz -> ch39 (tar)
tar xf ch39                 # ch39    -> usb.image
echo "Rebuilt: ch39 (tar) and usb.image"
