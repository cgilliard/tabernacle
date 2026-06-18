#!/bin/sh
set -e
IMG=./data/disk.img
dd if=/dev/zero of="$IMG" bs=1M count=64 2>/dev/null
dd if=bin/full_node.bin of="$IMG" conv=notrunc 2>/dev/null
echo "$IMG: $(stat -c %s bin/full_node.bin) bytes written"
