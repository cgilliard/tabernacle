#!/bin/sh

set -e

# --net + --hostfwd let net.fam's `burst` test round-trip real frames through
# slirp and back into the guest (high, generally-unused UDP port; keep in sync
# with mkhdr in src/net.fam).  Tests probe for their devices and self-skip, so
# this one line stays the whole suite.
./tools/fam --test --net --hostfwd=udp::47653-:47653 `cat scripts/files.txt`
