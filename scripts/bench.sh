#!/bin/sh

set -e

./tools/fam --bench --net --hostfwd=udp::47653-:47653 `cat scripts/files.txt` --disk=./tmp/disk.img
