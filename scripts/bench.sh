#!/bin/sh

set -e

./tools/fam --bench `cat scripts/files.txt` --disk=./tmp/disk.img
