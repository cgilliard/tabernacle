#!/bin/sh

set -e

./tools/fam --test `cat scripts/files.txt`
