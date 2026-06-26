#!/bin/sh
# bench_store.sh — one-shot load test of the COW store layer (node_disk_store.fam),
# standalone from the Test framework. Builds the bench program, runs it once against
# a FRESH zeroed disk (genesis -> init -> 10k increments under heavy eviction ->
# commit -> reboot+verify), and checks for "BENCH PASS".
set -e
cd "$(dirname "$0")/.."

echo "building store bench..." >&2
./tools/fam src/fence.fam src/disk.fam src/node_disk_store.fam \
            tests/node_disk_store_bench.fam -o bin/bench_store.bin
[ "$(head -c4 bin/bench_store.bin | xxd -p)" = "13000000" ] || { echo "compile failed (?)"; exit 1; }

DISK=$(mktemp)
dd if=/dev/zero of="$DISK" bs=512 count=70000 2>/dev/null   # fresh, zeroed (~34 MiB; M=65536 pages need ~65.5k sectors)
echo "running bench on fresh disk..." >&2
out=$(timeout 300 ./tools/q32 --disk="$DISK" bin/bench_store.bin </dev/null 2>&1) || true
echo "$out"
rm -f "$DISK"

echo "$out" | grep -q "BENCH PASS" || { echo "bench_store: FAIL"; exit 1; }
echo "bench_store: PASS"
