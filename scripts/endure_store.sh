#!/bin/sh
# endure_store.sh — endurance harness for the COW store layer, OUTSIDE the Test
# framework. Runs the bench program repeatedly against ONE PERSISTENT disk image:
# round 0 genesis-inits, every later round boots the prior round's committed state,
# verifies every page + the Σcounters==total invariant, then adds more. This
# exercises real cross-PROCESS durability (actual restart) over a long run.
#
#   scripts/endure_store.sh [rounds]      (default 200)
#
# Robustness: builds to its OWN binary path (so a concurrent bench_store.sh / build
# can't truncate the file mid-round) and classifies failures so a tooling hiccup is
# never mistaken for a data-integrity bug:
#   exit 1 = DATA INTEGRITY failure (real store bug)
#   exit 2 = harness/tooling error (bad binary, qemu didn't produce a verdict)
set -e
cd "$(dirname "$0")/.."
ROUNDS=${1:-200}
BIN=bin/bench_endure.bin                # distinct from bench_store.bin: no shared-path race

echo "building store bench -> $BIN ..." >&2
./tools/fam src/fence.fam src/disk.fam src/node_disk_store.fam \
            tests/node_disk_store_bench.fam -o "$BIN"
[ "$(head -c4 "$BIN" | xxd -p)" = "13000000" ] || { echo "compile failed (?)"; exit 1; }

DISK=$(mktemp)
dd if=/dev/zero of="$DISK" bs=512 count=70000 2>/dev/null   # persistent across all rounds (~34 MiB; M=65536 pages need ~65.5k sectors)
echo "endurance: $ROUNDS rounds  bin=$BIN  disk=$DISK" >&2

i=0
while [ "$i" -lt "$ROUNDS" ]; do
	# guard: if our binary lost its magic, that's a tooling/race issue, not a store bug
	if [ "$(head -c4 "$BIN" 2>/dev/null | xxd -p)" != "13000000" ]; then
		echo "round $i HARNESS ERROR: $BIN bad magic (concurrent build / disk?) — NOT a store failure"
		rm -f "$DISK"; exit 2
	fi
	out=$(timeout 300 ./tools/q32 --disk="$DISK" "$BIN" </dev/null 2>&1) || true
	if echo "$out" | grep -q "BENCH FAIL"; then
		echo "round $i DATA INTEGRITY FAILURE:"; echo "$out"; rm -f "$DISK"; exit 1
	fi
	if ! echo "$out" | grep -q "BENCH PASS"; then
		echo "round $i HARNESS/RUN ERROR (no verdict from qemu):"; echo "$out"; rm -f "$DISK"; exit 2
	fi
	total=$(echo "$out" | sed -n 's/.*BENCH PASS total=\([0-9]*\).*/\1/p')
	echo "round $i ok (total=$total)"
	i=$((i + 1))
done
rm -f "$DISK"
echo "endurance: $ROUNDS rounds PASS"
