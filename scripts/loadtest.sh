#!/bin/sh
# All-in-one BIN0 load test: build (if needed) -> write the image to disk ->
# disk-boot the node with UDP 3737 forwarded to the host -> wait until it serves
# -> run the concurrency ramp -> stop the node.  No external peers needed.
#
# Tunables (env):  PORT (3737)  LEVELS (1,2,4,8,16,32)  MODE (fetch|qps)
#                  DEADLINE (25, fetch)  DURATION (5, qps)  RUNTIME (300)
# Usage:  sh scripts/loadtest.sh            # bulk throughput
#         MODE=qps sh scripts/loadtest.sh   # request-rate QPS
set -e
PORT=${PORT:-3737}
LEVELS=${LEVELS:-1,2,4,8,16,32}
MODE=${MODE:-fetch}
DEADLINE=${DEADLINE:-25}
DURATION=${DURATION:-5}
RUNTIME=${RUNTIME:-300}
LOG=/tmp/loadtest_node.log

# Build the binaries if they're missing.
[ -f bin/tabernacle ] && [ -f bin/full_node.bin ] || sh scripts/build.sh

# Write full_node.bin into the disk image so the node DISK-BOOTS (no peers needed).
sh scripts/makenode.sh

# Launch the node in the background.  q32 exec's qemu, so $! is the qemu pid and the
# trap below (and `timeout`) reach it directly — no orphaned qemu.
printf '3737 0 10000\004' | timeout "$RUNTIME" ./tools/q32 bin/tabernacle \
	--disk=./data/disk.img --net --hostfwd=udp::${PORT}-:3737 >"$LOG" 2>&1 &
NODE=$!
trap 'kill "$NODE" 2>/dev/null; exit' INT TERM EXIT
echo "node launched (pid $NODE); waiting for it to serve..."

# Wait until the node answers (it takes a few seconds to disk-boot).
if ! python3 tools/bin0_probe.py 127.0.0.1 "$PORT" 4 90; then
	echo "FAIL: node never served. Last serial output:"; tail -8 "$LOG"; exit 1
fi

echo "--- ramp (mode=$MODE, LEVELS=$LEVELS) ---"
python3 tools/loadtest.py --host 127.0.0.1 --port "$PORT" --mode "$MODE" \
	--levels "$LEVELS" --deadline "$DEADLINE" --duration "$DURATION" --preflight 0
