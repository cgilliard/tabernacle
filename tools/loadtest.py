#!/usr/bin/env python3
"""BIN0 concurrency/saturation load test for the full_node chunk server.

Spawns N concurrent fetchers (ramped over a list of N), each performing a full
reliable download of the binary over the BIN0/UDP protocol, and reports per-N
completion time, aggregate goodput, and packet loss so you can find the knee
where the server (or, through --hostfwd, slirp) saturates.

Protocol:
  REQ_RANGE  "BIN0" 0x02 start(BE16) end(BE16) [bitmap(8)]
  RSP_CHUNK  "BIN0" 0x82 seq(BE16)  data(<=1400)
A plain 9-byte REQ_RANGE makes the server send the whole [start,end] range.  A
17-byte REQ_RANGE carrying an 8-byte bitmap re-requests only the missing chunks
of a <=64-chunk window (bitmap bit set = "I already have this", server skips it).

CAVEATS (printed in the report too):
  * Through QEMU --hostfwd, all clients share ONE source IP (slirp NAT = 10.0.2.2),
    so they are not fully independent peers; the server keys its dedup on source
    IP + start-chunk, so same-IP same-window bursts can be merged/dropped.  Numbers
    are slirp-bounded end-to-end, not the server's intrinsic ceiling.
  * Fetchers randomize window order to reduce same-start dedup collisions.

Usage:
  loadtest.py [--host H] [--port P] [--nchunks K] [--chunk-bytes B]
              [--levels 1,2,4,8,16] [--deadline S] [--win 64]
nchunks defaults to ceil(size(bin/full_node.bin)/chunk-bytes).
"""
import argparse, math, os, random, socket, struct, sys, time
from concurrent.futures import ThreadPoolExecutor

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=3737)
    p.add_argument("--nchunks", type=int, default=0)
    p.add_argument("--chunk-bytes", type=int, default=1400)
    p.add_argument("--levels", default="1,2,4,8,16")
    p.add_argument("--deadline", type=float, default=20.0, help="per-fetcher seconds")
    p.add_argument("--win", type=int, default=64)
    p.add_argument("--bin", default="bin/full_node.bin")
    p.add_argument("--preflight", type=float, default=5.0,
                   help="seconds to wait for the server before the ramp (0 = skip)")
    p.add_argument("--mode", choices=["fetch", "qps"], default="fetch",
                   help="fetch = bulk download throughput; qps = single-chunk request rate")
    p.add_argument("--duration", type=float, default=5.0,
                   help="qps mode: seconds of load per level")
    p.add_argument("--rtimeout", type=float, default=0.5,
                   help="qps mode: per-request reply timeout (s); a miss counts as a drop")
    return p.parse_args()

def req_plain(start, end):
    return b"BIN0" + bytes([0x02]) + struct.pack(">HH", start, end)

def req_bitmap(start, end, have, win):
    # 8-byte bitmap over chunks [start, start+63]: bit set = client HAS it (skip).
    bm = bytearray(8)
    for c in have:
        d = c - start
        if 0 <= d < 64:
            bm[d >> 3] |= 1 << (d & 7)
    return b"BIN0" + bytes([0x02]) + struct.pack(">HH", start, end) + bytes(bm)

def preflight(host, port, timeout):
    """Return True if the server answers a REQ_RANGE within `timeout` seconds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s.sendto(req_plain(0, 0), (host, port))
            data, _ = s.recvfrom(2048)
            if data[:4] == b"BIN0" and len(data) >= 5 and data[4] == 0x82:
                s.close(); return True
        except (socket.timeout, OSError):
            pass
    s.close(); return False

def fetch_one(host, port, nchunks, deadline, win):
    """One full reliable download. Returns dict of stats."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    have = set()
    sent = recv = 0
    rounds = 0
    t0 = time.time()
    end_all = nchunks - 1
    # round 0: plain full-range burst
    s.sendto(req_plain(0, end_all), (host, port)); sent += 1
    while len(have) < nchunks and time.time() - t0 < deadline:
        drained = False
        try:
            while True:
                data, _ = s.recvfrom(2048)
                recv += 1
                if len(data) >= 7 and data[:4] == b"BIN0" and data[4] == 0x82:
                    have.add(struct.unpack(">H", data[5:7])[0])
                drained = True
        except socket.timeout:
            pass
        if len(have) >= nchunks:
            break
        # nothing arriving -> re-request missing windows (bitmap = have)
        missing = [c for c in range(nchunks) if c not in have]
        windows = sorted({(c // win) * win for c in missing})
        random.shuffle(windows)
        rounds += 1
        for b in windows:
            e = min(b + win - 1, end_all)
            s.sendto(req_bitmap(b, e, have, win), (host, port)); sent += 1
        time.sleep(0.01)
    s.close()
    return {"t": time.time() - t0, "have": len(have), "n": nchunks,
            "sent": sent, "recv": recv, "rounds": rounds,
            "complete": len(have) >= nchunks}

def qps_worker(host, port, nchunks, duration, rtimeout):
    """Closed-loop QPS client: single-chunk REQ_RANGE (1 req -> 1 resp), repeat for
    `duration` seconds. Returns (sent, answered, [latencies_s])."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(rtimeout)
    sent = answered = 0
    lat = []
    seq = (id(s) // 8) % max(nchunks, 1)         # per-worker start offset (avoid dedup)
    t_end = time.time() + duration
    while time.time() < t_end:
        seq = (seq + 7919) % nchunks              # spread requests across chunks
        req = req_plain(seq, seq)                  # start == end -> exactly one chunk
        t0 = time.time()
        s.sendto(req, (host, port)); sent += 1
        try:
            while True:
                data, _ = s.recvfrom(2048)
                if (len(data) >= 7 and data[:4] == b"BIN0" and data[4] == 0x82
                        and struct.unpack(">H", data[5:7])[0] == seq):
                    answered += 1; lat.append(time.time() - t0); break
                # stray/late reply for another seq -> keep waiting until timeout
        except socket.timeout:
            pass                                   # dropped
    s.close()
    return sent, answered, lat

def run_qps_level(host, port, nchunks, duration, rtimeout, N):
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=N) as ex:
        futs = [ex.submit(qps_worker, host, port, nchunks, duration, rtimeout)
                for _ in range(N)]
        res = [f.result() for f in futs]
    wall = time.time() - t0
    sent = sum(r[0] for r in res)
    answered = sum(r[1] for r in res)
    lat = sorted(l for r in res for l in r[2])
    return wall, sent, answered, lat

def run_level(host, port, nchunks, deadline, win, N):
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=N) as ex:
        futs = [ex.submit(fetch_one, host, port, nchunks, deadline, win) for _ in range(N)]
        res = [f.result() for f in futs]
    wall = time.time() - t0
    return wall, res

def main():
    a = parse_args()
    nchunks = a.nchunks
    if not nchunks:
        try:
            nchunks = math.ceil(os.path.getsize(a.bin) / a.chunk_bytes)
        except OSError:
            print(f"can't size {a.bin}; pass --nchunks"); sys.exit(2)
    levels = [int(x) for x in a.levels.split(",") if x.strip()]
    if a.preflight > 0 and not preflight(a.host, a.port, a.preflight):
        print(f"ERROR: no response from {a.host}:{a.port} within {a.preflight}s — "
              f"is the node serving?", file=sys.stderr)
        print("Start an offline (disk-boot) node, then re-run, e.g.:", file=sys.stderr)
        print("  sh scripts/makenode.sh", file=sys.stderr)
        print("  printf '3737 0 10000\\004' | ./tools/q32 bin/tabernacle "
              "--disk=./data/disk.img --net --hostfwd=udp::3737-:3737 &", file=sys.stderr)
        print("  python3 tools/bin0_probe.py   # wait for SERVING", file=sys.stderr)
        print("...or just run the all-in-one:  sh scripts/loadtest.sh", file=sys.stderr)
        sys.exit(2)
    total_bytes = nchunks * a.chunk_bytes
    print(f"# server {a.host}:{a.port}  nchunks={nchunks}  mode={a.mode}")
    print(f"# NOTE: slirp shares one source IP across clients; numbers are slirp-bounded, "
          f"not the server's raw ceiling.")

    if a.mode == "qps":
        # Request-rate: single-chunk REQ_RANGE (1 req -> 1 resp). N closed-loop clients
        # fire as fast as they can for --duration s. QPS = answered/s; ramp N for the max.
        print(f"# QPS = single-chunk REQ_RANGE answered/s; N = concurrent closed-loop clients; "
              f"duration={a.duration}s, timeout={a.rtimeout}s")
        print(f"{'N':>3} {'QPS':>8} {'p50_ms':>7} {'p99_ms':>7} {'max_ms':>7} "
              f"{'drop%':>6} {'sent':>7}")
        for N in levels:
            wall, sent, answered, lat = run_qps_level(
                a.host, a.port, nchunks, a.duration, a.rtimeout, N)
            qps = answered / wall if wall else 0
            drop = 100.0 * (1 - answered / sent) if sent else 0
            p50 = lat[len(lat)//2] * 1e3 if lat else 0
            p99 = lat[min(len(lat)-1, int(len(lat)*0.99))] * 1e3 if lat else 0
            mx = lat[-1] * 1e3 if lat else 0
            print(f"{N:>3} {qps:>8.0f} {p50:>7.1f} {p99:>7.1f} {mx:>7.1f} "
                  f"{drop:>6.1f} {sent:>7}")
        return

    print("# req/s = REQ_RANGE sent/s (offered load, incl. resends); "
          "chunk/s = RSP_CHUNK recv/s (server emit rate). 1 request -> many chunks.")
    print(f"{'N':>3} {'done':>5} {'wall_s':>7} {'fetch_med':>9} {'fetch_p95':>9} "
          f"{'agg_MB/s':>8} {'req/s':>7} {'chunk/s':>8} {'rounds':>7}")
    for N in levels:
        wall, res = run_level(a.host, a.port, nchunks, a.deadline, a.win, N)
        done = sum(1 for r in res if r["complete"])
        times = sorted(r["t"] for r in res)
        med = times[len(times)//2]
        p95 = times[min(len(times)-1, int(len(times)*0.95))]
        recv_pkts = sum(r["recv"] for r in res)
        sent_reqs = sum(r["sent"] for r in res)
        have_total = sum(r["have"] for r in res)
        # aggregate goodput: unique chunk-bytes delivered across all fetchers / wall
        agg = (have_total * a.chunk_bytes) / wall / 1e6 if wall else 0
        req_s = sent_reqs / wall if wall else 0      # REQ_RANGE offered/s
        chunk_s = recv_pkts / wall if wall else 0    # RSP_CHUNK served/s
        rounds = sorted(r["rounds"] for r in res)
        rmed = rounds[len(rounds)//2]
        print(f"{N:>3} {done:>3}/{N:<1} {wall:>7.2f} {med:>9.2f} {p95:>9.2f} "
              f"{agg:>8.2f} {req_s:>7.0f} {chunk_s:>8.0f} {rmed:>7}")
    print("# ^ bulk-download throughput. For a single-chunk request-rate QPS number, "
          "re-run with:  --mode qps")

if __name__ == "__main__":
    main()
