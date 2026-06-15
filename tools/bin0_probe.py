#!/usr/bin/env python3
"""Minimal BIN0 probe: send one REQ_RANGE for chunks [0..N], print what comes back.
Retries (the node takes a few seconds to disk-boot) until a reply arrives or timeout.
Usage: bin0_probe.py [host] [port] [end_chunk] [overall_timeout_s]"""
import socket, sys, time, struct

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 3737
end  = int(sys.argv[3]) if len(sys.argv) > 3 else 4
budget = float(sys.argv[4]) if len(sys.argv) > 4 else 30.0

# REQ_RANGE = "BIN0" 0x02 start(BE16) end(BE16)
req = b"BIN0" + bytes([0x02]) + struct.pack(">HH", 0, end)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)

deadline = time.time() + budget
got = {}
while time.time() < deadline:
    try:
        s.sendto(req, (host, port))
    except OSError as e:
        print("send error:", e); time.sleep(0.5); continue
    try:
        while True:
            data, _ = s.recvfrom(2048)
            if data[:4] == b"BIN0" and len(data) >= 7 and data[4] == 0x82:
                seq = struct.unpack(">H", data[5:7])[0]
                got[seq] = len(data) - 7
            if len(got) > end:
                break
    except socket.timeout:
        pass
    if got:
        break

if got:
    print(f"SERVING: received {len(got)} chunks, seqs {sorted(got)[:8]}{'...' if len(got)>8 else ''}, "
          f"payload bytes {sum(got.values())}")
    sys.exit(0)
else:
    print("NO REPLY within", budget, "s")
    sys.exit(1)
