#!/usr/bin/env python3
"""serial_io.py PORT IN OUT — pump for QEMU's TCP serial chardev.

Connects to 127.0.0.1:PORT (retrying while QEMU starts up), streams file IN
into the socket, and writes everything received to file OUT until QEMU closes
the connection (guest exit).  Used where file-backed serial isn't available:
QEMU's win32 build rejects `-chardev file,input-path=...`, and its win32 stdio
chardev loses bytes on piped stdin.  The socket chardev behaves identically on
every platform, so this path is also testable on Linux via FAM_SERIAL=socket.
"""
import socket
import sys
import threading
import time

port, inf, outf = int(sys.argv[1]), sys.argv[2], sys.argv[3]

s = None
deadline = time.time() + 10
while time.time() < deadline:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        break
    except OSError:
        time.sleep(0.1)
if s is None:
    sys.exit("serial_io: cannot connect to qemu on port %d" % port)


def send():
    try:
        with open(inf, "rb") as f:
            s.sendall(f.read())
    except OSError:
        pass  # guest exited before consuming all input (e.g. compile abort)


if inf != "-":  # "-" = no input to send (native win32 python has no /dev/null)
    threading.Thread(target=send, daemon=True).start()

with open(outf, "wb") as f:
    while True:
        d = s.recv(65536)
        if not d:
            break
        f.write(d)
