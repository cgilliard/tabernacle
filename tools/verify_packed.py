#!/usr/bin/env python3
"""verify_packed.py — compositional proof for a self-extracting (fampack) binary.

A static CFG-walk CANNOT verify a packed binary: its real code is produced at
runtime by decompression (a linear walk would decode the LZ77 payload as
instructions). So we prove it in two independent pieces:

  1. the decompressor STUB is clean RV32I-base (no jalr / SYSTEM / illegal), and
  2. the LZ77 payload DECOMPRESSES to an image that itself passes P1/P2 (FSM) and
     P3 (W^X) -- i.e. the bytes that actually run are the verified image.

Together: at runtime the packed binary executes only the clean stub and then the
fully-verified decompressed image, so it inherits that image's properties.

fampack layout: 16-byte header [ nop ; jal x0,+12 ; payload_size LE ; uncomp_size
LE ], a 192-byte stub at offset 16, then the LZ77 payload at offset 208. LZ77
stream: a flag byte consumed MSB-first; bit 1 = literal (1 byte copied), bit 0 =
match (2 bytes: b0 | ((b1 & 0xf) << 8) = offset-1 [12b]; b1 >> 4 = length-3 [4b];
copy `length` bytes from dst-offset, byte-by-byte so overlapping copies work).

With --reference UNCOMPRESSED, also assert the decompressed image is byte-
identical to that file -- confirming this decoder matches the stub's decoder
(and that the build is reproducible).

--handoff selects the TABERNACLE profile: the decompressed image is a loader that
hands off to an appended payload, so P1/P2 run with the end_marker exit declared
(verify_fsm --handoff) and the fam-compiler W^X step is replaced by the P5
handoff-gate check (verify_handoff).  W^X/P3 for tabernacle needs a separate
memory model and is NOT claimed by this pass (see doc/TABERNACLE_SAFETY.md).

Usage: verify_packed.py PACKED [--handoff] [--reference UNCOMPRESSED]
Exit:  0 = PROVEN, 1 = a check failed, 2 = usage.
"""

import sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import verify_fsm
import verify_wx
import verify_handoff
from verify_fsm import decode

STUB_OFF = 16          # past the 16-byte header
PAYLOAD_OFF = 208      # fampack's stub is a fixed 192 bytes (16 + 192)
HDR_NOP = 0x00000013
HDR_JAL12 = 0x00c0006f  # jal x0, +12  (skip the two size fields -> stub at 0x10)


def lz_decode(payload, uncomp_size):
    out = bytearray()
    p = flag = bits = 0
    while len(out) < uncomp_size:
        if bits == 0:
            flag = payload[p]; p += 1; bits = 8
        bit = (flag >> 7) & 1
        flag = (flag << 1) & 0xff
        bits -= 1
        if bit:                                   # literal
            out.append(payload[p]); p += 1
        else:                                     # back-reference
            b0, b1 = payload[p], payload[p + 1]; p += 2
            off = (b0 | ((b1 & 0x0f) << 8)) + 1
            length = (b1 >> 4) + 3
            s = len(out) - off
            for i in range(length):
                out.append(out[s + i])            # byte-by-byte: overlaps ok
    return bytes(out)


def verify_stub(data, lo, hi):
    """Linear P1 scan of the stub region (pure code, no embedded data)."""
    bad = []
    for off in range(lo, hi, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        d = decode(w)
        if not d["legal"]:
            bad.append((off, w, d["name"]))
    return bad


def main(argv):
    path = ref = None
    handoff = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--reference":
            ref = argv[i + 1]; i += 2; continue
        if a == "--handoff":
            handoff = True; i += 1; continue
        if a in ("-h", "--help"):
            print(__doc__); return 0
        if a.startswith("-"):
            sys.exit(f"verify_packed: unknown option: {a}")
        path = a; i += 1
    if not path:
        print(__doc__); return 2

    data = open(path, "rb").read()
    print(f"{path}  ({len(data)} B)")

    # ---- header ----
    w0 = int.from_bytes(data[0:4], "little")
    w1 = int.from_bytes(data[4:8], "little")
    psize = int.from_bytes(data[8:12], "little")
    usize = int.from_bytes(data[12:16], "little")
    ok = True
    hdr_ok = (w0 == HDR_NOP and w1 == HDR_JAL12 and len(data) == PAYLOAD_OFF + psize)
    print(f"  header: nop+jal12={'ok' if (w0==HDR_NOP and w1==HDR_JAL12) else 'BAD'}"
          f"  payload={psize} B @ {PAYLOAD_OFF}  uncompressed={usize} B"
          f"  layout={'ok' if len(data)==PAYLOAD_OFF+psize else 'BAD'}")
    if not hdr_ok:
        print("  => NOT a fampack self-extracting binary (or truncated)")
        return 1

    # ---- (1) stub is clean RV32I ----
    stub_bad = verify_stub(data, STUB_OFF, PAYLOAD_OFF)
    print(f"  stub: {(PAYLOAD_OFF-STUB_OFF)//4} instrs, "
          f"{'no jalr/SYSTEM/illegal — clean' if not stub_bad else f'{len(stub_bad)} VIOLATION(S)'}")
    for off, w, name in stub_bad[:8]:
        print(f"    !! +{off:#06x} {w:08x} {name}")
    if stub_bad:
        ok = False

    # ---- (2) decompress + verify the image ----
    try:
        image = lz_decode(data[PAYLOAD_OFF:PAYLOAD_OFF + psize], usize)
    except (IndexError, ValueError) as e:
        print(f"  decompress: FAILED ({e})"); return 1
    print(f"  decompressed image: {len(image)} B"
          f"{'' if len(image)==usize else f' (expected {usize}!)'}")
    if len(image) != usize:
        ok = False

    r = verify_fsm.verify_bytes(image, handoff=handoff)
    p1 = [v for v in r.violations if v[2].startswith("P1")]
    p2 = [v for v in r.violations if v[2].startswith(("P2", "P0"))]
    hx = f"   ({len(r.exits)} declared handoff exit(s))" if r.exits else ""
    print(f"  image P1 (RV32I/no-jalr): {'PASS' if not p1 else 'FAIL'}   "
          f"P2 (closed CFG): {'PASS' if not p2 else 'FAIL'}{hx}")
    for off, w, msg in r.violations[:8]:
        print(f"    !! +{off:#06x} {w:08x} {msg}")
    if r.violations:
        ok = False

    if handoff:
        # Tabernacle profile: the image hands off to the payload, so prove the
        # handoff is hash-gated (P5a) instead of the fam-compiler W^X pass, which
        # uses a memory model that does not apply here.  P3/W^X for tabernacle is
        # a separate, future obligation (see doc/TABERNACLE_SAFETY.md).
        hr, _hg = verify_handoff.verify_bytes(image)
        if hr.bad:
            print("  image P5a (handoff gated): cannot run (image not P1/P2-clean)")
            ok = False
        else:
            gated = len(hr.exits) - len(hr.ungated)
            print(f"  image P5a (handoff gated): {'PASS' if hr.ok else 'FAIL'}"
                  f"   {gated}/{len(hr.exits)} exit(s) hash-gated")
            for kind, site in hr.ungated:
                print(f"    !! +{site:#06x} UNGATED exit ({kind})")
            if not hr.ok:
                ok = False
    else:
        wx = verify_wx.analyze(image, verify_wx.ROOTS_COMPILER)
        tr = f" (modulo {len(wx.tramps)} declared trampoline)" if wx.tramps else ""
        print(f"  image P3 (W^X): {'PASS' if wx.ok else 'FAIL'}{tr}")
        for off, w, base, msg in wx.flags[:8]:
            print(f"    !! +{off:#06x} {w:08x} base={base} {msg}")
        if not wx.ok:
            ok = False

    # ---- optional: byte-identity with the proven reference image ----
    if ref:
        refbytes = open(ref, "rb").read()
        match = (image == refbytes)
        print(f"  reference {ref}: {'byte-identical — decoder matches stub & build reproducible' if match else 'MISMATCH'}")
        if not match:
            ok = False

    if ok:
        props = "P1/P2(handoff)/P5a" if handoff else "P1/P2/P3"
        print(f"  => PROVEN: clean stub + payload decompresses to a {props}-verified image")
    else:
        print("  => NOT PROVEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
