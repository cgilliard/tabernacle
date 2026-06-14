#!/usr/bin/env python3
"""verify_fsm.py — prove a fam binary is a bounded finite-state machine.

The core theorem: in RV32I the ONLY instruction that loads the PC from a
register is `jalr`.  Every other transfer (`jal`, branches) uses a PC-relative
immediate baked into the instruction.  So if a binary contains no `jalr`, the PC
is always a static function of the current PC -> control flow is independent of
input/data -> the control-flow graph is a fixed, finite graph (an FSM) -> no
input can ever redirect execution (no control-flow-hijack RCE).

Passes implemented here (the "no-RCE core"):

  P1  every REACHABLE word is a fully-legal RV32I-BASE instruction.  This is an
      ALLOW-LIST, not a block-list: anything not in the base ISA is rejected,
      which subsumes
        - no jalr (indirect control)      - no SYSTEM (ecall/ebreak/CSR, Zicsr)
        - no M / A / F / D extension       - no compressed (16-bit) encodings
        - funct3 / funct7 / reserved bits must be valid base encodings.

  P2  every jal/branch target is in-bounds, 4-aligned, and lands on an
      instruction boundary -> the CFG is closed and finite.

The analysis is a CFG-reachability walk from the entry (offset 0): it follows
only STATIC jal/branch edges, so it ALSO proves embedded data is never executed
as code (unreached in-bounds words are reported, never decoded).

NOTE the scope line: this proves the property for the BINARY it is handed.  It
does not trust any source.  fam's own binaries get the full result; a hostile
source can still hand-emit a `jalr` via raw `,`, in which case P1 fails here —
the proof has no blind spot, it just shifts the obligation to the output binary.

Pending passes (not yet implemented): P3 W^X / region separation (store-address
value analysis), P4 RID-stack / pinned-register discipline.

Usage: verify_fsm.py [--quiet] [--selftest] BINARY [BINARY ...]
Exit:  0 = all PROVEN, 1 = a VIOLATION, 2 = usage / self-test failure.
"""

import sys


# --------------------------------------------------------------------------
# immediate decoders
# --------------------------------------------------------------------------
def _jimm(w):
    imm = ((w >> 31 & 1) << 20) | ((w >> 12 & 0xff) << 12) \
        | ((w >> 20 & 1) << 11) | ((w >> 21 & 0x3ff) << 1)
    return imm - (1 << 21) if imm & (1 << 20) else imm


def _bimm(w):
    imm = ((w >> 31 & 1) << 12) | ((w >> 7 & 1) << 11) \
        | ((w >> 25 & 0x3f) << 5) | ((w >> 8 & 0xf) << 1)
    return imm - (1 << 13) if imm & (1 << 12) else imm


# --------------------------------------------------------------------------
# strict RV32I-base decoder (allow-list)
# --------------------------------------------------------------------------
# kind: None (no control / fall-through only), 'jal', or 'branch'.
def decode(w):
    """Return dict(legal, name, kind, imm, rd) for a 32-bit word."""
    if (w & 3) != 3:
        return dict(legal=False, name="compressed/16-bit (RVC, disabled)", kind=None)
    op = w & 0x7f
    f3 = (w >> 12) & 7
    f7 = (w >> 25) & 0x7f
    rd = (w >> 7) & 0x1f

    def ok(name, kind=None, imm=0):
        return dict(legal=True, name=name, kind=kind, imm=imm, rd=rd)

    def bad(name):
        return dict(legal=False, name=name, kind=None)

    if op == 0x37: return ok("lui")
    if op == 0x17: return ok("auipc")
    if op == 0x6f: return ok("jal", "jal", _jimm(w))
    if op == 0x67: return bad("jalr (indirect jump)")
    if op == 0x63:
        names = {0: "beq", 1: "bne", 4: "blt", 5: "bge", 6: "bltu", 7: "bgeu"}
        if f3 in names: return ok(names[f3], "branch", _bimm(w))
        return bad(f"BRANCH reserved funct3={f3}")
    if op == 0x03:
        names = {0: "lb", 1: "lh", 2: "lw", 4: "lbu", 5: "lhu"}
        if f3 in names: return ok(names[f3])
        return bad(f"LOAD reserved funct3={f3}")
    if op == 0x23:
        names = {0: "sb", 1: "sh", 2: "sw"}
        if f3 in names: return ok(names[f3])
        return bad(f"STORE reserved funct3={f3}")
    if op == 0x13:
        if f3 == 1:
            return ok("slli") if f7 == 0x00 else bad(f"slli reserved funct7={f7:#x}")
        if f3 == 5:
            return ok("srli/srai") if f7 in (0x00, 0x20) else bad(f"sr*i reserved funct7={f7:#x}")
        names = {0: "addi", 2: "slti", 3: "sltiu", 4: "xori", 6: "ori", 7: "andi"}
        return ok(names[f3])
    if op == 0x33:
        if f7 == 0x01: return bad("M-ext (mul/div/rem)")
        if f7 == 0x00:
            names = {0: "add", 1: "sll", 2: "slt", 3: "sltu", 4: "xor", 5: "srl", 6: "or", 7: "and"}
            return ok(names[f3])
        if f7 == 0x20:
            if f3 == 0: return ok("sub")
            if f3 == 5: return ok("sra")
            return bad(f"OP funct7=0x20 reserved funct3={f3}")
        return bad(f"OP reserved funct7={f7:#x}")
    if op == 0x0f:
        if f3 == 0: return ok("fence")
        if f3 == 1: return bad("fence.i (Zifencei, disabled)")
        return bad(f"MISC-MEM reserved funct3={f3}")
    if op == 0x73: return bad("SYSTEM (ecall/ebreak/CSR, Zicsr disabled)")
    if op == 0x2f: return bad("A-ext (atomic)")
    if op in (0x07, 0x27): return bad("F/D-ext (fp load/store)")
    if op in (0x53, 0x43, 0x47, 0x4b, 0x4f): return bad("F/D-ext (fp arith)")
    return bad(f"unknown opcode {op:#x}")


# --------------------------------------------------------------------------
# CFG-reachability verifier
# --------------------------------------------------------------------------
class Result:
    def __init__(self):
        self.size = 0
        self.reached = set()
        self.violations = []   # (offset, word, message)
        self.jal_link = []     # offsets of `jal rd!=0` (call-style; informational)
        self.exits = []        # offsets of declared handoff jumps (--handoff only)

    @property
    def ok(self):
        return not self.violations


def verify_bytes(data, entry=0, handoff=False):
    """handoff=True: a jal/branch whose target is exactly `n` (the byte past the
    image = end_marker) is recorded as a DECLARED EXIT to the appended payload,
    not a P2 violation.  Its safety (that it is hash-gated) is verify_handoff/P5,
    not this pass — here it just keeps the CFG "closed except for the declared
    exit"."""
    r = Result()
    n = r.size = len(data)

    def word(off):
        return int.from_bytes(data[off:off + 4], "little")

    def in_code(off):
        return 0 <= off and off + 4 <= n and off % 4 == 0

    # Non-vacuity: an empty or sub-word image has no in-code entry, so the walk
    # below would terminate immediately and vacuously "pass".  Reject it.
    if not in_code(entry):
        r.violations.append((entry, 0, "P0 entry not in code (empty/truncated image)"))
        return r

    stack = [entry]
    while stack:
        pc = stack.pop()
        if pc in r.reached:
            continue
        if not in_code(pc):
            # Fell off the end (or onto a misaligned addr) by fall-through: this
            # is a terminal/halt state, not a violation.  Bad *targets* are
            # caught at the jump site below, where we know it was a real edge.
            continue
        r.reached.add(pc)
        w = word(pc)
        d = decode(w)
        if not d["legal"]:
            r.violations.append((pc, w, "P1 " + d["name"]))
            continue
        k = d["kind"]
        if k == "jal":
            tgt = pc + d["imm"]
            if in_code(tgt):
                stack.append(tgt)
            elif handoff and tgt == n:
                r.exits.append(pc)
            else:
                r.violations.append((pc, w, f"P2 jal target out of code -> {tgt:#x}"))
            if d["rd"] != 0:                 # call-style: also reaches the return point
                r.jal_link.append(pc)
                stack.append(pc + 4)
        elif k == "branch":
            tgt = pc + d["imm"]
            if in_code(tgt):
                stack.append(tgt)
            elif handoff and tgt == n:
                r.exits.append(pc)
            else:
                r.violations.append((pc, w, f"P2 branch target out of code -> {tgt:#x}"))
            stack.append(pc + 4)
        else:
            stack.append(pc + 4)
    return r


def verify_file(path, entry=0, handoff=False):
    with open(path, "rb") as f:
        return verify_bytes(f.read(), entry, handoff)


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def report(path, r, quiet=False):
    words = r.size // 4
    code = len(r.reached)
    if not quiet:
        print(f"{path}")
        print(f"  size: {r.size} B ({words} words)   entry: 0x0")
        print(f"  reachable code: {code} words   unreached (data/dead): {words - code} words")
        p1 = [v for v in r.violations if v[2].startswith("P1")]
        p2 = [v for v in r.violations if v[2].startswith("P2")]
        print(f"  P1 (RV32I-base; no jalr/system/M/A/F/D/RVC):  {'PASS' if not p1 else 'FAIL'}")
        print(f"  P2 (closed, in-bounds CFG):                   {'PASS' if not p2 else 'FAIL'}")
        if r.exits:
            print(f"  note: {len(r.exits)} declared handoff exit(s) to end_marker "
                  f"— safety is verify_handoff/P5")
        if r.jal_link:
            print(f"  note: {len(r.jal_link)} jal-with-link (rd!=0) — call-style, allowed")
        for off, w, msg in r.violations[:40]:
            print(f"    !! +{off:#06x}  {w:08x}  {msg}")
        if len(r.violations) > 40:
            print(f"    ... and {len(r.violations) - 40} more")
    if r.ok:
        print(f"  => PROVEN: bounded FSM, no indirect control, no control-hijack RCE")
    else:
        print(f"  => VIOLATION ({len(r.violations)} finding(s))")
    return r.ok


# --------------------------------------------------------------------------
# self-test: prove the prover is not vacuous (it must REJECT bad binaries)
# --------------------------------------------------------------------------
def selftest():
    le = lambda w: w.to_bytes(4, "little")
    NOP = 0x00000013
    cases = []
    # 1. clean: nop ; jal x0,0 (self-loop halt)        -> PASS
    cases.append(("clean nop+selfloop", le(NOP) + le(0x0000006f), True))
    # 2. jalr present                                    -> FAIL P1
    cases.append(("jalr", le(NOP) + le(0x00008067), False))      # ret = jalr x0,0(ra)
    # 3. M-ext mul                                       -> FAIL P1
    cases.append(("mul", le(NOP) + le(0x02208033), False))       # mul x0,x1,x2
    # 4. ecall                                           -> FAIL P1
    cases.append(("ecall", le(NOP) + le(0x00000073), False))
    # 5. jal target out of range                         -> FAIL P2
    cases.append(("jal-oob", le(0x100000ef), False))             # jal ra, +0x100 (past 4-byte file)
    # 6. compressed                                      -> FAIL P1
    cases.append(("rvc", le(NOP) + le(0x00000001), False))       # low2 bits != 11
    # 7. empty image (non-vacuity): must NOT vacuously pass -> FAIL P0
    cases.append(("empty", b"", False))
    ok = True
    for name, blob, expect_pass in cases:
        got = verify_bytes(blob).ok
        verdict = "OK" if got == expect_pass else "WRONG"
        if got != expect_pass:
            ok = False
        print(f"  selftest {name:22s} expect={'PASS' if expect_pass else 'FAIL'}  got={'PASS' if got else 'FAIL'}  [{verdict}]")
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------
def main(argv):
    quiet = False
    handoff = False
    paths = []
    for a in argv:
        if a == "--quiet": quiet = True
        elif a == "--handoff": handoff = True
        elif a == "--selftest": return 0 if selftest() else 2
        elif a in ("-h", "--help"): print(__doc__); return 0
        elif a.startswith("-"): sys.exit(f"verify_fsm: unknown option: {a}")
        else: paths.append(a)
    if not paths:
        print(__doc__); return 2
    all_ok = True
    for p in paths:
        r = verify_file(p, handoff=handoff)
        if not report(p, r, quiet):
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
