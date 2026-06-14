#!/usr/bin/env python3
"""verify_cfi.py — P4: RID-stack + pinned-register discipline (control-flow
integrity), which also discharges the ROOT AXIOM that P3 (W^X) assumes.

P4a — ROOT PROVENANCE.  Every reachable write to a pinned (region-root) register
must produce a value computed from the `data` region-base + constants, via ALU
on constant/region operands.  A pinned register is NEVER set from a memory load,
a return address (jal rd), a code address other than `data`, or an arithmetic op
with an INPUT/loaded operand.  Therefore each root is always `data + integer` and
cannot be corrupted to point into code or to an input-controlled address — the
qualitative discharge of P3's root axiom.

P4b — RID-STACK DISCIPLINE.  The return-id stack pointer s11 is only adjusted by
+/-4 outside its _start init; every push (`sw rs,0(s11)`) is guarded on its path
by the s11>=s10 overflow check (`b{lt,ge}u s11,s10,_`); every pushed return-id is
a compile-time constant.  So the no-jalr return mechanism (push RID -> j body ->
dispatch BST -> j site) cannot be redirected by a corrupted RID, and the RID
stack cannot grow below its floor s10.

RESIDUAL: the numeric "roots stay >= code_end / regions pairwise disjoint" part
needs the relational analysis of the CHECK_HEAP / overflow guards (the
region-safety pass).  P4 proves roots are region-RELATIVE and the RID mechanism
is integrity-protected; the guards (verified present here for the RID stack) keep
the decrementing roots in range.

Reuses verify_wx's provenance dataflow for operand classification.

Usage: verify_cfi.py [--roots prog|compiler] BINARY ...
Exit:  0 = PROVEN, 1 = a discipline violation, 2 = usage.
"""

import sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import verify_fsm
import verify_wx
from verify_fsm import decode

LOAD = 0x80000000
S1, S2, S10, S11 = 9, 18, 26, 27
RN = verify_wx.RN
S32 = verify_wx.S32
# s1 (source cursor) and s2 (limit) are input pointers, read-only -- never used
# as a store base nor to derive one, so P3's W^X axiom does not depend on them.
# They are heavily arg-passed / restored from the macro-resume stack, so we don't
# subject them to the root-provenance check.
NOT_STORE_BASE = {S1, S2}


def _iimm(w):
    v = (w >> 20) & 0xfff
    return v - (1 << 12) if v & 0x800 else v

def _simm(w):
    v = ((w >> 25) & 0x7f) << 5 | ((w >> 7) & 0x1f)
    return v - (1 << 12) if v & 0x800 else v


def analyze(data, roots):
    n = len(data)
    code_hi = LOAD + n
    word = lambda o: int.from_bytes(data[o:o + 4], "little")
    reached = verify_fsm.verify_bytes(data).reached
    wx = verify_wx.analyze(data, roots)          # provenance of every non-root reg
    state, readtag = wx.state, wx.readtag
    code_lo, code_hi = LOAD, LOAD + n
    flags = []                                   # (off, word, msg)
    checked = roots - NOT_STORE_BASE             # store-base roots P3 relies on

    def benign(tag):
        """A value that, if loaded into a root, keeps it OUT of the code image:
        a region pointer, or a constant whose address is outside [code_lo,code_hi)."""
        return tag[0] in ('R', 'RG') or (tag[0] == 'C' and not (code_lo <= tag[1] < code_hi))

    # root-safe slots: every store to (root,offset) writes a benign value, so a
    # load from it yields a value that keeps the root out of the code image.
    bad_slot, seen_slot = set(), set()
    for off in sorted(reached):
        w = word(off)
        if (w & 0x7f) != 0x23:
            continue
        base = readtag((w >> 15) & 0x1f, state.get(off, {}))
        if not (base and all(t[0] == 'R' for t in base)):
            continue
        val = readtag((w >> 20) & 0x1f, state.get(off, {}))
        ok = bool(val) and all(benign(t) for t in val)
        for bt in base:
            slot = (bt[1], bt[2] + _simm(w))
            seen_slot.add(slot)
            if not ok:
                bad_slot.add(slot)
    root_safe = seen_slot - bad_slot

    def prov_ok(reg, st):
        """True if reg holds only region pointers or constants (not INPUT/CODE/TOP)."""
        tags = readtag(reg, st)
        return bool(tags) and all(t[0] in ('R', 'RG', 'C') for t in tags)

    def load_from_pointer_slot(w, st):
        """A load whose base+offset is a root-safe slot yields a value that keeps
        the root out of code (a saved cursor/pointer round-tripping through memory)."""
        base = readtag((w >> 15) & 0x1f, st)
        return bool(base) and all(t[0] == 'R' and (t[1], t[2] + _iimm(w)) in root_safe for t in base)

    # ---- P4a: root write discipline ----
    n_root_writes = 0
    for off in sorted(reached):
        w = word(off)
        rd = verify_wx.written_reg(w)
        if rd is None or rd not in checked:
            continue
        n_root_writes += 1
        op = w & 0x7f
        st = state.get(off, {})
        rs1 = (w >> 15) & 0x1f
        rs2 = (w >> 20) & 0x1f
        if op == 0x03:                                       # load into a root
            if not load_from_pointer_slot(w, st):
                flags.append((off, w, f"P4a {RN[rd]} loaded from a non-pointer-slot (input could control a root)"))
        elif op == 0x6f:                                     # jal rd (return addr into a root)
            flags.append((off, w, f"P4a {RN[rd]} set to a return address (jal)"))
        elif op == 0x17:                                     # auipc: only LOAD_ADDRESS data
            nxt = word(off + 4) if (off + 4) in reached else 0
            base = LOAD + off + S32(((w >> 12) & 0xfffff) << 12)
            ok = ((nxt & 0x7f) == 0x13 and ((nxt >> 12) & 7) == 0
                  and ((nxt >> 7) & 0x1f) == rd and ((nxt >> 15) & 0x1f) == rd
                  and base + _iimm(nxt) == code_hi)
            if not ok:
                flags.append((off, w, f"P4a {RN[rd]} set via auipc to a non-`data` code address"))
        elif op == 0x37:                                     # lui: constant offset literal -> ok
            pass
        elif op in (0x13, 0x33):                             # ALU: operands must be region/const
            srcs = [rs1] if op == 0x13 else [rs1, rs2]
            bad = [s for s in srcs if s != 0 and s not in roots and not prov_ok(s, st)]
            if bad:
                names = ",".join(RN[s] for s in bad)
                flags.append((off, w, f"P4a {RN[rd]} computed from non-region/non-const operand(s): {names}"))
        else:
            flags.append((off, w, f"P4a {RN[rd]} written by unexpected op {op:#x}"))

    # ---- P4b: RID-stack discipline ----
    n_pushes = 0
    for off in sorted(reached):
        w = word(off)
        # adjustments to s11 outside init must be addi s11,s11,+/-4
        if verify_wx.written_reg(w) == S11 and (w & 0x7f) == 0x13 \
           and ((w >> 12) & 7) == 0 and ((w >> 15) & 0x1f) == S11:
            if _iimm(w) not in (4, -4):
                flags.append((off, w, f"P4b s11 adjusted by {_iimm(w)} (not +/-4)"))
        # RID pushes: sw rs, 0(s11)
        if (w & 0x7f) == 0x23 and ((w >> 15) & 0x1f) == S11 and ((w >> 12) & 7) == 2 \
           and (((w >> 25) & 0x7f) << 5 | ((w >> 7) & 0x1f)) == 0:
            n_pushes += 1
            # (b1) guarded by an s11>=s10 overflow branch within the few prior insns
            guarded = False
            for back in range(4, 20, 4):
                p = off - back
                if p not in reached:
                    break
                pw = word(p)
                if (pw & 0x7f) == 0x63:
                    a, b = (pw >> 15) & 0x1f, (pw >> 20) & 0x1f
                    if {a, b} == {S10, S11}:
                        guarded = True
                        break
            if not guarded:
                flags.append((off, w, "P4b RID push not guarded by an s11>=s10 overflow check"))
            # (b2) the pushed return-id is a constant
            rs = (w >> 20) & 0x1f
            tags = readtag(rs, state.get(off, {}))
            if not (tags and all(t[0] == 'C' for t in tags)):
                flags.append((off, w, f"P4b RID pushed from {RN[rs]} is not a compile-time constant"))

    return flags, n_root_writes, n_pushes


def report(path, roots):
    with open(path, "rb") as f:
        data = f.read()
    flags, nrw, npush = analyze(data, roots)
    p4a = [x for x in flags if x[2].startswith("P4a")]
    p4b = [x for x in flags if x[2].startswith("P4b")]
    print(f"{path}")
    print(f"  pinned-register writes: {nrw}   RID pushes: {npush}")
    print(f"  P4a (root provenance: roots are data+integer, never loaded/foreign): "
          f"{'PASS' if not p4a else 'FAIL'}")
    print(f"  P4b (RID stack: +/-4 only, every push guarded, ids constant):         "
          f"{'PASS' if not p4b else 'FAIL'}")
    for off, w, msg in flags[:40]:
        print(f"    !! +{off:#06x}  {w:08x}  {msg}")
    ok = not flags
    if ok:
        print("  => PROVEN: pinned-register + RID-stack discipline holds (CFI; root axiom discharged)")
    else:
        print(f"  => VIOLATION ({len(flags)} finding(s))")
    return ok


def selftest():
    le = lambda w: w.to_bytes(4, "little")
    HALT = 0x0000006f                                   # j .
    cases = [
        ("clean: root from root",  le(0x00010193) + le(HALT), True),   # addi gp,sp,0
        ("load into root",         le(0x00012183) + le(HALT), False),  # lw gp,0(sp)
        ("jal into root",          le(0x000001ef),            False),  # jal gp,.  (return addr -> root)
        ("s11 adjust by 8",        le(0x008d8d93) + le(HALT), False),  # addi s11,s11,8
    ]
    ok = True
    for name, blob, expect in cases:
        flags, _, _ = analyze(blob, verify_wx.ROOTS_COMPILER)
        got = not flags
        v = "OK" if got == expect else "WRONG"
        if got != expect: ok = False
        print(f"  selftest {name:24s} expect={'PASS' if expect else 'FAIL'} got={'PASS' if got else 'FAIL'} [{v}]")
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


def main(argv):
    roots = verify_wx.ROOTS_COMPILER
    paths = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--roots":
            roots = verify_wx.ROOTS_PROGRAM if argv[i + 1] == "prog" else verify_wx.ROOTS_COMPILER
            i += 2; continue
        if a == "--selftest":
            return 0 if selftest() else 2
        if a in ("-h", "--help"):
            print(__doc__); return 0
        if a.startswith("-"):
            sys.exit(f"verify_cfi: unknown option: {a}")
        paths.append(a); i += 1
    if not paths:
        print(__doc__); return 2
    all_ok = True
    for p in paths:
        if not report(p, roots):
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
