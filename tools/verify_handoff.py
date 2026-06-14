#!/usr/bin/env python3
"""verify_handoff.py — P5: prove tabernacle hands off to the payload ONLY through
a hash gate (the authenticity half of the tabernacle safety claim, T1).

tabernacle is the one fam-family binary that deliberately transfers control OUT
of its own image: after loading `full_node` (from disk or net) it `j end_marker`,
where `end_marker` = the byte just past the image = the entry of the appended,
attacker-controlled payload.  verify_fsm's P2 reports those jumps as "out of
code" — correctly, they ARE exits.  This pass takes ownership of them and proves
they are *gated*.

The CFG is static (no jalr — see verify_fsm/P1), so the set of paths is fixed.
An EXIT is a static jal/branch/fall-through whose target is exactly `n` (the file
size = end_marker).  For each exit site x we prove:

  P5a (machine-checked)  GATED-EXIT DOMINANCE.  There is a conditional branch B
      with B dom x such that EXACTLY ONE of B's two successors dominates x.  That
      successor is the only way the exit is reached, so every path to the payload
      — including after net-retry loops — leaves B on the same (hash-equal) edge
      on its final traversal.  The other successor is the reject/mismatch path,
      which is NOT forced (it may halt, or, on the net path, retry through B
      again).  We report B (the gate) for each exit.

      Soundness note: "reject side can't reach ANY exit" would be WRONG here — the
      disk reject falls into the net path (its own exit) and the net reject loops
      back to re-check.  Per-exit dominance is the property that actually holds:
      x is reached only via B's dominating edge, whatever the reject side does.

  P5b (inspected residual)  GATE SEMANTICS.  That the gate branch B is the
      compare of the freshly-computed gimli_hash(payload) against the sealed
      `hash_data` constant (image bytes [n-32, n)), over all 32 bytes, branching
      away on any inequality.  Confirmed by reading src/tabernacle.S (hash_cmp
      §4, lines ~451-477; net_hash_cmp §5, lines ~1120-1146).  A future tightening
      can machine-check this by recognising B's operands as a load from the
      gimli scratch and a load from the in-image hash_data region.

Together with verify_packed (the running binary IS the sealed image) and the
P5b inspection, this discharges T1: control reaches the payload iff its hash
matches the sealed hash — modulo the Gimli-Hash preimage assumption.

Usage: verify_handoff.py [--quiet] [--selftest] BINARY [BINARY ...]
Exit:  0 = all exits gated (or none present), 1 = an ungated exit, 2 = usage.
"""

import sys

from verify_fsm import decode


# --------------------------------------------------------------------------
# CFG with edges + exit detection
# --------------------------------------------------------------------------
class CFG:
    def __init__(self, n):
        self.n = n                 # file size = end_marker offset
        self.reached = set()       # reachable instruction offsets (nodes)
        self.succ = {}             # off -> [in-code successor offsets]
        self.branch = {}           # off -> (fallthrough|None, taken|None) for cond branches
        self.exits = []            # [(kind, off)] sites that transfer to the payload (==n)
        self.bad = []              # [(off, msg)] illegal/out-of-code — run verify_fsm first


def build_cfg(data, entry=0):
    n = len(data)
    g = CFG(n)

    def word(o):
        return int.from_bytes(data[o:o + 4], "little")

    def in_code(o):
        return 0 <= o and o + 4 <= n and o % 4 == 0

    if not in_code(entry):
        g.bad.append((entry, "entry not in code (empty/truncated image)"))
        return g

    stack = [entry]
    while stack:
        pc = stack.pop()
        if pc in g.reached:
            continue
        g.reached.add(pc)
        d = decode(word(pc))
        if not d["legal"]:
            g.bad.append((pc, "P1 " + d["name"]))
            g.succ[pc] = []
            continue
        k = d["kind"]
        s = []
        if k == "jal":
            tgt = pc + d["imm"]
            if tgt == n:
                g.exits.append(("jal", pc))
            elif in_code(tgt):
                s.append(tgt)
            else:
                g.bad.append((pc, f"P2 jal target out of code -> {tgt:#x}"))
            if d["rd"] != 0:                       # call-style: also reaches return point
                nxt = pc + 4
                if nxt == n:
                    g.exits.append(("fallthrough", pc))
                elif in_code(nxt):
                    s.append(nxt)
        elif k == "branch":
            tgt = pc + d["imm"]
            nxt = pc + 4
            ft = nxt if in_code(nxt) else None
            tk = tgt if in_code(tgt) else None
            if nxt == n:
                g.exits.append(("branch-ft", pc)); ft = None
            elif not in_code(nxt):
                g.bad.append((pc, f"P2 fallthrough out of code -> {nxt:#x}"))
            if tgt == n:
                g.exits.append(("branch-taken", pc)); tk = None
            elif not in_code(tgt):
                g.bad.append((pc, f"P2 branch target out of code -> {tgt:#x}"))
            g.branch[pc] = (ft, tk)
            for t in (ft, tk):
                if t is not None:
                    s.append(t)
        else:
            nxt = pc + 4
            if nxt == n:
                g.exits.append(("fallthrough", pc))
            elif in_code(nxt):
                s.append(nxt)
            # else: fall off the end past the image -> terminal halt, not an exit
        g.succ[pc] = s
        for t in s:
            stack.append(t)
    return g


# --------------------------------------------------------------------------
# dominators (iterative dataflow over the reachable CFG)
# --------------------------------------------------------------------------
def dominators(g, entry=0):
    nodes = g.reached
    preds = {x: [] for x in nodes}
    for u in nodes:
        for v in g.succ.get(u, ()):
            if v in preds:
                preds[v].append(u)
    dom = {x: set(nodes) for x in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for x in nodes:
            if x == entry:
                continue
            ps = preds[x]
            if ps:
                inter = set(nodes)
                for p in ps:
                    inter &= dom[p]
            else:
                inter = set()           # unreachable-but-in-set guard (shouldn't happen)
            new = {x} | inter
            if new != dom[x]:
                dom[x] = new
                changed = True
    return dom


# --------------------------------------------------------------------------
# P5a: each exit is gated
# --------------------------------------------------------------------------
def find_gates(g, dom, x):
    """Conditional branches B that gate exit-site x:
       B dom x, and EXACTLY ONE of B's two successors dominates x."""
    gates = []
    for B, (ft, tk) in g.branch.items():
        if x not in dom or B not in dom[x]:
            continue                                  # B must dominate x
        f_dom = ft is not None and ft in dom[x]
        t_dom = tk is not None and tk in dom[x]
        if f_dom != t_dom:                            # exactly one successor dominates x
            keep = ft if f_dom else tk
            gates.append((B, keep))
    return gates


# --------------------------------------------------------------------------
# P5b: the dominating gate is the full-width hash compare
# --------------------------------------------------------------------------
# P5a proves a branch B dominates the handoff; it does NOT look at what B
# compares.  A gate that checked one byte, or compared the wrong buffer, would
# pass P5a.  P5b mechanizes the gate SEMANTICS: that B is the equality test of a
# freshly computed gimli_hash digest against the sealed 32-byte `hash_data`
# (the 32 bytes at [gp-32, gp), immediately before the payload), compared over
# ALL 32 bytes, with the handoff reached only on full equality.
#
# The gate is a counted compare loop (identical in the disk and net paths):
#       j gimli_hash                 # CALL: digest -> [sp, sp+32)
#       ...                          # CALL return
#   B-20:  addi p0, sp, 0            # p0 = sp        (the digest buffer)
#   B-16:  addi p1, gp, -32          # p1 = gp-32     (the sealed hash_data)
#   B-12:  addi C,  x0, 8            # count = 8 words
#   B-8 :  lw   A,  0(p0)            # header / back-edge target
#   B-4 :  lw   Bb, 0(p1)
#   B   :  bne  A,  Bb, reject       # THE GATE (mismatch -> reject)
#   B+4 :  addi p0, p0, 4
#   B+8 :  addi p1, p1, 4
#   B+12:  addi C,  C,  -1
#   B+16:  bne  C,  x0, header       # back-edge (loop while C != 0)
#       ...                          # fall through all 8 -> j end_marker
# 8 words x 4 bytes = 32 = the full hash; p1 sweeps exactly [gp-32, gp).
SP_, GP_, X0_ = 2, 3, 0


def _fields(w):
    """Decode the RV32I fields P5b needs (rd/rs1/rs2 + I/B/J immediates)."""
    iimm = w >> 20
    if iimm & 0x800:
        iimm -= 0x1000
    bimm = (((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) \
        | (((w >> 25) & 0x3f) << 5) | (((w >> 8) & 0xf) << 1)
    if bimm & 0x1000:
        bimm -= 0x2000
    jimm = (((w >> 31) & 1) << 20) | (((w >> 12) & 0xff) << 12) \
        | (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3ff) << 1)
    if jimm & 0x100000:
        jimm -= 0x200000
    return {"op": w & 0x7f, "rd": (w >> 7) & 0x1f, "f3": (w >> 12) & 7,
            "rs1": (w >> 15) & 0x1f, "rs2": (w >> 20) & 0x1f,
            "iimm": iimm, "bimm": bimm, "jimm": jimm}


def gate_semantics(data, B, keep):
    """P5b for one gate B (with P5a's dominating successor `keep`).  Returns
    {ok, reason, bytes, sealed_off, gimli_call}."""
    n = len(data)
    R = {"ok": False, "reason": "", "bytes": None, "sealed_off": None,
         "gimli_call": None}

    def F(o):
        return _fields(int.from_bytes(data[o:o + 4], "little")) \
            if 0 <= o and o + 4 <= n else None

    def is_addi(f, rd=None, rs1=None, imm=None):
        return f and f["op"] == 0x13 and f["f3"] == 0 \
            and (rd is None or f["rd"] == rd) and (rs1 is None or f["rs1"] == rs1) \
            and (imm is None or f["iimm"] == imm)

    fb = F(B)
    if not (fb and fb["op"] == 0x63 and fb["f3"] == 1):
        R["reason"] = "innermost gate is not a `bne` (inequality reject)"; return R
    # the PASSING edge must be the equal/fall-through side (B+4); the taken side
    # is the mismatch -> reject.  (P5a says one successor dominates; P5b pins it
    # to the equality side, so equality is REQUIRED to proceed.)
    if keep != B + 4:
        R["reason"] = "passing edge is branch-taken, not the equality fall-through"; return R
    A, Bb = fb["rs1"], fb["rs2"]
    l1, l2 = F(B - 8), F(B - 4)                       # lw A,0(p0) ; lw Bb,0(p1)
    if not (l1 and l1["op"] == 0x03 and l1["f3"] == 2 and l1["rd"] == A and l1["iimm"] == 0):
        R["reason"] = "compare lhs is not `lw A,0(p0)` directly before the gate"; return R
    if not (l2 and l2["op"] == 0x03 and l2["f3"] == 2 and l2["rd"] == Bb and l2["iimm"] == 0):
        R["reason"] = "compare rhs is not `lw B,0(p1)` directly before the gate"; return R
    p0, p1, header = l1["rs1"], l2["rs1"], B - 8
    # back-edge: a `bne C,x0,header` in the loop body -> the counter C
    C = back = None
    for o in range(B + 4, min(B + 40, n), 4):
        f = F(o)
        if f and f["op"] == 0x63 and f["f3"] == 1 and f["rs2"] == X0_ and o + f["bimm"] == header:
            C, back = f["rs1"], o; break
    if C is None:
        R["reason"] = "no `bne C,x0,header` back-edge — not a counted compare loop"; return R

    def find(rng, **kw):
        for o in rng:
            if is_addi(F(o), **kw):
                return F(o)
        return None

    body = range(B + 4, back + 4, 4)
    s0 = find(body, rd=p0, rs1=p0)                    # addi p0,p0,stride
    s1 = find(body, rd=p1, rs1=p1)                    # addi p1,p1,stride
    dec = find(body, rd=C, rs1=C)                     # addi C,C,-1
    if not (s0 and s1 and dec):
        R["reason"] = "missing cursor-advance / counter-decrement in the loop body"; return R
    if dec["iimm"] != -1:
        R["reason"] = f"counter decrement is {dec['iimm']}, not -1"; return R
    pro = range(header - 24, header, 4)
    ic = find(pro, rd=C, rs1=X0_)                     # li C,N  (= addi C,x0,N)
    ip1 = find(pro, rd=p1, rs1=GP_)                   # addi p1,gp,IMM
    ip0 = find(pro, rd=p0, rs1=SP_, imm=0)            # mv p0,sp
    if not (ic and ip1 and ip0):
        R["reason"] = "prologue does not set count=li, p1=gp+imm, p0=sp"; return R
    N = ic["iimm"]
    if not (N > 0 and s0["iimm"] == 4 and s1["iimm"] == 4):
        R["reason"] = f"non-4-byte stride or non-positive count (N={N}, " \
                      f"strides {s0['iimm']}/{s1['iimm']})"; return R
    nbytes = N * 4
    if nbytes != 32:
        R["reason"] = f"compares {nbytes} bytes, not the full 32-byte hash"; return R
    if ip1["iimm"] != -32:
        R["reason"] = f"sealed-hash cursor base is gp{ip1['iimm']:+d}, not gp-32"; return R
    # provenance: a gimli_hash CALL (`j gimli_hash` = jal x0) precedes the prologue,
    # so [sp, sp+32) is the freshly computed digest the loop then compares.
    for o in range(header - 44, header, 4):
        f = F(o)
        if f and f["op"] == 0x6f and f["rd"] == X0_:
            R["gimli_call"] = (o, o + f["jimm"])
    if R["gimli_call"] is None:
        R["reason"] = "no gimli_hash CALL precedes the compare (digest provenance)"; return R
    R["ok"], R["bytes"], R["sealed_off"] = True, nbytes, ip1["iimm"]
    return R


class Result:
    def __init__(self):
        self.exits = []          # [(kind, site, [gate_addrs], innermost)]
        self.ungated = []        # [(kind, site)]
        self.p5b = []            # [(site, innermost, sem_dict)]
        self.bad = []

    @property
    def ok(self):               # P5a: every exit gated, image P1/P2-clean
        return not self.ungated and not self.bad

    @property
    def p5b_ok(self):           # P5b: every gate is the full 32-byte hash compare
        return self.ok and bool(self.exits) and all(s["ok"] for _, _, s in self.p5b)


def verify_bytes(data, entry=0):
    g = build_cfg(data, entry)
    r = Result()
    r.bad = list(g.bad)
    if g.bad:
        return r, g
    dom = dominators(g, entry)
    for kind, site in g.exits:
        pairs = find_gates(g, dom, site)
        gates = [b for b, _ in pairs]
        # All dominators of `site` lie on one dominator-tree chain, so the gates
        # are linearly ordered; the INNERMOST (most dominators => closest to the
        # exit) is the one P5b must confirm is the hash compare.  If anything
        # between it and the exit re-introduced an ungated path, a tighter gate
        # would not exist and this one would not dominate the exit.
        innermost = max(gates, key=lambda b: len(dom[b])) if gates else None
        r.exits.append((kind, site, gates, innermost))
        if not gates:
            r.ungated.append((kind, site))
        else:
            keep = next(k for b, k in pairs if b == innermost)
            r.p5b.append((site, innermost, gate_semantics(data, innermost, keep)))
    return r, g


def verify_file(path, entry=0):
    with open(path, "rb") as f:
        return verify_bytes(f.read(), entry)


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def report(path, r, g, quiet=False):
    if not quiet:
        print(f"{path}")
        print(f"  size: {g.n} B   end_marker (payload entry): +{g.n:#06x}")
        if r.bad:
            print("  !! cannot run P5 — image is not P1/P2-clean (run verify_fsm):")
            for off, msg in r.bad[:10]:
                print(f"       +{off:#06x}  {msg}")
        elif not r.exits:
            print("  no handoff exits (no jump to end_marker) — nothing to gate.")
        else:
            print(f"  handoff exits to payload: {len(r.exits)}")
            for kind, site, gates, innermost in r.exits:
                if gates:
                    print(f"    +{site:#06x}  ({kind})  GATED — innermost gate "
                          f"+{innermost:#06x}  ({len(gates)} dominating guard(s) total)")
                else:
                    print(f"    +{site:#06x}  ({kind})  !! UNGATED — no dominating hash gate")
        print(f"  P5a (gated-exit dominance):  {'PASS' if r.ok else 'FAIL'}")
        if r.ok and r.exits:
            print(f"  P5b (gate is the full 32-byte gimli_hash vs sealed hash_data compare): "
                  f"{'PASS' if r.p5b_ok else 'FAIL'}")
            for site, B, s in r.p5b:
                if s["ok"]:
                    gc = s["gimli_call"]
                    print(f"    +{B:#06x}  gate compares {s['bytes']} B "
                          f"[sp,sp+32) vs [gp{s['sealed_off']:+d}, gp) "
                          f"(gimli_hash CALL +{gc[0]:#06x}) -> handoff +{site:#06x}")
                else:
                    print(f"    +{B:#06x}  !! P5b FAIL: {s['reason']}")
    if r.p5b_ok:
        print("  => PROVEN: every handoff is hash-gated (P5a) AND each gate is the "
              "full 32-byte hash compare (P5b); T1 modulo the gimli_hash routine + crypto")
    elif r.ok:
        print("  => P5a PROVEN (every handoff hash-gated); P5b FAILED (gate semantics)")
    else:
        bad = len(r.ungated) + len(r.bad)
        print(f"  => VIOLATION ({bad} finding(s))")
    # Success requires P5b when there ARE handoffs (the full gate proof); with no
    # handoff there is nothing to gate, so P1/P2-cleanliness (r.ok) suffices.
    return r.p5b_ok if r.exits else r.ok


# --------------------------------------------------------------------------
# self-test: the prover must REJECT ungated exits
# --------------------------------------------------------------------------
def selftest():
    le = lambda w: w.to_bytes(4, "little")
    NOP = 0x00000013
    HALT = 0x0000006f               # jal x0, 0  (self-loop)

    def jal_to(off_from, target_off):
        return 0x6f | (_enc_jimm(target_off - off_from))

    def _enc_jimm(imm):
        i = imm & 0x1fffff
        return (((i >> 20) & 1) << 31) | (((i >> 1) & 0x3ff) << 21) \
            | (((i >> 11) & 1) << 20) | (((i >> 12) & 0xff) << 12)

    def bne(off_from, target_off, rs1=5, rs2=6):
        imm = (target_off - off_from) & 0x1fff
        enc = (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) \
            | (rs2 << 20) | (rs1 << 15) | (1 << 12) | (((imm >> 1) & 0xf) << 8) \
            | (((imm >> 11) & 1) << 7) | 0x63
        return enc

    def addi(rd, rs1, imm):
        return ((imm & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13

    def lw(rd, rs1, imm):
        return ((imm & 0xfff) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03

    def gate_image(count=8, sealed=-32):
        # The real hash-compare idiom: `j .+4` (provenance marker) ; p0=sp ;
        # p1=gp+sealed ; count=N ; [hdr] lw t3,0(p0); lw t4,0(p1); bne->reject ;
        # advance/decrement ; back-edge ; j end_marker ; reject:halt.  Handoff at
        # 44 -> n=52.  Any (count,sealed) still passes P5a (the compare bne gates
        # the exit); only count=8 & sealed=-32 (== 32 bytes vs [gp-32,gp)) is P5b.
        sp, gp, t0, t1, t2, t3, t4 = 2, 3, 5, 6, 7, 28, 29
        return b"".join(le(w) for w in [
            jal_to(0, 4), addi(t0, sp, 0), addi(t1, gp, sealed), addi(t2, 0, count),
            lw(t3, t0, 0), lw(t4, t1, 0), bne(24, 48, t3, t4),
            addi(t0, t0, 4), addi(t1, t1, 4), addi(t2, t2, -1), bne(40, 16, t2, 0),
            jal_to(44, 52), HALT])

    cases = []

    # 1. GATED: nop ; bne t0,t1,reject ; j n(exit) ; reject: halt    -> PASS
    #    layout: [0]nop [4]bne->+12 [8]j->n(=16) [12]halt
    g1 = bytes()
    img1 = le(NOP) + le(bne(4, 12)) + le(jal_to(8, 16)) + le(HALT)
    cases.append(("gated exit", img1, True))

    # 2. UNGATED: nop ; j n(exit)                                     -> FAIL
    #    [0]nop [4]j->n(=8)
    img2 = le(NOP) + le(jal_to(4, 8))
    cases.append(("ungated jump-to-payload", img2, False))

    # 3. BOTH-SIDES-REACH-ONE-EXIT: a branch whose taken AND fall-through arms
    #    both flow to a SINGLE common exit C.  Neither arm dominates C, so the
    #    branch does not gate it -> the exit is ungated -> FAIL.
    #    [0]bne->+8(=8)  [4]j->C(=12)  [8]j->C(=12)  [12]C: j->n(=16)
    img3 = le(bne(0, 8)) + le(jal_to(4, 12)) + le(jal_to(8, 12)) + le(jal_to(12, 16))
    cases.append(("branch with both arms reaching one exit", img3, False))

    # 4. empty image (non-vacuity): must NOT vacuously pass
    cases.append(("empty image", b"", False))

    ok = True
    for name, blob, expect in cases:
        r, _g = verify_bytes(blob)
        got = r.ok
        verdict = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest P5a {name:32s} expect={'PASS' if expect else 'FAIL'}  "
              f"got={'PASS' if got else 'FAIL'}  [{verdict}]")

    # P5b non-vacuity: the gate idiom must verify ONLY when it compares the full
    # 32 bytes against [gp-32, gp).  The two FAIL cases still pass P5a (the gate
    # dominates the handoff) -- so they prove P5b adds real semantics on top.
    p5b_cases = [
        ("full 32 B vs gp-32",       gate_image(count=8, sealed=-32), True),
        ("truncated: 1 word (4 B)",  gate_image(count=1, sealed=-32), False),
        ("wrong sealed base gp-16",  gate_image(count=8, sealed=-16), False),
    ]
    for name, blob, expect in p5b_cases:
        r, _g = verify_bytes(blob)
        assert r.ok, f"P5b case {name!r} should still pass P5a"   # all gate P5a
        got = r.p5b_ok
        verdict = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest P5b {name:32s} expect={'PASS' if expect else 'FAIL'}  "
              f"got={'PASS' if got else 'FAIL'}  [{verdict}]")
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------
def main(argv):
    quiet = False
    paths = []
    for a in argv:
        if a == "--quiet": quiet = True
        elif a == "--selftest": return 0 if selftest() else 2
        elif a in ("-h", "--help"): print(__doc__); return 0
        elif a.startswith("-"): sys.exit(f"verify_handoff: unknown option: {a}")
        else: paths.append(a)
    if not paths:
        print(__doc__); return 2
    all_ok = True
    for p in paths:
        r, g = verify_file(p)
        if not report(p, r, g, quiet):
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
