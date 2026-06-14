#!/usr/bin/env python3
"""verify_wx.py — P3: prove a fam binary never stores into its own code (W^X),
modulo declared self-modifying trampoline slots.

This is the pass that makes P1/P2 valid at RUNTIME: if the code is immutable, the
static "no jalr / closed CFG" proof cannot be undone by a store that writes a
`jalr` into the instruction stream.

It is a CONTEXT-SENSITIVE, SET-VALUED provenance abstract-interpreter over the
finite CFG. Each register maps to a SET of possible provenance tags (so distinct
sources -- e.g. an output pointer on one path and a trampoline code address on
another -- are not lost to a single TOP):

    R(root,off)  region pointer = a designated root register + constant offset
    RG           region pointer, root/offset unknown (joined, or a loaded cursor)
    C(v)         an exact constant
    CODE(a)      a PC-derived address `a` (auipc / LOAD_ADDRESS), in the code image
    INPUT        a value loaded from memory (not a known pointer slot)
    TOP          unknown

A store `s{b,h,w} rs, off(base)` is SAFE iff EVERY tag the base may hold is:
  * a region pointer (R/RG), or
  * a constant whose address is OUTSIDE the code image (MMIO 0x10000000 / 0x100000), or
  * a DECLARED TRAMPOLINE: a code address that statically holds `j .` (jal x0,0).
fam patches exactly these `j .` placeholder slots (e.g. `imm_tramp`) to dispatch
immediate words without `jalr` -- the one intentional self-modification. Any other
code-reaching, loaded, or unknown base is FLAGGED.

Ingredients that make it precise enough for fam:
  * INTERPROCEDURAL: calls are `push RID; j body` (return site one word after the
    `j`, via EMIT_CALL), returning through `j __dispatch`. We match call->return
    and apply a per-routine CLOBBER summary, so a caller-saved region pointer that
    survives a call is preserved, not merged to TOP through the shared dispatcher.
  * CURSOR SLOTS: a load from a root-relative slot that ONLY ever receives
    region-pointer stores yields a region pointer (call-site / name-table cursors).
  * ROOT AXIOM: the region pointers below hold addresses >= code_end for the whole
    run -- true by construction in fam's _start (every root = `data` label + a
    positive offset; `data` = end-of-code) and kept so by CHECK_HEAP. P4 verifies
    the roots are never corrupted; P3 assumes it.

SCOPE: clean for the COMPILER chain (its only self-modification is the imm_tramp
trampoline). A compiled PROGRAM that uses `variable`/user `!` has data-dependent
store targets -- flagged as "not statically W^X", the explicit escape hatch.

Usage: verify_wx.py [--roots prog|compiler] [--selftest] BINARY ...
Exit:  0 = W^X PROVEN (modulo declared trampolines), 1 = a store unproven, 2 = self-test.
"""

import sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from verify_fsm import decode, verify_bytes

LOAD = 0x80000000
MAXSET = 8                                          # cap set size; overflow -> TOP

S0, S1, S2, S3 = 8, 9, 18, 19
SP, GP, TP, S6, S7, S8, S9, S10, S11 = 2, 3, 4, 22, 23, 24, 25, 26, 27
T0, T1 = 5, 6
ROOTS_COMPILER = {S0, S1, S2, S3, SP, GP, TP, S6, S7, S8, S9, S10, S11}
ROOTS_PROGRAM  = {SP, GP, S8, S10, S11}
RN = {0:'zero',1:'ra',2:'sp',3:'gp',4:'tp',5:'t0',6:'t1',7:'t2',8:'s0',9:'s1',
      10:'a0',11:'a1',12:'a2',13:'a3',14:'a4',15:'a5',16:'a6',17:'a7',18:'s2',
      19:'s3',20:'s4',21:'s5',22:'s6',23:'s7',24:'s8',25:'s9',26:'s10',27:'s11',
      28:'t3',29:'t4',30:'t5',31:'t6'}

S32 = lambda v: ((v + 0x80000000) & 0xffffffff) - 0x80000000
TOP = ('TOP',); INPUT = ('INPUT',); RG = ('RG',)
def is_region(t): return t[0] in ('R', 'RG')


def cap(s):
    s = frozenset(s)
    return frozenset({TOP}) if len(s) > MAXSET else s

def join_set(a, b):
    return cap((a or frozenset()) | (b or frozenset()))

def join_map(m1, m2):
    out = dict(m1)
    for k, v in m2.items():
        nv = join_set(out.get(k), v)
        if nv: out[k] = nv
    return out


def _iimm(w):
    v = (w >> 20) & 0xfff
    return v - (1 << 12) if v & 0x800 else v

def _simm(w):
    v = ((w >> 25) & 0x7f) << 5 | ((w >> 7) & 0x1f)
    return v - (1 << 12) if v & 0x800 else v

def written_reg(w):
    op = w & 0x7f
    rd = (w >> 7) & 0x1f
    if rd == 0: return None
    if op in (0x37, 0x17, 0x13, 0x33, 0x03, 0x6f): return rd
    return None


def add_tag(a, b):
    if a[0] == 'R' and b[0] == 'C': return ('R', a[1], a[2] + b[1])
    if b[0] == 'R' and a[0] == 'C': return ('R', b[1], b[2] + a[1])
    if a == RG and b[0] == 'C': return RG
    if b == RG and a[0] == 'C': return RG
    if a[0] == 'C' and b[0] == 'C': return ('C', S32(a[1] + b[1]))
    if a[0] == 'CODE' and b[0] == 'C': return ('CODE', a[1] + b[1])
    if b[0] == 'CODE' and a[0] == 'C': return ('CODE', b[1] + a[1])
    # adding a constant to a loaded/unknown value keeps its kind (offset pointer)
    if a[0] == 'INPUT' and b[0] == 'C': return INPUT
    if b[0] == 'INPUT' and a[0] == 'C': return INPUT
    return TOP

def sub_tag(a, b):
    if a[0] == 'R' and b[0] == 'C': return ('R', a[1], a[2] - b[1])
    if a[0] == 'R' and b[0] == 'R' and a[1] == b[1]: return ('C', S32(a[2] - b[2]))
    if a[0] == 'C' and b[0] == 'C': return ('C', S32(a[1] - b[1]))
    if a[0] == 'CODE' and b[0] == 'C': return ('CODE', a[1] - b[1])
    if a[0] == 'INPUT' and b[0] == 'C': return INPUT
    return TOP


class WxResult:
    def __init__(self):
        self.size = 0; self.stores = 0; self.flags = []
        self.ptr_slots = 0; self.tramps = set(); self.tramp_offs = set()
    @property
    def ok(self):
        return not self.flags


def analyze(data, roots):
    n = len(data)
    code_lo, code_hi = LOAD, LOAD + n
    r = verify_bytes(data)
    reached = r.reached
    word = lambda off: int.from_bytes(data[off:off+4], "little")
    dec = {off: decode(word(off)) for off in reached if decode(word(off))["legal"]}
    TRAMP = {LOAD + off for off in reached if word(off) == 0x0000006f}   # `j .` slots

    # ---- structure: dispatch entries, calls, return sites ----
    dispatch = {off for off in reached
                if (word(off) & 0x7f) == 0x03 and ((word(off) >> 12) & 7) == 2
                and ((word(off) >> 15) & 0x1f) == S11 and ((word(off) >> 7) & 0x1f) == T0
                and _iimm(word(off)) == 0}
    calls, retsites = {}, {}
    for off in reached:
        d = dec.get(off)
        if not d or d["kind"] != "jal" or d["rd"] != 0:
            continue
        pw = word(off - 4)
        if (off - 4) in reached and (pw & 0x7f) == 0x23 and ((pw >> 15) & 0x1f) == S11:
            body, ret = off + d["imm"], off + 4
            if body in reached and ret in reached:
                calls[off] = (body, ret); retsites[ret] = off

    def is_ret(off):
        d = dec.get(off)
        return d and d["kind"] == "jal" and d["rd"] == 0 and (off + d["imm"]) in dispatch

    bodies = {0} | {b for (b, _) in calls.values()}
    def block_set(entry):
        seen, stack, nested = set(), [entry], []
        while stack:
            pc = stack.pop()
            if pc in seen or pc not in reached: continue
            seen.add(pc)
            if pc in dispatch or is_ret(pc): continue
            if pc in calls:
                body, ret = calls[pc]; nested.append(body); stack.append(ret); continue
            d = dec.get(pc)
            if not d: continue
            if d["kind"] == "jal": stack.append(pc + d["imm"])
            elif d["kind"] == "branch": stack += [pc + d["imm"], pc + 4]
            else: stack.append(pc + 4)
        return seen, nested
    blocks = {b: block_set(b) for b in bodies}

    clob = {b: set() for b in bodies}
    changed = True
    while changed:
        changed = False
        for b, (insset, nested) in blocks.items():
            c = {w for pc in insset if (w := written_reg(word(pc))) is not None}
            for nb in nested: c |= clob.get(nb, set())
            c |= {T0, T1}; c -= roots
            if c != clob[b]: clob[b] = c; changed = True

    # ---- transfer ----
    def readtag(reg, m):
        if reg == 0:     return frozenset({('C', 0)})
        if reg in roots: return frozenset({('R', reg, 0)})
        return m.get(reg, frozenset())

    def transfer(pc, m, ptr):
        w = word(pc); op = w & 0x7f
        rd = (w >> 7) & 0x1f; rs1 = (w >> 15) & 0x1f; rs2 = (w >> 20) & 0x1f; f3 = (w >> 12) & 7
        out = dict(m)
        def setrd(s):
            if rd == 0 or rd in roots: return
            s = cap(s)
            if s: out[rd] = s
            else: out.pop(rd, None)
        if op == 0x37:
            setrd({('C', S32(((w >> 12) & 0xfffff) << 12))})
        elif op == 0x17:
            setrd({('CODE', LOAD + pc)})
        elif op == 0x13:
            a = readtag(rs1, m); k = _iimm(w)
            if f3 == 0:
                setrd({add_tag(t, ('C', k)) for t in a})
            else:
                setrd({TOP})
        elif op == 0x33:
            a = readtag(rs1, m); b = readtag(rs2, m); f7 = (w >> 25) & 0x7f
            if f3 == 0 and f7 == 0:
                setrd({add_tag(x, y) for x in a for y in b})
            elif f3 == 0 and f7 == 0x20:
                setrd({sub_tag(x, y) for x in a for y in b})
            else:
                setrd({TOP})
        elif op == 0x03:
            base = readtag(rs1, m)
            if f3 == 2 and base and all(t[0] == 'R' and (t[1], t[2] + _iimm(w)) in ptr for t in base):
                setrd({RG})
            else:
                setrd({INPUT})
        elif op == 0x6f:
            if rd != 0: setrd({('CODE', LOAD + pc + 4)})
        elif op in (0x63, 0x23, 0x0f):
            pass
        else:
            setrd({TOP})
        return out

    def apply_clobber(m, c):
        out = dict(m)
        for rg in c:
            if rg not in roots: out[rg] = frozenset({TOP})
        return out

    def successors(pc, in_state, ptr):
        if pc in calls:
            body, ret = calls[pc]
            return [(body, in_state),
                    (ret, apply_clobber(in_state, clob.get(body, set()) | {T0, T1}))]
        if pc in dispatch or is_ret(pc):
            return []
        out = transfer(pc, in_state, ptr); d = dec.get(pc); k = d["kind"] if d else None
        if k == "jal":      outs = [(pc + d["imm"], out)]
        elif k == "branch": outs = [(pc + d["imm"], out), (pc + 4, out)]
        else:               outs = [(pc + 4, out)]
        return [(s, st) for (s, st) in outs if s in reached and s not in retsites]

    def run_dataflow(ptr):
        st = {0: {}}; work = [0]
        while work:
            pc = work.pop()
            for s, stt in successors(pc, st[pc], ptr):
                merged = join_map(st.get(s, {}), stt)
                if merged != st.get(s): st[s] = merged; work.append(s)
        return st

    # ---- pointer-slot fixpoint (cursors): ground on a genuine root store, drop
    #      any slot left with an unresolved (non-region) store ----
    def all_region(vs): return bool(vs) and all(is_region(t) for t in vs)
    st0 = run_dataflow(set())
    grounded, defbad = set(), set()
    for off in reached:
        w = word(off)
        if (w & 0x7f) != 0x23: continue
        base = readtag((w >> 15) & 0x1f, st0.get(off, {}))
        if not (base and all(t[0] == 'R' for t in base)): continue
        for bt in base:
            slot = (bt[1], bt[2] + _simm(w)); val = readtag((w >> 20) & 0x1f, st0.get(off, {}))
            if ((w >> 12) & 7) != 2: defbad.add(slot)
            elif all_region(val): grounded.add(slot)
            elif all(t == INPUT for t in val): pass
            else: defbad.add(slot)
    PTR = grounded - defbad
    state = st0
    while True:
        state = run_dataflow(PTR)
        residual = set()
        for off in reached:
            w = word(off)
            if (w & 0x7f) != 0x23 or ((w >> 12) & 7) != 2: continue
            base = readtag((w >> 15) & 0x1f, state.get(off, {}))
            if not (base and all(t[0] == 'R' for t in base)): continue
            for bt in base:
                slot = (bt[1], bt[2] + _simm(w))
                if slot in PTR and not all_region(readtag((w >> 20) & 0x1f, state.get(off, {}))):
                    residual.add(slot)
        if not residual: break
        PTR -= residual

    # ---- store check ----
    def classify(tag, off):
        if is_region(tag): return 'safe'
        if tag[0] == 'C':
            a = (tag[1] + off) & 0xffffffff
            if a in TRAMP: return ('tramp', a)
            return 'bad' if code_lo <= a < code_hi else 'safe'
        if tag[0] == 'CODE':
            a = tag[1] + off
            if a in TRAMP: return ('tramp', a)
            return 'bad' if code_lo <= a < code_hi else 'safe'
        return 'unprov'

    res = WxResult(); res.size = n; res.ptr_slots = len(PTR)
    res.state = state; res.readtag = readtag; res.ptr = PTR   # exposed for P4 (verify_cfi)
    for off in sorted(reached):
        w = word(off)
        if (w & 0x7f) != 0x23: continue
        res.stores += 1
        base = readtag((w >> 15) & 0x1f, state.get(off, {})); soff = _simm(w)
        sz = {0: 'sb', 1: 'sh', 2: 'sw'}.get((w >> 12) & 7, 's?')
        if not base:
            res.flags.append((off, w, RN[(w >> 15) & 0x1f], f"{sz} via an undefined register")); continue
        verdicts = [classify(t, soff) for t in base]
        bad = [v for v in verdicts if v == 'bad']
        unp = [v for v in verdicts if v == 'unprov']
        for v in verdicts:
            if isinstance(v, tuple): res.tramps.add(v[1]); res.tramp_offs.add(off)
        if bad:
            res.flags.append((off, w, RN[(w >> 15) & 0x1f], f"{sz} INSIDE code image (not a trampoline slot)"))
        elif unp:
            res.flags.append((off, w, RN[(w >> 15) & 0x1f], f"{sz} via an unprovable / loaded pointer"))
    return res


# --------------------------------------------------------------------------
def report(path, res):
    print(f"{path}")
    print(f"  size: {res.size} B   reachable stores: {res.stores}   "
          f"pointer-slots: {res.ptr_slots}   flagged: {len(res.flags)}")
    for off, w, base, msg in res.flags[:40]:
        print(f"    !! +{off:#06x}  {w:08x}  base={base:4s}  {msg}")
    if len(res.flags) > 40:
        print(f"    ... and {len(res.flags) - 40} more")
    if res.tramps:
        ts = ", ".join(f"{a:#x}" for a in sorted(res.tramps))
        print(f"  declared self-modifying trampoline slot(s): {ts}")
    if res.ok:
        if res.tramps:
            print(f"  => W^X PROVEN modulo {len(res.tramps)} declared trampoline slot(s) "
                  f"(each a `j .` placeholder patched to `j <entry>`)")
        else:
            print("  => W^X PROVEN: every store targets a region pointer or MMIO; none can reach code")
    else:
        print(f"  => NOT PROVEN: {len(res.flags)} store(s) with an unprovable / code-reaching base")
    return res.ok


def selftest():
    le = lambda w: w.to_bytes(4, "little")
    NOP = 0x00000013
    cases = [
        ("store via gp",          le(0x00512023) + le(0x0000006f), ROOTS_COMPILER, True),
        ("store via auipc(code)",  le(0x00000297) + le(0x0002a023) + le(0x0000006f), ROOTS_COMPILER, False),
        ("store via loaded ptr",   le(0x00012283) + le(0x0002a023) + le(0x0000006f), ROOTS_COMPILER, False),
        ("store via MMIO const",   le(0x100002b7) + le(0x0002a023) + le(0x0000006f), ROOTS_COMPILER, True),
        # patch a `j .` trampoline slot: auipc a0,0; addi a0,a0,8; sw zero,0(a0); j .; <slot j.>
        # auipc a0,0; addi a0,a0,12; sw zero,0(a0); <offset12: j .>  -> patches a reached `j .` slot
        ("patch trampoline slot",  le(0x00000517) + le(0x00c50513) + le(0x00052023)
                                   + le(0x0000006f), ROOTS_COMPILER, True),
    ]
    ok = True
    for name, blob, roots, expect in cases:
        got = analyze(blob, roots).ok
        v = "OK" if got == expect else "WRONG"
        if got != expect: ok = False
        print(f"  selftest {name:24s} expect={'SAFE' if expect else 'FLAG'} got={'SAFE' if got else 'FLAG'} [{v}]")
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


def main(argv):
    roots = ROOTS_COMPILER; paths = []; i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--roots": roots = ROOTS_PROGRAM if argv[i+1] == "prog" else ROOTS_COMPILER; i += 2; continue
        if a == "--selftest": return 0 if selftest() else 2
        if a in ("-h", "--help"): print(__doc__); return 0
        if a.startswith("-"): sys.exit(f"verify_wx: unknown option: {a}")
        paths.append(a); i += 1
    if not paths:
        print(__doc__); return 2
    all_ok = True
    for p in paths:
        with open(p, "rb") as f:
            if not report(p, analyze(f.read(), roots)): all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
