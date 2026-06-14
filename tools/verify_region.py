#!/usr/bin/env python3
"""verify_region.py - region confinement + disjointness (L1/L2/L3).

Refines the numeric-W^X pass ("every store is outside the code image") into the
stronger property we want: every store lands in ONE specific, statically disjoint
region (or a whitelisted MMIO range), and the two regions that share an address
span (heap up / stack down = one ARENA) never collide.  Three lemmas:

  L1  static layout : the regions, as fixed offsets from the data base
                      (s10 = `data` = code_hi), are pairwise-disjoint intervals.
  L2  confinement   : every store address resolves to base+offset inside a single
                      region's interval, or an MMIO range.
  L3  no-collision  : within the shared ARENA the heap cursor never passes the
                      stack pointer.  [A later step; not implemented here yet.]

POSITION INDEPENDENCE.  fam output is PIC: every region root is `code_hi + k`,
from one auipc/lui in the prologue.  The lattice tracks a delta WINDOW with an
ALIGNMENT per register:

    C(v)            exact constant v
    P(lo, hi, al)   address in [code_hi+lo, code_hi+hi), a multiple of al
    A(a)            exact PC-relative code address (auipc)
    TOP             unknown

ALIGNMENT lets a 4-byte store at the TOP of an in-region window stay inside the
region: fam's cursors are 4-aligned, so a word store via an aligned cursor whose
window ends at the region ceiling touches at most [ceiling-4, ceiling).

ROOT-REGION INVARIANT.  Each pinned cursor never leaves its region, so its value
is intersected with the region window at every merge (clamp_root) -- the
inductive hypothesis the compiler's L3 DISCHARGES and a produced binary ASSUMES.

INTERPROCEDURAL.  Calls are `push RID; j body` (return = next word); returns are
`j __dispatch`.  Match call->return, apply a per-routine clobber summary, and cut
dispatcher->return edges.  (Same skeleton as verify_wx; lattice is region-aware.)

fam0 (the 168-byte seed) predates the s10-relative scheme: a fixed ABSOLUTE
output buffer at 0x80100000 plus UART/finisher MMIO -> FAM0_MODEL.

Usage: verify_region.py [--model compiler|output|fam0] [--selftest] BINARY ...
Exit:  0 = PROVEN, 1 = a store unconfined, 2 = self-test / usage.
"""

import sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import verify_fsm
import verify_wx
import verify_handoff
from verify_fsm import decode

LOAD = 0x80000000
S32 = verify_wx.S32
RN = verify_wx.RN

SP, GP, TP = 2, 3, 4
T0, T1, T2 = 5, 6, 7
S1, S2, S3 = 9, 18, 19
S5, S6, S7, S8, S9, S10, S11 = 21, 22, 23, 24, 25, 26, 27

OUTPUT_MODEL = {
    "name": "output",
    "anchor": "code_hi",
    "regions": [
        ("rid",   0x0,       0x1000),
        ("vars",  0x1000,    0x5000),
        ("arena", 0x5000,    0x4005000),
        ("loop",  0x4005000, 0x4015000),
    ],
    "roots": {S11: "rid", GP: "arena", SP: "arena", S8: "loop", S10: "_base"},
    "mmio_store": [("uart", 0x10000000, 0x10000100),
                   ("finisher", 0x100000, 0x100100)],
    "mmio_load":  [("mtime", 0x0200BFF8, 0x0200C000)],
}
COMPILER_MODEL = {
    "name": "compiler",
    "anchor": "code_hi",
    "regions": [
        ("rid",       0x0,      0x1000),
        ("cstack",    0x1000,   0x1400),
        ("immediate", 0x1400,   0x41400),
        ("nametable", 0x41400,  0x141400),
        ("callsite",  0x141400, 0x181400),
        # The stack split (src/fam.S) made heap and fam-stack DISJOINT fixed
        # regions, so the old relational L3 (gp<=sp) is now static L1 disjointness:
        ("heap",      0x181400, 0x4181400),          # 0x181400 + 64 MiB, gp grows up
        ("fstack",    0x4181400, 0x4181800),         # 1 KiB fam stack (sp/s3)
    ],
    "roots": {S11: "rid", TP: "cstack", S6: "nametable", S7: "nametable",
              GP: "heap", SP: "fstack", S3: "fstack", S10: "_base"},
    # FIXED roots are set-once base pointers (never advanced): s7 = nametable base
    # (also callsite base via s7+0x100000), s10 = data anchor.  Modeled as the
    # EXACT region-low point so `s7 + 0x100000` resolves to the nametable ceiling
    # exactly -- needed to refine the s6 insert-cursor against the bounds guard.
    "fixed": {S7, S10},
    "mmio_store": [("uart", 0x10000000, 0x10000100),
                   ("finisher", 0x100000, 0x100100)],
    "mmio_load":  [("mtime", 0x0200BFF8, 0x0200C000)],
}
FAM0_MODEL = {
    "name": "fam0",
    "anchor": 0x80100000,
    "regions": [("buffer", 0x0, None)],
    "roots": {S1: "buffer", S2: "buffer"},
    "mmio_store": [("uart", 0x10000000, 0x10000100),
                   ("finisher", 0x100000, 0x100100)],
    "mmio_load":  [("mtime", 0x0200BFF8, 0x0200C000)],
}

# Tabernacle (the sealed bootstrap loader) — a TWO-ANCHOR model.  See
# doc/TABERNACLE_SAFETY.md §4.  gp = end_marker = code_hi anchors the payload
# buffer; s7 = page_align_up(gp+bin_size) anchors the working arena and the two
# stacks.  Their physical disjointness (payload top <= s7) is the relational L1'
# lemma, argued there -- here L1 is checked per anchor.  s3 is the virtio device
# base (a scan-loop result), pinned to its mmio window; s8 (UART) and the SiFive
# finisher are plain constants handled by the mmio_store path.
TABERNACLE_MODEL = {
    "name": "tabernacle",
    "anchor": "code_hi",                    # gp = end_marker (drives gp/auipc recognition)
    "regions": [
        # code_hi-anchored (gp): the downloaded payload.  Upper bound is the
        # runtime load clamp (inspected), so the window is [0, inf) -- "at or
        # above gp"; a store BELOW gp (into tabernacle's code) is flagged (W^X).
        ("payload",  0x0,      None,        "code_hi"),
        # s7-anchored: working arena + the two stacks.
        ("arena",    0x0,      0xB000,      "s7"),
        ("dstack",   0xB000,   0x100000,    "s7"),
        ("ridstack", 0x100000, 0x101000,    "s7"),
        # absolute: the virtio-mmio device window (s3 + small struct offsets).
        ("virtio",   0x10001000, 0x10009000, "abs"),
    ],
    "roots": {GP: "payload", S7: "arena", S9: "ridstack", SP: "dstack",
              S10: "ridstack", S3: "virtio"},
    # FIXED set-once bases: s7 = arena base, s9 = s7+0x100000 (dstack top /
    # ridstack floor = ridstack low).  s3 is forced via root_window below.
    "fixed": {S7, S9},
    "root_window": {S3: (0x10001000, 0x10008001, 0x1000)},
    "mmio_store": [("uart", 0x10000000, 0x10000100),
                   ("finisher", 0x100000, 0x100100)],
    "mmio_load":  [("mtime", 0x0200BFF8, 0x0200C000)],
    # P4 (CFI): the pinned region bases whose corruption would break W^X/region,
    # and the RID-stack convention (CALL: `addi s10,s10,-4; bgeu s10,s9,ok; sw
    # s11,0(s10); li s11,_CSN; j body`).  s10 = RID-stack ptr, s9 = floor, s11 =
    # the pushed return id.  sp is a moving cursor (L2-confined), s3 an MMIO base
    # (scan-bounded by root_window) -- neither is a fixed region base, so not here.
    "cfi_roots": {GP, S7, S9, S10},
    "rid_ptr": S10, "rid_floor": S9, "rid_val": S11,
    # D1 (DMA-target confinement).  Device-shared QUEUE regions hold the virtqueue
    # descriptors the device reads to find DMA addresses; any POINTER the CPU
    # stores there must point into an allowed TARGET (the RX/TX buffers, or -- for
    # the virtio-blk read -- the payload buffer the device DMAs the image into).
    # So the device can DMA only into rxbuf/txframe/payload, never code or state.
    # The descriptor TABLES (16-aligned, 16-byte entries).  rx-net and virtio-blk
    # reuse the same table at s7+0 (mutually exclusive in time); tx-net at +0x8000.
    # A descriptor's addr field is at in-entry offset {0,4} (mod 16); len/flags/
    # next (8/12/14) are not addresses.
    "dma_queues": [("descs", 0x0000, 0x0100, "s7"),     # rx-net / virtio-blk descriptors
                   ("txdesc", 0x8000, 0x8100, "s7")],   # tx-net descriptors
    "dma_targets": [("rxbuf", 0x2000, 0x8000, "s7"),    # 16 RX buffers
                    ("txframe", 0x8200, 0x8400, "s7"),  # TX frame
                    ("diskctl", 0x1200, 0x1220, "s7"),  # virtio-blk status + req header
                    ("payload", 0x0, None, "code_hi")], # full_node image [gp, gp+bin_size)
    # D2 (quiesce / TOCTOU): a device kick = a store to QueueNotify, offset 0x50
    # within a 0x1000 virtio-mmio device window.  Proves no kick (so no fresh DMA)
    # lies between a hash gate and the payload handoff.
    "dma_notify": 0x50,
}

MODELS = {"compiler": COMPILER_MODEL, "output": OUTPUT_MODEL, "fam0": FAM0_MODEL,
          "tabernacle": TABERNACLE_MODEL}


def iter_regions(model):
    """Yield (name, lo, hi, anchor) for each region.  A region tuple is
    (name, lo, hi) -> anchor "code_hi" (the legacy single anchor), or
    (name, lo, hi, anchor) -> explicit (tabernacle's "s7")."""
    for rt in model["regions"]:
        nm, lo, hi = rt[0], rt[1], rt[2]
        yield nm, lo, hi, (rt[3] if len(rt) > 3 else "code_hi")


def region_window(model, regname):
    for nm, lo, hi, _anc in iter_regions(model):
        if nm == regname:
            return (lo, hi)
    if regname == "_base":
        return (0, 0)
    raise KeyError(regname)


def region_anchor(model, regname):
    for nm, _lo, _hi, anc in iter_regions(model):
        if nm == regname:
            return anc
    return "code_hi"


def fits_region(p, regions):
    """If P value `p`'s whole window lies inside one of `regions`
    [(name, lo, hi, anchor)], return that region's name, else None."""
    if not is_P(p):
        return None
    anc, lo, hi = panchor(p), p[1], p[2]
    for nm, rlo, rhi, ranc in regions:
        if ranc != anc:
            continue
        if rhi is None:
            if lo >= rlo:
                return nm
        elif hi is not None and lo >= rlo and hi <= rhi:
            return nm
    return None


def assert_L1(model):
    # Disjointness is checked PER ANCHOR: two regions in different coordinate
    # systems (code_hi vs s7) live in independent spaces and are never compared
    # numerically.  Their physical disjointness is the relational L1' lemma
    # (s7 >= gp + bin_size), argued separately -- see doc/TABERNACLE_SAFETY.md.
    by_anchor = {}
    for nm, lo, hi, anc in iter_regions(model):
        hi_eff = (1 << 62) if hi is None else hi
        if lo >= hi_eff:
            return False, f"region {nm} has empty/inverted interval"
        by_anchor.setdefault(anc, []).append((lo, hi_eff, nm))
    for anc, ivs in by_anchor.items():
        ivs.sort()
        for (lo1, hi1, n1), (lo2, hi2, n2) in zip(ivs, ivs[1:]):
            if hi1 > lo2:
                return False, f"regions {n1} and {n2} overlap (anchor {anc})"
    multi = f" across {len(by_anchor)} anchors" if len(by_anchor) > 1 else ""
    return True, f"regions pairwise-disjoint{multi}"


TOP = ("TOP",)


def is_P(t):  return t is not None and t[0] == "P"
def is_C(t):  return t is not None and t[0] == "C"
def is_A(t):  return t is not None and t[0] == "A"
def is_I(t):  return t is not None and t[0] == "I"


# I(lo, hi, al): a bounded scalar -- an integer value in the INCLUSIVE range
# [lo, hi], every element a multiple of `al`.  Produced by `andi x,m` (-> [0,m])
# and propagated through `slli`/`add`.  Added to a region pointer it yields a
# bounded P window (a `base + idx*scale` address), which is how computed-index
# stores and (later) virtqueue descriptor pointers get confined.
def mkI(lo, hi, al=1):
    return ("I", lo, hi, max(1, al))
def ilo(t): return t[1]
def ihi(t): return t[2]
def ial(t): return t[3]
def _val_al(v):                       # alignment a single constant `v` forces
    return (v & -v) if v else 1


def palign(t):
    return t[3] if (is_P(t) and len(t) > 3) else 1


def palias(t):
    # optional 5th element: (root_reg, off) meaning t == root_reg + off EXACTLY
    return t[4] if (is_P(t) and len(t) > 4) else None


def panchor(t):
    # optional 6th element: the coordinate origin this P is relative to.  Default
    # "code_hi" (the only anchor fam ever used), so every legacy 4/5-tuple is
    # unchanged -- tabernacle adds a second anchor "s7".  Pointers in different
    # anchors are NEVER numerically compared; join/widen of two anchors -> TOP.
    return t[5] if (is_P(t) and len(t) > 5) else "code_hi"


def mkP(lo, hi, al, alias=None, anchor="code_hi"):
    """Construct a P, eliding trailing fields so code_hi/alias-free Ps stay the
    legacy 4-tuple (keeps fam models byte-for-byte identical)."""
    if anchor != "code_hi":
        return ("P", lo, hi, al, alias, anchor)
    if alias is not None:
        return ("P", lo, hi, al, alias)
    return ("P", lo, hi, al)


def _maxNone(a, b):
    if a is None or b is None:
        return None
    return max(a, b)


def _gcd(a, b):
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a or 1


CLAMP_LO = -0x4020000


def _mkP(lo, hi, al, alias, anchor="code_hi"):
    # P value, carrying the optional relational alias (root, off) = "rd == root +
    # off EXACTLY".  Widening/joining the numeric window never breaks that exact
    # relation, so it is sound to preserve it through join/widen.
    return mkP(lo, hi, al, alias, anchor)


def join(a, b):
    if a is None: return b
    if b is None: return a
    if a == b:    return a
    if is_P(a) and is_P(b):
        if panchor(a) != panchor(b):      # two coordinate systems don't merge
            return TOP
        alias = palias(a) if palias(a) == palias(b) else None
        return _mkP(min(a[1], b[1]), _maxNone(a[2], b[2]),
                    _gcd(palign(a), palign(b)), alias, panchor(a))
    # bounded scalars: widen the interval, gcd the alignment; a constant is a
    # singleton interval.
    if (is_I(a) or is_C(a)) and (is_I(b) or is_C(b)):
        alo, ahi, aa = (ilo(a), ihi(a), ial(a)) if is_I(a) else (a[1], a[1], _val_al(a[1]))
        blo, bhi, ba = (ilo(b), ihi(b), ial(b)) if is_I(b) else (b[1], b[1], _val_al(b[1]))
        return mkI(min(alo, blo), _maxNone(ahi, bhi), _gcd(aa, ba))
    return TOP


def widen(old, new):
    if is_I(old) and is_I(new):
        # Widen the UPPER bound to None (unbounded-above) on growth -- NOT to TOP
        # -- so a later guard (`bge idx,N` on the loop body) can narrow it back to
        # a finite [lo, N-1].  The lower bound is kept; if it shrinks we give up
        # (-> TOP), which is rare.  Ensures termination either way.
        if ilo(new) < ilo(old):
            return TOP
        hi = ihi(new) if (ihi(old) is None or
                          (ihi(new) is not None and ihi(new) <= ihi(old))) else None
        return mkI(ilo(new), hi, _gcd(ial(old), ial(new)))
    if not (is_P(old) and is_P(new)):
        return new
    if panchor(old) != panchor(new):
        return TOP
    lo = new[1] if new[1] >= old[1] else CLAMP_LO
    if old[2] is None or new[2] is None:
        hi = None
    else:
        hi = new[2] if new[2] <= old[2] else None
    alias = palias(new) if palias(new) == palias(old) else None
    return _mkP(lo, hi, _gcd(palign(old), palign(new)), alias, panchor(old))


def _iimm(w):
    v = (w >> 20) & 0xfff
    return v - (1 << 12) if v & 0x800 else v


def _simm(w):
    v = ((w >> 25) & 0x7f) << 5 | ((w >> 7) & 0x1f)
    return v - (1 << 12) if v & 0x800 else v


def _is_addi(w, rd, rs1):
    return (w & 0x7f) == 0x13 and ((w >> 12) & 7) == 0 \
        and ((w >> 7) & 0x1f) == rd and ((w >> 15) & 0x1f) == rs1


def p_add(t, k):
    if is_P(t):
        al = palign(t) if k == 0 else _gcd(palign(t), k)
        return mkP(t[1] + k, None if t[2] is None else t[2] + k, al,
                   anchor=panchor(t))
    if is_C(t):
        return ("C", S32(t[1] + k))
    if is_A(t):
        return ("A", t[1] + k)
    if is_I(t):                                       # shift a bounded scalar by k
        hi = None if ihi(t) is None else ihi(t) + k
        return mkI(ilo(t) + k, hi, _gcd(ial(t), k))
    return TOP


def analyze(data, model):
    n = len(data)
    code_lo, code_hi = LOAD, LOAD + n
    anchor = code_hi if model["anchor"] == "code_hi" else model["anchor"]
    word = lambda o: int.from_bytes(data[o:o + 4], "little")
    reached = verify_fsm.verify_bytes(data).reached
    dec = {o: decode(word(o)) for o in reached if decode(word(o))["legal"]}
    roots = model["roots"]
    fixed = model.get("fixed", set())

    root_window = model.get("root_window", {})

    def root_win(reg):
        rgn = roots[reg]
        anc = region_anchor(model, rgn)
        # An explicit root_window pins a base to a bounded value range narrower
        # than its confinement region -- e.g. s3, the virtio device base, which a
        # scan loop leaves on one of the 8 mmio slots [0x10001000,0x10008000]
        # aligned 0x1000, while stores reach +offset into the wider device window.
        rw = root_window.get(reg)
        if rw is not None:
            return mkP(rw[0], rw[1], rw[2], anchor=anc)
        lo, hi = region_window(model, rgn)
        # a FIXED base never advances: model it as the exact region-low point
        # (lo == hi), so arithmetic like `s7 + 0x100000` stays exact.
        if reg in fixed:
            return mkP(lo, lo, 4, anchor=anc)
        return mkP(lo, hi, 4, anchor=anc)

    def clamp_root(reg, t):
        if not is_P(t):
            return t
        rgn = roots[reg]
        if panchor(t) != region_anchor(model, rgn):
            return t                       # different coordinate space; don't clamp
        rlo, rhi = region_window(model, rgn)
        lo = max(t[1], rlo)
        if rhi is None:
            hi = t[2]
        elif t[2] is None:
            hi = rhi
        else:
            hi = min(t[2], rhi)
        return mkP(lo, hi, _gcd(palign(t), 4), anchor=panchor(t))

    # Loop headers = targets of a BACKWARD jal/branch.  Widening is applied ONLY
    # here (not at every merge): elsewhere we just join, so a guard's narrowing
    # (`bge idx,N` -> idx<N) is not immediately re-widened away.  Sound -- every
    # loop has a back-edge, so widening still happens often enough to terminate --
    # and strictly more precise than widen-everywhere.
    headers = set()
    for pc in reached:
        d = dec.get(pc)
        if d and d["kind"] in ("jal", "branch"):
            t = pc + d["imm"]
            if t <= pc and t in reached:
                headers.add(t)

    def merge_states(old, new, do_widen=True):
        out = dict(old)
        for k, v in new.items():
            prev = out.get(k)
            nv = join(prev, v)
            if do_widen and nv is not None and prev is not None:
                nv = widen(prev, nv)
            if nv is not None and k in roots:
                nv = clamp_root(k, nv)
            if nv is None:
                out.pop(k, None)
            else:
                out[k] = nv
        # FIXED roots are global constants (set-once base pointers): force them
        # present in EVERY state so a routine reached via an interproc edge that
        # didn't carry s7/s10 still sees the base.  Sound -- a fixed root never
        # changes, so asserting its exact value never over-approximates.  Roots
        # with an explicit root_window (e.g. s3) are forced the same way: the
        # window soundly over-approximates wherever the scan loop leaves them.
        for r in fixed | set(root_window):
            out[r] = root_win(r)
        return out

    def seed_state():
        return {}

    # Interprocedural model.  Two calling conventions are recognised:
    #   fam:        ...; sw ?, ?(s11) ; j body ; <retsite>     (dispatch reads s11)
    #   tabernacle: sw s11,k(s10) ; li s11,N ; j body ; <retsite>
    #               (CALL macro: push caller RID, set this RID, jump; the body
    #                returns `j dispatch`, a BST on s11 that jumps to the retsite)
    # In both, a call site is `j body` (jal x0) and the retsite is the next word.
    calls, retsites = {}, {}
    for o in reached:
        d = dec.get(o)
        if not d or d["kind"] != "jal" or d["rd"] != 0:
            continue
        pw = word(o - 4) if (o - 4) in reached else 0
        pw2 = word(o - 8) if (o - 8) in reached else 0
        fam = (pw & 0x7f) == 0x23 and ((pw >> 15) & 0x1f) == S11
        tab = (_is_addi(pw, S11, 0)                                # li s11, N
               and (pw2 & 0x7f) == 0x23 and ((pw2 >> 12) & 7) == 2   # sw ...
               and ((pw2 >> 15) & 0x1f) == S10                       # base s10
               and ((pw2 >> 20) & 0x1f) == S11)                      # value s11
        if fam or tab:
            body, ret = o + d["imm"], o + 4
            if body in reached and ret in reached:
                calls[o] = (body, ret)
                retsites[ret] = o

    bodies = {b for (b, _) in calls.values()}

    # The dispatch/return target.  fam: the `lw t0,0(s11)` site.  tabernacle: the
    # BST root that bodies `j dispatch` to.  It is NOT a call body, its pure-
    # control forward region (no stores) reaches >=2 distinct retsites (unlike
    # `halt`, which spins and reaches none), and ALL bodies return to it -- so
    # among such targets it has the most jal-x0 predecessors.  Marking it cut
    # models returns via the call->retsite edge; if mis-identified the analysis
    # stays SOUND (returns just fall back to following all edges, less precise).
    dispatch = {o for o in reached
                if (word(o) & 0x7f) == 0x03 and ((word(o) >> 12) & 7) == 2
                and ((word(o) >> 15) & 0x1f) == S11 and ((word(o) >> 7) & 0x1f) == T0
                and _iimm(word(o)) == 0}
    if not dispatch and retsites:
        def reaches_retsites(T):
            seen, stack, hit = set(), [T], set()
            while stack:
                x = stack.pop()
                if x in seen or x not in reached:
                    continue
                seen.add(x)
                dd = dec.get(x)
                if not dd or (word(x) & 0x7f) == 0x23:    # stop at stores (not in BST)
                    continue
                if dd["kind"] == "jal":
                    t = x + dd["imm"]
                    if t in retsites:
                        hit.add(t)
                    else:
                        stack.append(t)
                elif dd["kind"] == "branch":
                    stack += [x + dd["imm"], x + 4]
                else:
                    stack.append(x + 4)
            return hit
        jpred = {}                                        # jal-x0 edges into each target
        for o in reached:
            dd = dec.get(o)
            if dd and dd["kind"] == "jal" and dd["rd"] == 0 and (o + dd["imm"]) in reached:
                t = o + dd["imm"]
                jpred[t] = jpred.get(t, 0) + 1
        cands = [t for t in jpred if t not in bodies and t not in retsites
                 and len(reaches_retsites(t)) >= 2]
        if cands:
            dispatch = {max(cands, key=lambda t: jpred[t])}

    def is_ret(o):
        d = dec.get(o)
        return d and d["kind"] == "jal" and d["rd"] == 0 and (o + d["imm"]) in dispatch

    def block_set(entry):
        seen, stack, nested = set(), [entry], []
        while stack:
            pc = stack.pop()
            if pc in seen or pc not in reached:
                continue
            seen.add(pc)
            if pc in dispatch or is_ret(pc):
                continue
            if pc in calls:
                b, r = calls[pc]
                nested.append(b)
                stack.append(r)
                continue
            d = dec.get(pc)
            if not d:
                continue
            if d["kind"] == "jal":
                stack.append(pc + d["imm"])
            elif d["kind"] == "branch":
                stack += [pc + d["imm"], pc + 4]
            else:
                stack.append(pc + 4)
        return seen, nested

    blocks = {b: block_set(b) for b in bodies}

    # Callee-saved preservation: a register saved at entry and restored before
    # return via the same single-frame stack slot is NET-unchanged across a call
    # to the routine, so the may-write clobber summary's inclusion of it is a
    # false positive.  Excluding it lets a caller-saved region pointer (e.g.
    # gimli_hash's s0 = state base, across `CALL gimli_permute`) survive the call.
    # Sound conditions (all required): exactly one sp frame (-N entry / +N exit);
    # `sw rX,k(sp)` with NO prior write to rX (so the saved value IS the entry
    # value) and the slot written ONLY by that save; and the routine's LAST write
    # to rX is `lw rX,k(sp)` from that same slot (so rX returns at the saved value).
    CALLEE_SAVED = {SP, S1, S2, S3, S5, S6, S7, S8, S9, S10, S11, 8}  # +s0=x8
    def preserved_regs(entry):
        ins = sorted(blocks[entry][0])
        spadj = [(o, _iimm(word(o))) for o in ins if _is_addi(word(o), SP, SP)]
        if len(spadj) != 2:
            return set()                       # not a single, balanced frame
        (_, d1), (_, d2) = spadj
        if not (d1 < 0 and d2 == -d1):
            return set()
        save_off, slot_writers, last_write = {}, {}, {}
        for o in ins:
            w = word(o)
            if (w & 0x7f) == 0x23 and ((w >> 12) & 7) == 2 and ((w >> 15) & 0x1f) == SP:
                k = _simm(w); rs2 = (w >> 20) & 0x1f
                slot_writers[k] = slot_writers.get(k, 0) + 1
                save_off.setdefault(rs2, (o, k))
            wr = verify_wx.written_reg(w)
            if wr is not None:
                last_write[wr] = o
        pres = set()
        for reg in CALLEE_SAVED:
            so = save_off.get(reg)
            if so is None:
                continue
            o_save, k = so
            if slot_writers.get(k, 0) != 1:           # slot reused -> unsound
                continue
            if any(verify_wx.written_reg(word(o)) == reg for o in ins if o < o_save):
                continue                              # written before save -> saved != entry
            lo = last_write.get(reg)
            lw = word(lo) if lo is not None else 0
            if (lw & 0x7f) == 0x03 and ((lw >> 12) & 7) == 2 \
                    and ((lw >> 15) & 0x1f) == SP and _iimm(lw) == k:  # load: I-type imm
                pres.add(reg)                         # last write IS the restore
        return pres

    preserved = {b: preserved_regs(b) for b in bodies}

    clob = {b: set() for b in bodies}
    changed = True
    while changed:
        changed = False
        for b, (ins, nested) in blocks.items():
            c = {wr for pc in ins if (wr := verify_wx.written_reg(word(pc))) is not None}
            for nb in nested:
                c |= clob.get(nb, set())
            c |= {T0, T1}
            c -= preserved[b]                  # net-preserved regs are not clobbered
            if c != clob[b]:
                clob[b] = c
                changed = True

    def transfer(pc, m):
        w = word(pc)
        op = w & 0x7f
        rd = (w >> 7) & 0x1f
        rs1 = (w >> 15) & 0x1f
        rs2 = (w >> 20) & 0x1f
        f3 = (w >> 12) & 7
        out = dict(m)

        def val(reg):
            return ("C", 0) if reg == 0 else m.get(reg)

        def setrd(t):
            if rd == 0:
                return
            if rd in roots and is_P(t):
                t = clamp_root(rd, t)
            if t is None:
                out.pop(rd, None)
            else:
                out[rd] = t

        if op == 0x37:
            c = S32(((w >> 12) & 0xfffff) << 12)
            if (c & 0xffffffff) == (anchor & 0xffffffff):   # lui of the anchor base (fam0)
                hi = region_window(model, roots[rd])[1] if rd in roots else None
                setrd(("P", 0, hi, 4))
            else:
                setrd(("C", c))
        elif op == 0x17:
            a = (LOAD + pc + S32(((w >> 12) & 0xfffff) << 12)) & 0xffffffff
            setrd(("P", a - anchor, a - anchor, 4)
                  if a == (anchor & 0xffffffff) else ("A", a))
        elif op == 0x13 and f3 == 0:
            k = _iimm(w)
            t = p_add(val(rs1), k)
            if is_A(t) and t[1] == anchor:
                t = ("P", 0, 0, 4)
            # relational alias: tag rd == (root + off) exactly, so a later guard
            # on rd can refine the root's window (closes the s6 burst-write case).
            if is_P(t):
                if rs1 in roots:
                    t = mkP(t[1], t[2], palign(t), (rs1, k), panchor(t))
                else:
                    a0 = palias(val(rs1))
                    if a0 is not None:
                        t = mkP(t[1], t[2], palign(t), (a0[0], a0[1] + k), panchor(t))
            setrd(t)
        elif op == 0x13 and f3 == 7:
            a = val(rs1)
            k = _iimm(w)
            if is_P(a) and k < 0:
                step = -k
                al = step if (step & (step - 1)) == 0 else 1
                setrd(mkP(a[1] + k + 1, a[2], al, anchor=panchor(a)))
            elif k >= 0:                              # x & m  (m>=0)  in [0, m]
                setrd(mkI(0, k, k & -k if k else 1))
            else:
                setrd(TOP)
        elif op == 0x13 and f3 == 1:                  # slli rd, rs, shamt
            sh = (w >> 20) & 0x1f
            a = val(rs1)
            if is_I(a):
                hi = None if ihi(a) is None else ihi(a) << sh
                setrd(mkI(ilo(a) << sh, hi, ial(a) << sh))
            elif is_C(a):
                setrd(("C", S32(a[1] << sh)))
            else:
                setrd(TOP)
        elif op == 0x33 and f3 == 0 and ((w >> 25) & 0x7f) == 0:
            a, b = val(rs1), val(rs2)

            def p_add_I(p, i):
                # base in [p.lo, p.hi) (exclusive) or exact (lo==hi); index in
                # [i.lo, i.hi] inclusive -> P window covering base+index.
                al = _gcd(palign(p), ial(i))
                if p[2] is None or ihi(i) is None:    # either unbounded -> unbounded
                    return mkP(p[1] + ilo(i), None, al, anchor=panchor(p))
                hi_excl = p[2] if p[1] < p[2] else p[1] + 1
                return mkP(p[1] + ilo(i), hi_excl + ihi(i), al, anchor=panchor(p))

            def addt(x, y):
                if is_P(x) and is_C(y):
                    return p_add(x, y[1])
                if is_C(x) and is_C(y):
                    return ("C", S32(x[1] + y[1]))
                if is_A(x) and is_C(y):
                    return ("A", x[1] + y[1])
                if is_P(x) and is_I(y):
                    return p_add_I(x, y)
                if is_C(x) and is_I(y):
                    hi = None if ihi(y) is None else x[1] + ihi(y)
                    return mkI(x[1] + ilo(y), hi, ial(y))
                if is_I(x) and is_I(y):
                    hi = None if (ihi(x) is None or ihi(y) is None) else ihi(x) + ihi(y)
                    return mkI(ilo(x) + ilo(y), hi, _gcd(ial(x), ial(y)))
                return None
            setrd(addt(a, b) or addt(b, a) or TOP)
        elif op == 0x33 and f3 == 0 and ((w >> 25) & 0x7f) == 0x20:
            a, b = val(rs1), val(rs2)
            if is_P(a) and is_C(b):
                setrd(p_add(a, -b[1]))
            elif is_C(a) and is_C(b):
                setrd(("C", S32(a[1] - b[1])))
            else:
                setrd(TOP)
        elif op == 0x03:
            # A load INTO a pinned root is a cursor reload (root-region invariant).
            # Otherwise, if the loaded address is an EXACT region cell that only
            # ever receives region-pointer stores (cells[]), the loaded value is a
            # pointer into that region; else TOP.
            if rd in roots:
                setrd(root_win(rd))
            else:
                base = val(rs1)
                cell = None
                if is_P(base) and base[1] == base[2]:        # exact address
                    cell = base[1] + _iimm(w)
                rgn = cells.get(cell) if cell is not None else None
                setrd(mkP(*region_window(model, rgn), 4,
                          anchor=region_anchor(model, rgn)) if rgn else TOP)
        elif op in (0x63, 0x23, 0x0f):
            pass
        elif op == 0x6f:
            if rd != 0:
                setrd(("A", LOAD + pc + 4))
        else:
            setrd(TOP)
        return out

    def refine(m, w, taken):
        f3 = (w >> 12) & 7
        rs1 = (w >> 15) & 0x1f
        rs2 = (w >> 20) & 0x1f
        out = dict(m)
        a = ("C", 0) if rs1 == 0 else m.get(rs1)
        b = ("C", 0) if rs2 == 0 else m.get(rs2)
        # Scalar interval refinement: a bounded scalar rs1 compared to a constant
        # rs2 narrows on each edge (e.g. a loop guard `bge idx,16` -> idx<=15 on
        # the loop body).  Handles all of blt/bge/bltu/bgeu before the P-vs-P
        # pointer logic below (which only fires when both operands are pointers).
        if f3 in (4, 5, 6, 7) and rs1 != 0 and (is_I(a) or is_C(a)) and is_C(b):
            lt_taken = f3 in (4, 6)                  # blt/bltu: taken => rs1 < rs2
            rs1_lt = lt_taken if taken else not lt_taken
            lo, hi = (ilo(a), ihi(a)) if is_I(a) else (a[1], a[1])
            al = ial(a) if is_I(a) else _val_al(a[1])
            N = b[1]
            if rs1_lt:                               # rs1 < N -> cap upper at N-1
                nhi = N - 1 if hi is None else min(hi, N - 1)
                if nhi >= lo:
                    out[rs1] = mkI(lo, nhi, al)
            elif max(lo, N) <= hi if hi is not None else True:   # rs1 >= N
                out[rs1] = mkI(max(lo, N), hi, al)
        if f3 == 6:
            ge = not taken
        elif f3 == 7:
            ge = taken
        else:
            return out
        if rs1 != 0 and is_P(a) and is_P(b) and panchor(a) == panchor(b):
            al = palign(a)
            anc = panchor(a)
            if ge:
                t = mkP(max(a[1], b[1]), a[2], al, anchor=anc)
            else:
                hi = b[2] if b[2] is not None else a[2]
                if hi is None:
                    t = a
                else:
                    t = mkP(a[1], min(a[2], hi) if a[2] is not None else hi, al, anchor=anc)
            out[rs1] = clamp_root(rs1, t) if rs1 in roots else t
        # relational refinement: with big >= small, if small == root + c (alias)
        # and big has a finite max delta M, then root <= M - c -> cap root.hi.
        def maxdelta(v):
            if not is_P(v) or v[2] is None:
                return None
            return v[2] if v[1] == v[2] else v[2] - 1   # exact point: lo==hi
        small, big = (b, a) if ge else (a, b)
        als = palias(small)
        if als is not None and als[0] in roots:
            root, c = als
            M = maxdelta(big)
            rv = out.get(root)
            if M is not None and is_P(rv):
                newhi = (M - c) + 1                      # exclusive upper bound
                nh = newhi if rv[2] is None else min(rv[2], newhi)
                out[root] = clamp_root(root, ("P", rv[1], nh, palign(rv)))
        return out

    def apply_clobber(m, c):
        out = dict(m)
        for r in c:
            out[r] = root_win(r) if r in roots else TOP
        return out

    def successors(pc, m):
        if pc in calls:
            body, ret = calls[pc]
            return [(body, m),
                    (ret, apply_clobber(m, clob.get(body, set()) | {T0, T1}))]
        if pc in dispatch or is_ret(pc):
            return []
        d = dec.get(pc)
        if not d:
            return []
        if d["kind"] == "branch":
            w = word(pc)
            t = pc + d["imm"]
            res = []
            if t in reached:
                res.append((t, refine(m, w, True)))
            if (pc + 4) in reached:
                res.append((pc + 4, refine(m, w, False)))
            return [(s, st) for (s, st) in res if s not in retsites]
        out = transfer(pc, m)
        if d["kind"] == "jal":
            t = pc + d["imm"]
            return [(t, out)] if (t in reached and t not in retsites) else []
        nxt = pc + 4
        return [(nxt, out)] if (nxt in reached and nxt not in retsites) else []

    def run():
        st = {0: seed_state()}
        work = [0]
        while work:
            pc = work.pop()
            for s, ss in successors(pc, st[pc]):
                merged = merge_states(st.get(s, {}), ss, s in headers)
                if merged != st.get(s):
                    st[s] = merged
                    work.append(s)
        return st

    # ---- memory-cell map: which EXACT region cells hold a region pointer ----
    # A store `sw rs2, off(base)` where base is an exact region address (lo==hi)
    # writes cell = base+off.  If EVERY reaching store to a cell writes a value
    # that is a pointer into region R (and never anything else), then a load from
    # that cell yields an R pointer.  Computed as a greatest-fixpoint: start
    # optimistic, drop any cell with a non-R (or mixed) store.  Sound: a dropped
    # cell just falls back to TOP.
    cells = {}
    def store_cell(stm, w):
        b = ("C", 0) if ((w >> 15) & 0x1f) == 0 else stm.get((w >> 15) & 0x1f)
        if is_P(b) and b[1] == b[2]:
            return b[1] + _simm(w)
        return None
    def stored_region(stm, w):
        v = ("C", 0) if ((w >> 20) & 0x1f) == 0 else stm.get((w >> 20) & 0x1f)
        if not is_P(v):
            return None
        vanc = panchor(v)
        for nm, rlo, rhi, ranc in iter_regions(model):
            if ranc != vanc:
                continue
            rhi_eff = (1 << 62) if rhi is None else rhi
            if v[1] >= rlo and (v[2] is not None) and v[2] <= rhi_eff:
                return nm
        return None
    while True:
        state = run()
        # collect, per cell, the set of regions stored (None = a non-pointer store)
        seen = {}
        for off in reached:
            w = word(off)
            if (w & 0x7f) != 0x23 or ((w >> 12) & 7) != 2:   # word stores only
                continue
            c = store_cell(state.get(off, {}), w)
            if c is None:
                continue
            seen.setdefault(c, set()).add(stored_region(state.get(off, {}), w))
        newcells = {c: next(iter(rs)) for c, rs in seen.items()
                    if len(rs) == 1 and None not in rs}
        if newcells == cells:
            break
        cells = newcells

    # ---- induction-variable bounding (tightens loop-cursor stores) ----------
    # A temp cursor incremented by a constant stride in a constant-trip-count
    # loop widens its `hi` to None (it is not a pinned root, so never clamped),
    # leaving its stores unconfinable.  Recover a SOUND finite ceiling from the
    # loop: at a counted loop `... bnez c,header` with `addi c,c,-1` and `addi
    # cur,cur,+k`, where c = N (a constant) on entry, the cursor satisfies
    # cur in [cur_init.lo, cur_init.hi + N*k] at every store.  We fire ONLY on
    # this exact, unambiguous idiom -- any deviation falls back to flagging, and
    # the result is a superset of the true value, so a region match stays sound.
    def induction_bounds():
        preds = {}
        for u in reached:
            for (s, _ss) in successors(u, state.get(u, {})):
                preds.setdefault(s, []).append(u)

        def out_state(u, target):           # state flowing edge u -> target
            for (s, ss) in successors(u, state.get(u, {})):
                if s == target:
                    return ss
            return None

        tight = {}
        for back in reached:
            d = dec.get(back)
            if not d:
                continue
            # Two counted-loop shapes share this code:
            #   (a) do-while: back-edge `bnez c,header`, with `addi c,c,-1`.
            #       Trip count N = c on entry.
            #   (b) while:    back-edge `j header` (unconditional), and a top
            #       guard `bge/bgeu idx,lim,exit` (forward exit) with `addi
            #       idx,idx,1`.  Trip count N = lim - idx on entry.
            if d["kind"] == "branch":
                w = word(back)
                if ((w >> 12) & 7) != 1 or ((w >> 20) & 0x1f) != 0:    # need bnez
                    continue
                shape, counter = "dec", (w >> 15) & 0x1f
            elif d["kind"] == "jal" and d["rd"] == 0:
                shape, counter = "guard", None
            else:
                continue
            header = back + d["imm"]
            if header >= back or header not in reached:
                continue
            body = [o for o in reached if header <= o <= back]
            # No backward escape out of the loop (keeps the body = contiguous
            # [header, back], so the write scan below is complete).  Forward
            # exits (the guard) are fine -- they leave the loop.
            if any(o != back and (od := dec.get(o)) and od["kind"] in ("jal", "branch")
                   and (o + od["imm"]) < header for o in body):
                continue
            # writes in the body, grouped by destination register
            writes = {}
            for o in body:
                wr = verify_wx.written_reg(word(o))
                if wr is not None and wr != 0:
                    writes.setdefault(wr, []).append(o)

            def inc_by(reg, want):     # reg written exactly once, by `addi reg,reg,want`
                offs = writes.get(reg, [])
                return len(offs) == 1 and _is_addi(word(offs[0]), reg, reg) \
                    and _iimm(word(offs[0])) == want

            entry = [u for u in preds.get(header, []) if not (header <= u <= back)]
            if not entry:
                continue

            # Identify the trip-count source and the index/counter register.
            if shape == "dec":
                if not inc_by(counter, -1):                # counter -= 1
                    continue
                ctrl = {counter}
                def trip(ms):                              # N = counter on entry
                    cv = ms.get(counter)
                    return cv[1] if is_C(cv) and cv[1] > 0 else None
            else:  # guard
                # find a forward-exit guard `bge/bgeu idx,lim,exit` (idx += 1).
                # The limit is read at the GUARD (it is often `li lim,N` reloaded
                # inside the loop header, so it is not constant at loop entry).
                guard = None
                for o in body:
                    od = dec.get(o)
                    if not od or od["kind"] != "branch":
                        continue
                    gw = word(o); gf3 = (gw >> 12) & 7
                    if gf3 not in (5, 7):                  # bge / bgeu (exit if idx>=lim)
                        continue
                    if (o + od["imm"]) <= back:            # must be a forward EXIT
                        continue
                    gi, gl = (gw >> 15) & 0x1f, (gw >> 20) & 0x1f
                    lv = state.get(o, {}).get(gl)
                    if inc_by(gi, 1) and gi != 0 and is_C(lv):
                        guard = (gi, lv[1])
                        break
                if guard is None:
                    continue
                idx, lim_const = guard
                ctrl = {idx}
                def trip(ms):                              # N = lim - idx on entry
                    iv = ms.get(idx)
                    if is_C(iv) and lim_const - iv[1] > 0:
                        return lim_const - iv[1]
                    return None

            # induction cursors: written exactly once, by `addi r,r,+k` (k>0) OR
            # `add r,r,R` where R holds a constant stride (e.g. the rx-descriptor
            # buffer pointer `add t2,t2,t5`, t5=1536 -> a 1536-byte stride).
            cursors = {}
            for reg, offs in writes.items():
                if reg in ctrl or len(offs) != 1:
                    continue
                ww = word(offs[0])
                if _is_addi(ww, reg, reg) and _iimm(ww) > 0:
                    cursors[reg] = _iimm(ww)
                elif (ww & 0x7f) == 0x33 and ((ww >> 12) & 7) == 0 \
                        and ((ww >> 25) & 0x7f) == 0 and ((ww >> 7) & 0x1f) == reg:
                    a_, b_ = (ww >> 15) & 0x1f, (ww >> 20) & 0x1f
                    other = b_ if a_ == reg else (a_ if b_ == reg else None)
                    rv = state.get(offs[0], {}).get(other) if other is not None else None
                    if is_C(rv) and rv[1] > 0:
                        cursors[reg] = rv[1]
            if not cursors:
                continue

            # N + cursor inits from every entry edge (must agree on N)
            N = None
            inits = {r: None for r in cursors}
            bail = False
            for u in entry:
                ms = out_state(u, header)
                if ms is None:
                    bail = True
                    break
                t_n = trip(ms)
                if t_n is None:
                    bail = True
                    break
                N = t_n if N is None else (N if N == t_n else -1)
                for r in cursors:
                    inits[r] = join(inits[r], ms.get(r))
            if bail or N is None or N < 0:
                continue
            for reg, k in cursors.items():
                cur0 = inits[reg]
                if not is_P(cur0) or cur0[2] is None:
                    continue
                ceil = cur0[2] + N * k          # cur in [init.lo, init.hi + N*stride)
                t = mkP(cur0[1], ceil, palign(cur0), anchor=panchor(cur0))
                # record the bound for EVERY store in the loop body -- it applies
                # to the cursor whether it is the store BASE (L2) or the stored
                # VALUE (D1, a descriptor address).
                for o in body:
                    if (word(o) & 0x7f) == 0x23:
                        tight.setdefault(o, {})[reg] = t
        return tight

    induction = induction_bounds()       # {store_off: {cursor_reg: bound P}}

    def classify(base, off, sz):
        if base is None:
            return None, "undefined base"
        if is_P(base):
            al = palign(base)
            banc = panchor(base)
            lo = base[1] + off
            hi = None if base[2] is None else base[2] + off
            hi_touch = None
            if hi is not None:
                if base[1] == base[2]:
                    # EXACT base (P(A,A)): the store hits the single address
                    # lo = A+off, touching [lo, lo+sz).  No alignment trick (that
                    # is only sound for a cursor RANGE whose aligned top store
                    # ends exactly at the region top); using it here underestimated
                    # the touched end and wrongly confined one-past-the-end stores.
                    hi_touch = lo + sz
                else:
                    # RANGE base: value in [lo, hi); max aligned base = align-down
                    # of hi-1; its store ends at top_a + sz.
                    top_a = ((hi - 1) // al) * al
                    hi_touch = top_a + sz
            for nm, rlo, rhi, ranc in iter_regions(model):
                if ranc != banc:
                    continue
                rhi_eff = (1 << 62) if rhi is None else rhi
                if lo >= rlo and hi_touch is not None and hi_touch <= rhi_eff:
                    return nm, None
            if hi is None:
                for nm, rlo, rhi, ranc in iter_regions(model):
                    if ranc == banc and rhi is None and lo >= rlo:
                        return nm, None
            hs = "inf" if hi is None else hex(hi)
            return None, f"P@{banc}[{lo:#x},{hs}) al={al} fits no single region"
        if is_C(base) or is_A(base):
            a = (base[1] + off) & 0xffffffff
            for nm, mlo, mhi in model["mmio_store"]:
                if mlo <= a < mhi:
                    return f"mmio:{nm}", None
            if code_lo <= a < code_hi:
                return None, f"const {a:#x} INSIDE code image"
            return None, f"const {a:#x} not in any region/MMIO"
        return None, "TOP base"

    def wx_safe(base, off, sz):
        """W^X: prove the store's address can NOT land in the code image
        [code_lo, code_hi).  This is WEAKER than region confinement -- a store
        only has to be provably OUTSIDE the code band, not pinned to one region.
        The address space is  MMIO (<code_lo)  <  code  <  payload (>=code_hi)
        <  arena/stacks (>=s7 > code_hi, by the L1' lemma s7=page_align(gp+
        bin_size) > gp=code_hi).  So:"""
        if is_P(base):
            anc = panchor(base)
            lo = base[1] + off
            if anc == "code_hi":
                return lo >= 0                      # >= code_hi -> payload, not code
            if anc == "s7":
                return lo >= 0                      # >= s7 > code_hi (L1')
            if anc == "abs":                        # absolute (e.g. virtio mmio)
                hi = None if base[2] is None else base[2] + off
                return hi is not None and (hi <= code_lo or lo >= code_hi)
            return False
        if is_C(base) or is_A(base):
            a = (base[1] + off) & 0xffffffff
            return a + sz <= code_lo or a >= code_hi
        return False                                # TOP / None -> not provable

    tally = {}
    flags = []
    wx_flags = []
    dma_flags = []
    notify_stores = []       # D2: device-kick (QueueNotify) sites
    nstores = 0
    for off in sorted(reached):
        w = word(off)
        if (w & 0x7f) != 0x23:
            continue
        nstores += 1
        st = state.get(off, {})
        breg = (w >> 15) & 0x1f
        soff = _simm(w)
        base = ("C", 0) if breg == 0 else st.get(breg)
        sz = {0: 1, 1: 2, 2: 4}.get((w >> 12) & 7, 4)
        szname = {0: "sb", 1: "sh", 2: "sw"}.get((w >> 12) & 7, "s?")
        ind = induction.get(off, {}).get(breg)        # loop bound for the base reg
        rg, reason = classify(base, soff, sz)
        if rg is None and ind is not None:
            # the loop-derived ceiling is a sound superset of the real cursor;
            # if THAT confines, the actual (subset) store is confined too.
            rg2, reason2 = classify(ind, soff, sz)
            if rg2 is not None:
                rg, reason, base = rg2, reason2, ind
        if rg is None:
            flags.append((off, w, breg, szname, base, reason))
        else:
            tally[rg] = tally.get(rg, 0) + 1
        # W^X (P3): does this store provably avoid the code image?
        if not (wx_safe(base, soff, sz) or (ind is not None and wx_safe(ind, soff, sz))):
            wx_flags.append((off, w, breg, szname, base))
        # D1 (DMA): a POINTER stored into a device-shared queue (a descriptor
        # address) must point into an allowed DMA target.  Non-pointer stores
        # (len/flags/next, ring indices) are not addresses -- ignored.
        # D1: a virtqueue descriptor's ADDR field (a WORD at in-entry offset {0,4}
        # of a 16-aligned descriptor table) is a physical address the device will
        # DMA to -- it MUST point into an allowed DMA target.  len/flags/next
        # fields are not addresses; the rings (indices) live outside the table.
        if "dma_queues" in model and ((w >> 12) & 7) == 2:    # word stores only
            dbase = ind if ind is not None else base
            if is_P(dbase) and fits_region(dbase, model["dma_queues"]) is not None \
                    and (dbase[1] + soff) % 16 in (0, 4):     # the addr lo/hi field
                vreg = (w >> 20) & 0x1f
                vraw = ("C", 0) if vreg == 0 else st.get(vreg)
                vind = induction.get(off, {}).get(vreg)
                veff = vind if vind is not None else vraw
                # OK iff provably a target pointer, or a non-code constant (addr_hi
                # = 0, or a low/MMIO addr that cannot hit code).  TOP -> unknown
                # DMA target -> flag (the device could be pointed at code/state).
                if is_P(veff):
                    if fits_region(veff, model["dma_targets"]) is None:
                        dma_flags.append((off, w, vreg, veff))
                elif is_C(veff):
                    if code_lo <= veff[1] < code_hi:
                        dma_flags.append((off, w, vreg, veff))
                elif not is_I(veff):                          # TOP/None (lost addr)
                    dma_flags.append((off, w, vreg, veff))
        # D2: a device kick = a store to a virtqueue's QueueNotify register
        # (offset `dma_notify` within a 0x1000 virtio-mmio device window).  After
        # such a kick the device may DMA; D2 proves none lies between a hash gate
        # and the handoff.
        if "dma_notify" in model and is_P(base) and panchor(base) == "abs" \
                and (soff % 0x1000) == model["dma_notify"]:
            notify_stores.append(off)

    return {"model": model, "nstores": nstores, "tally": tally,
            "flags": flags, "wx_flags": wx_flags, "dma_flags": dma_flags,
            "notify_stores": notify_stores,
            "reached": reached, "state": state, "code_hi": code_hi}


def analyze_cfi(data, model):
    """P4 (CFI) for tabernacle, derived from the same two-anchor machinery.

    P4a (root provenance): every write to a pinned region base (gp/s7/s9/s10) is
    either the prologue init -- which runs at entry, BEFORE any network/disk input
    is read, so it cannot be input-controlled; we only reject a *direct* load or a
    jal-link into a root there -- or the CALL's `addi s10,s10,+/-4`.  No
    data-dependent write to a root anywhere in the body.

    P4b (RID-stack discipline): s10 (RID ptr) moves only by +/-4 in the body; every
    write to s11 (the RID) is `li s11,const` or a pop `lw s11,0(s10)` (so the RID
    is ALWAYS a compile-time constant -- structural, no value tracking); every push
    `sw s11,0(s10)` is dominated by an `s10>=s9` overflow guard a few insns prior.
    """
    n = len(data)
    word = lambda o: int.from_bytes(data[o:o + 4], "little")
    reached = verify_fsm.verify_bytes(data).reached
    pinned = model["cfi_roots"]
    PTR, FLOOR, VAL = model["rid_ptr"], model["rid_floor"], model["rid_val"]

    def is_pm4(w, reg):
        return _is_addi(w, reg, reg) and _iimm(w) in (4, -4)

    pushes = [o for o in sorted(reached)
              if (word(o) & 0x7f) == 0x23 and ((word(o) >> 12) & 7) == 2
              and ((word(o) >> 15) & 0x1f) == PTR and ((word(o) >> 20) & 0x1f) == VAL]
    prologue_end = min(pushes) if pushes else n      # roots init'd before 1st CALL
    p4a, p4b = [], []
    nroot = 0
    for o in sorted(reached):
        w = word(o)
        rd = verify_wx.written_reg(w)
        if rd in pinned:
            nroot += 1
            if rd == PTR and is_pm4(w, PTR):
                pass                                  # CALL push/pop adjust
            elif o < prologue_end:                    # prologue init (pre-input)
                if (w & 0x7f) == 0x03:
                    p4a.append((o, w, f"P4a {RN[rd]} set by a direct load in prologue"))
                elif (w & 0x7f) == 0x6f:
                    p4a.append((o, w, f"P4a {RN[rd]} set to a return address (jal)"))
            else:
                p4a.append((o, w, f"P4a {RN[rd]} written in the body (not prologue / not RID +/-4)"))
        # P4b: RID ptr in the body only by +/-4
        if rd == PTR and o >= prologue_end and (w & 0x7f) == 0x13 \
                and ((w >> 12) & 7) == 0 and ((w >> 15) & 0x1f) == PTR \
                and _iimm(w) not in (4, -4):
            p4b.append((o, w, f"P4b {RN[PTR]} adjusted by {_iimm(w)} (not +/-4)"))
        # P4b: RID value only by li-const or pop
        if rd == VAL:
            is_li = _is_addi(w, VAL, 0)               # addi s11,x0,const  (li s11,N)
            is_pop = (w & 0x7f) == 0x03 and ((w >> 12) & 7) == 2 and ((w >> 15) & 0x1f) == PTR
            if not (is_li or is_pop):
                p4b.append((o, w, f"P4b {RN[VAL]} (RID) set by neither li-const nor pop"))
    for o in pushes:                                  # every push overflow-guarded
        guarded = False
        for back in range(4, 24, 4):
            p = o - back
            if p not in reached:
                break
            pw = word(p)
            if (pw & 0x7f) == 0x63 and {(pw >> 15) & 0x1f, (pw >> 20) & 0x1f} == {PTR, FLOOR}:
                guarded = True
                break
        if not guarded:
            p4b.append((o, word(o), f"P4b RID push not guarded by {RN[PTR]}>={RN[FLOOR]} overflow check"))
    return {"p4a": p4a, "p4b": p4b, "nroot": nroot, "npush": len(pushes)}


def verify_quiesce(data, model):
    """D2 (quiesce / no TOCTOU on the payload).

    The device can DMA into the payload only via the virtio-blk read (D1: the only
    descriptor target that overlaps [gp, gp+bin_size); the net device's descriptors
    point only at rxbuf/txframe).  D2 proves that read is QUIESCED before the
    handoff: no device kick (QueueNotify) lies between a hash gate and the payload
    handoff, so nothing the device was told to do can land in the payload after it
    was hashed.

    P5a already proves the hash gate B DOMINATES each handoff x, so EVERY path to
    the handoff passes B.  D2 adds: no QueueNotify store lies in the region between
    B and x (the nodes B dominates that can still reach x).  A kick strictly before
    B is harmless -- its DMA is to a buffer the gate then re-hashes (or, with the
    blocking completion-wait in the read loop, has already retired); the property
    we machine-check is that NO kick survives into the post-gate window.

    Returns {ok, kicks, windows, bad} where bad = [(gate, handoff, kick), ...].
    """
    r = analyze(data, model)
    kicks = set(r["notify_stores"])
    g = verify_handoff.build_cfg(data)
    dom = verify_handoff.dominators(g)
    res, _ = verify_handoff.verify_bytes(data)

    # predecessors, for backward reachability to a handoff
    preds = {}
    for u, succ in g.succ.items():
        for v in succ:
            preds.setdefault(v, set()).add(u)

    def reaches(x):                      # nodes that can reach x (x included)
        seen, stk = {x}, [x]
        while stk:
            u = stk.pop()
            for p in preds.get(u, ()):
                if p not in seen:
                    seen.add(p); stk.append(p)
        return seen

    bad, windows = [], []
    for kind, site, gates, innermost in res.exits:
        if innermost is None:            # ungated -> a P5a failure, not D2's job
            continue
        B = innermost
        back = reaches(site)
        # the gate->handoff window: nodes B dominates that still reach the handoff
        window = {n for n in back if B in dom.get(n, set())}
        windows.append((B, site, len(window)))
        for k in kicks:
            if k in window:
                bad.append((B, site, k))
    return {"ok": not bad, "kicks": sorted(kicks), "windows": windows, "bad": bad}


def report(path, model):
    with open(path, "rb") as f:
        data = f.read()
    l1_ok, l1_msg = assert_L1(model)
    r = analyze(data, model)
    print(f"{path}  [model: {model['name']}]")
    print(f"  L1 layout : {'OK' if l1_ok else 'FAIL'} - {l1_msg}")
    print(f"  reachable stores: {r['nstores']}   flagged: {len(r['flags'])}")
    if r["tally"]:
        tally = "  ".join(f"{k}={v}" for k, v in sorted(r["tally"].items()))
        print(f"  by region : {tally}")
    nwx = len(r["wx_flags"])
    print(f"  P3 (W^X)  : {r['nstores'] - nwx}/{r['nstores']} stores provably avoid the "
          f"code image" + ("" if nwx == 0 else f"  ({nwx} not provable -> inspect)"))
    for off, w, breg, sz, base in r["wx_flags"][:20]:
        bv = "undef" if base is None else f"{base}"
        print(f"    w^x? +{off:#06x}  {w:08x}  {sz} via {RN[breg]:<4}  {bv}")
    if "cfi_roots" in model:
        c = analyze_cfi(data, model)
        print(f"  P4a (roots region-relative, never input):  "
              f"{'PASS' if not c['p4a'] else 'FAIL'}   ({c['nroot']} root writes)")
        print(f"  P4b (RID stack: +/-4, guarded, ids const): "
              f"{'PASS' if not c['p4b'] else 'FAIL'}   ({c['npush']} pushes)")
        for off, w, msg in (c["p4a"] + c["p4b"])[:20]:
            print(f"    cfi! +{off:#06x}  {w:08x}  {msg}")
    if "dma_queues" in model:
        nd = len(r["dma_flags"])
        print(f"  D1 (descriptor addrs -> DMA targets only): "
              f"{'PASS' if nd == 0 else f'{nd} unconfined'}")
        for off, w, vreg, val in r["dma_flags"][:20]:
            print(f"    dma! +{off:#06x}  {w:08x}  addr via {RN[vreg]:<4}  {val}")
    if "dma_notify" in model:
        q = verify_quiesce(data, model)
        print(f"  D2 (no device kick between hash gate and handoff): "
              f"{'PASS' if q['ok'] else 'FAIL'}   "
              f"({len(q['kicks'])} kicks, {len(q['windows'])} gate->handoff windows)")
        for B, site, k in q["bad"][:20]:
            print(f"    kick! +{k:#06x} in window gate +{B:#06x} -> handoff +{site:#06x}")
    for off, w, breg, sz, base, reason in r["flags"][:60]:
        bv = "undef" if base is None else f"{base}"
        print(f"    !! +{off:#06x}  {w:08x}  {sz} via {RN[breg]:<4}  {bv}  {reason}")
    ok = l1_ok and not r["flags"]
    if ok:
        print(f"  => PROVEN (L1+L2): every store confined to one region "
              f"({model['name']} model)")
    else:
        print(f"  => NOT PROVEN: {len(r['flags'])} store(s) unconfined")
    return ok


def selftest():
    le = lambda w: w.to_bytes(4, "little")
    HALT = 0x0000006f
    mmio = le(0x100002b7) + le(0x00628023) + le(HALT)
    topb = le(0x00628023) + le(HALT)

    # Induction-bounding non-vacuity: a counted loop `mv t0,gp; li t1,8; loop:
    # sw zero,0(t0); addi t0,t0,4; addi t1,t1,-1; bnez t1,loop` walks the cursor
    # t0 (= gp, a fixed region base) over 8 words = [0, 0x20).  Run against two
    # regions: one that CONTAINS the walk (must confine) and one too small (the
    # bound 0x20 exceeds it, so it MUST still flag -- proving the bound is real,
    # not a blind "cursor is in some region" pass).
    def bne(frm, to, rs1, rs2=0):
        imm = (to - frm) & 0x1fff
        return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) \
            | (rs2 << 20) | (rs1 << 15) | (1 << 12) | (((imm >> 1) & 0xf) << 8) \
            | (((imm >> 11) & 1) << 7) | 0x63
    indloop = (le(0x00000013)            # nop  (so the merge into +4 forces gp present)
               + le(0x00018293)          # addi t0,gp,0   (t0 = gp = region base)
               + le((8 << 20) | 0x313)   # addi t1,x0,8   (li t1,8)
               + le(0x0002a023)          # sw zero,0(t0)  <- loop @ +12
               + le(0x00428293)          # addi t0,t0,4
               + le(0xfff30313)          # addi t1,t1,-1
               + le(bne(24, 12, 6))      # bne t1,x0      (back to loop)
               + le(HALT))
    ind_model = lambda hi: {
        "name": f"ind{hi:#x}", "anchor": "code_hi",
        "regions": [("buf", 0x0, hi, "code_hi")], "roots": {GP: "buf"},
        "fixed": {GP}, "mmio_store": [], "mmio_load": []}

    cases = [
        ("store via MMIO const", mmio, COMPILER_MODEL, True),
        ("store via TOP base",   topb, COMPILER_MODEL, False),
        ("induction cursor fits region",     indloop, ind_model(0x20), True),
        ("induction cursor OVERFLOWS region", indloop, ind_model(0x10), False),
    ]

    # Exact-base one-past-the-end: a `sw zero,off(t0)` with t0 = gp (the exact
    # region base).  off=region_hi-sz fits; off=region_hi overflows by sz and
    # MUST flag (it touches [hi, hi+sz)); off=hi-1,sz=2 straddles the top and
    # MUST flag.  Guards the exact-base hi_touch = lo+sz fix.
    def exb(off, sz):       # nop; mv t0,gp; s{b,h,w} zero,off(t0); halt
        f3 = {1: 0, 2: 1, 4: 2}[sz]
        s = (((off >> 5) & 0x7f) << 25) | (5 << 15) | (f3 << 12) \
            | ((off & 0x1f) << 7) | 0x23
        return le(0x13) + le(0x00018293) + le(s) + le(HALT)
    cases += [
        ("exact-base store fits region",  exb(4, 4), ind_model(0x8), True),
        ("exact-base store one-past-end",  exb(8, 4), ind_model(0x8), False),
        ("exact-base store straddles top", exb(7, 2), ind_model(0x8), False),
    ]

    # Interval-scalar (value-range) bounding: a masked index, scaled and added to
    # a region base, gives a bounded address.  `andi t1,t1,7` -> [0,7]; `slli
    # t1,t1,1` -> [0,14] (al 2); `add t0,gp,t1` -> P[0,15); `sw zero,0(t0)` touches
    # [0,18).  Region [0,18) fits; [0,16) overflows (max touch 18 > 16) -> FLAG.
    imask = (le(0x00000013)            # nop (force gp present at the add)
             + le(0x00737313)          # andi t1,t1,7
             + le(0x00131313)          # slli t1,t1,1
             + le(0x006182B3)          # add  t0,gp,t1
             + le(0x0002a023)          # sw   zero,0(t0)
             + le(HALT))
    cases += [
        ("interval index fits region",      imask, ind_model(0x12), True),
        ("interval index OVERFLOWS region", imask, ind_model(0x10), False),
    ]
    ok = True
    for name, blob, model, expect in cases:
        got = not analyze(blob, model)["flags"]
        verd = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest {name:24s} expect={'PASS' if expect else 'FAIL'} "
              f"got={'PASS' if got else 'FAIL'} [{verd}]")

    # W^X (P3) non-vacuity: a store into the code image MUST be flagged as not
    # provably-non-code; a store at/above gp (payload) must be W^X-clean.
    wx_cases = [
        ("W^X: store at gp+0 (payload)", exb(0, 4), ind_model(0x8), True),
        ("W^X: store at gp-4 (CODE)",    exb(-4, 4), ind_model(0x8), False),
    ]
    for name, blob, model, expect in wx_cases:
        got = not analyze(blob, model)["wx_flags"]
        verd = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest {name:30s} expect={'CLEAN' if expect else 'FLAG'} "
              f"got={'CLEAN' if got else 'FLAG'} [{verd}]")

    # P4 (CFI) non-vacuity.  rid: s10=ptr s9=floor s11=val.  PUSH = sw s11,0(s10).
    def bgeu(frm, to):                                   # bgeu s10,s9,to
        imm = (to - frm) & 0x1fff
        return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (S9 << 20) \
            | (S10 << 15) | (7 << 12) | (((imm >> 1) & 0xf) << 8) \
            | (((imm >> 11) & 1) << 7) | 0x63
    PUSH = 0x01BD2023      # sw s11,0(s10)
    ADD_S7 = 0x00628BB3    # add s7,t0,t1   (a data-dependent write to a pinned root)
    ADD_S11 = 0x00628DB3   # add s11,t0,t1  (RID set by neither li nor pop)
    cfi_m = {"cfi_roots": {S7}, "rid_ptr": S10, "rid_floor": S9, "rid_val": S11}
    cfi_cases = [   # (name, blob, which_list, expect_clean)
        ("CFI clean (guarded push)",      le(bgeu(0, 8)) + le(HALT) + le(PUSH) + le(HALT), "both", True),
        ("CFI P4a root set in body",      le(PUSH) + le(ADD_S7) + le(HALT), "p4a", False),
        ("CFI P4b push not guarded",      le(PUSH) + le(HALT), "p4b", False),
        ("CFI P4b RID set by add",        le(ADD_S11) + le(HALT), "p4b", False),
    ]
    for name, blob, which, expect in cfi_cases:
        c = analyze_cfi(blob, cfi_m)
        got = (not (c["p4a"] or c["p4b"])) if which == "both" else not c[which]
        verd = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest {name:30s} expect={'CLEAN' if expect else 'FLAG'} "
              f"got={'CLEAN' if got else 'FLAG'} [{verd}]")

    # D1 (DMA) non-vacuity: a descriptor addr (word at offset 0 of a desc table,
    # base gp) pointing into a target is clean; pointing into the code image
    # (gp-4) MUST flag.  `addi t0,gp,IMM; sw t0,0(gp)`.
    dma_m = {"name": "dma", "anchor": "code_hi",
             "regions": [("descs", 0, 0x100, "code_hi"), ("buf", 0x100, 0x200, "code_hi")],
             "roots": {GP: "descs"}, "fixed": {GP}, "mmio_store": [], "mmio_load": [],
             "dma_queues": [("descs", 0, 0x100, "code_hi")],
             "dma_targets": [("buf", 0x100, 0x200, "code_hi")]}
    dput = le(0x0051A023)         # sw t0,0(gp)   (desc[0].addr = t0)
    dma_cases = [
        ("D1 descriptor addr -> target", le(0x13) + le(0x10018293) + dput + le(HALT), True),
        ("D1 descriptor addr -> CODE",   le(0x13) + le(0xFFC18293) + dput + le(HALT), False),
    ]
    for name, blob, expect in dma_cases:
        got = not analyze(blob, dma_m)["dma_flags"]
        verd = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest {name:30s} expect={'CLEAN' if expect else 'FLAG'} "
              f"got={'CLEAN' if got else 'FLAG'} [{verd}]")

    # D2 (quiesce) non-vacuity.  `beq a0,x0,+8` gates a `jal x0,end_marker`
    # handoff; a device kick `sw x0,0x50(s3)` is clean BEFORE the gate (not in the
    # gate->handoff window) but MUST flag when it lands inside the window.
    d2_m = {"name": "d2", "anchor": "code_hi",
            "regions": [("virtio", 0x10001000, 0x10009000, "abs")],
            "roots": {S3: "virtio"}, "fixed": set(),
            "root_window": {S3: (0x10001000, 0x10008001, 0x1000)},
            "mmio_store": [], "mmio_load": [], "dma_notify": 0x50}
    GATE, REJF, REJG, KICK, HOFF = 0x00050463, 0x0000006F, 0x0000006F, 0x0409A823, 0x0040006F
    d2_cases = [
        ("D2 kick BEFORE gate", le(KICK) + le(GATE) + le(REJF) + le(HOFF), True),
        ("D2 kick IN gate->handoff", le(GATE) + le(REJG) + le(KICK) + le(HOFF), False),
    ]
    for name, blob, expect in d2_cases:
        got = verify_quiesce(blob, d2_m)["ok"]
        verd = "OK" if got == expect else "WRONG"
        if got != expect:
            ok = False
        print(f"  selftest {name:30s} expect={'CLEAN' if expect else 'FLAG'} "
              f"got={'CLEAN' if got else 'FLAG'} [{verd}]")

    for mname, model in MODELS.items():
        l1, _ = assert_L1(model)
        print(f"  selftest L1 {mname:8s} disjoint  [{'OK' if l1 else 'WRONG'}]")
        ok = ok and l1
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


def pick_model(path):
    import os
    b = os.path.basename(path)
    if b == "fam0":
        return FAM0_MODEL
    if b.startswith("tabernacle"):
        return TABERNACLE_MODEL
    if b.startswith("fam"):
        return COMPILER_MODEL
    return OUTPUT_MODEL


def main(argv):
    model = None
    paths = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--model":
            model = MODELS.get(argv[i + 1])
            if model is None:
                sys.exit(f"verify_region: unknown model: {argv[i + 1]}")
            i += 2
            continue
        if a == "--selftest":
            return 0 if selftest() else 2
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a.startswith("-"):
            sys.exit(f"verify_region: unknown option: {a}")
        paths.append(a)
        i += 1
    if not paths:
        print(__doc__)
        return 2
    all_ok = True
    for p in paths:
        if not report(p, model or pick_model(p)):
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
