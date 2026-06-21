# COW Trie — the full node's storage engine

This document specifies the on-disk storage engine for the sealed `full_node`
(the fam blockchain client that runs under QEMU). It records **what we are
building** (a copy-on-write radix/HAMT trie over a buffer pool, with a
double-buffered meta sector for crash-safe commit), and — at least as important —
**why** this shape beats the obvious alternatives (a B+Tree, a log-structured
hash) *for this specific use case*.

It is a design doc, not a proof. A status table at the end says what is built and
tested today versus what is still ahead.

Code layout (each on top of the previous; compiled in order):

| file | contents |
|------|----------|
| `src/disk.fam` | virtio-blk block primitives — **multi-slot non-blocking** (`vreq`/`vread`/`vwrite`/`vpoll`/`vstat`/`vflush`, up to 5 in flight) |
| `src/node_disk_store.fam` | **common engine**: buffer pool, meta sector, allocator, transaction, async scheduler *(planned)* |
| `src/node_disk_trie.fam` | the COW trie (32-B key → value) *(planned)* |
| `src/node_disk_pmmr.fam` | PMMR array *(planned)* |
| `src/node_disk_bitmap.fam` | bitmap Merkle tree *(planned)* |

`src/disk.fam` carries its own inline logic tests. A leftover
`tests/node_disk_trie_dev.fam` survives from an earlier prototype but references
files not present in this tree (see §16). The common engine is shared by every
structure; each individual structure lives in its own file.

---

## 1. Context and requirements

The Rust proof-of-concept used **LMDB** (a copy-on-write B+Tree) and it worked
well. We can't use LMDB inside the node — there is no LMDB under QEMU/fam — so we
rebuild the part we need. The environment and workload are specific, and they
drive every decision below:

- **Runtime:** RV32I, no `zicsr` (no interrupts → all I/O is poll-based), one
  thread. ~**128 MB RAM**, but the chain state (PMMR + bitmap + indexes) grows to
  **GBs–TBs** on disk. The index must therefore live on disk and be paged in, not
  held in RAM.
- **Sealed binary:** the node ships once and is never patched (see the sealed-
  release design). The engine code is hashed into the binary. *Simplicity is a
  correctness requirement* — the fewer subtle code paths, the better.
- **I/O surface:** 512-byte sectors via `src/disk.fam`'s **multi-slot, non-blocking**
  primitives. `vread`/`vwrite` *submit* a one-sector request and return a slot id
  **without waiting**; `vpoll` reaps completions into a per-slot `done[]`; `vstat`
  reads a slot's completion flag; `vflush` is the durability barrier (returns the
  `-1` sentinel and is a no-op in writethrough mode). **Up to 5 requests in flight**
  (5 slots × 3 descriptors). One sector = one request. A blocking convenience
  `vwait` exists for the boot path only.
- **One cooperative event loop:** the live node runs a single `evloop` that
  interleaves peer serving with disk work (§6). Nothing the engine does while the
  node is live may block that loop.

What we store, and how it's accessed:

| Data | Shape | Access | Needs ordered range scan? |
|------|-------|--------|---------------------------|
| **PMMR** | append-only MMR of hashes | by position (append / read) | No — direct-indexed array |
| **Bitmap** | fixed-depth Merkle tree, 512 B leaves | set/clear bits → recompute path; read siblings by position | No — positions are computable |
| **Input lookup** | PMMR index → 32-B input hash | point lookup by integer position | No |
| **Headers / blocks** | log by height + index by hash | by height (array) / by hash (point) | No |
| small items (peers, …) | fixed | point | No |

> **The defining property of the workload: everything is a point lookup or a
> positional access. Nothing needs ordered range scans.** All keys are either
> dense integer positions or uniformly-distributed hashes.

The hard requirements the engine must meet:

1. **Atomic multi-structure commit + rollback.** Applying a block writes the
   bitmap, the PMMR, and the kv indexes; either the whole block commits or none of
   it does. (In the Rust PoC this was an LMDB write txn: speculatively apply, read
   back the resulting roots, then commit-or-rollback.)
2. **Snapshot isolation.** A peer reading state (sync serving) must see a
   consistent committed snapshot even while a block — or a multi-second reorg — is
   being applied. Blocking serving for the duration of a deep reorg is a
   denial-of-service vector on a young chain (where deep reorgs are common).
3. **Arbitrary rewind.** Reorgs (commonly 30+ blocks deep when the chain is young)
   require rewinding the materialized state to a fork point and replaying the
   winning branch. The node must *survive* an arbitrary reorg — no stall, crash,
   corruption, or unbounded resource use — because in a low-work young chain you
   cannot *prevent* deep reorgs.
4. **Crash safety.** A power loss mid-commit must leave the last committed state
   intact.
5. **Bounded RAM.** See above: GBs–TBs of state, ~128 MB RAM.
6. **No leak.** fam's `alloc` is a pure bump allocator (never frees), so the
   engine must allocate its RAM structures **once at startup and reuse them** —
   never per-operation.
7. **Non-blocking under the shared event loop.** Every read that serves a peer,
   and every commit that overlaps serving, must be a *resumable state machine*
   driven by the multi-slot primitives — issue a request, yield to `evloop`, resume
   on completion — sharing the 5 disk slots with the network path (§6). A lookup
   that blocks on a page-in stalls all serving for a full disk round-trip per
   uncached level.

> **On pruning.** Under normal operation the node **never prunes** — it is
> archival, so the sizing below is full-history. Reclaiming fully-spent outputs is
> a *separate, offline* program (load the image, compact, exit) that is **out of
> scope here**; taking a node down for it ~monthly is acceptable for the full-node
> use case. This is distinct from the **online** GC of COW-superseded pages past
> the reorg horizon (§8, §11), which the live engine does need.

---

## 2. The decision

> The engine is a **copy-on-write radix/HAMT trie** over a **buffer pool**, with
> all state rooted in a **double-buffered meta sector** that is flipped atomically
> to commit. Page-sized, high-fanout, pointer-only internal nodes keep it shallow;
> dense leaf buckets keep it packed; copy-on-write gives snapshots, atomic commit,
> and rewind for free. All disk access through it is non-blocking (§6).

The crucial realization is that LMDB bundled two separable things, and we only
need one of them:

- an **index structure** (the B+Tree) — we do **not** need this, because we never
  range-scan; and
- a **transaction mechanism** (copy-on-write pages + a single atomic root flip) —
  this is what gave us atomic commit/rollback, snapshots, and rewind.

We keep the second and replace the first with the simplest structure that serves
point lookups: a trie. COW is not specific to B+Trees; it is a property of
"don't overwrite live data + flip one root pointer," and it works on a trie just
as well.

---

## 3. Why not a B+Tree

A B+Tree's one advantage over a hash-keyed structure is **ordered range scans**.
We never range-scan. Stripped of that, the B+Tree is pure cost:

- **Rebalancing (splits, merges, underflow redistribution) is the largest and
  buggiest part of a B+Tree, and COW makes it worse** (splitting a *shared* node
  and propagating the split up through copied parents). For a binary we seal once
  and can never patch, deleting the buggiest subsystem is worth a great deal. A
  trie has *no* rebalancing — its shape is fixed by the key bits.
- **A trie is shallower per point lookup** (see §10 and §15): trie internal nodes
  store *pointers only* (the key bits are positional), while B+Tree internal nodes
  must store *keys* for comparison. So a 512 B page holds ~5–9× the fanout as a
  trie node, making the tree shallower → fewer page reads (→ fewer async
  round-trips, §6) per lookup.
- The B+Tree's dense per-page key packing only pays off for range scans; for a
  point lookup you use exactly one entry per page either way.

---

## 4. Why not a log-structured hash

A log-structured hash (Bitcask-style: an append-only log of `(key,value)` records
+ a hash index mapping key → log offset) is a fine engine for append-heavy local
data — but it loses on our hard requirements:

- **The index is classically in RAM.** Our biggest tables (input lookup, headers)
  reach billions of entries at full capacity; an in-RAM index of that many keys is
  far beyond a 128 MB node. (Bitcask's known constraint: "the keydir must fit in
  RAM.") Pushing the index onto disk either gives up versioning (in-place) or *is*
  a COW trie (versioned) — so it doesn't escape the trie.
- **The index is unversioned.** Snapshots and rewind need a consistent view *as of
  block B*; a mutable hash index can't provide that without replaying the log or
  versioning the index (→ COW).
- **Recovery scans the log** to rebuild the index at every boot, growing with the
  log. COW recovery is reading one meta sector — instant.
- **The bitmap is a Merkle tree by necessity** (its root is consensus), so we have
  a COW tree regardless; unifying the kv tables under the same engine is cleaner
  than bolting a second mechanism (with its own index + recovery + compaction)
  alongside it.

> Where the log-structured idea **is** right: genuinely append-only data that
> never rewinds — **the PMMR** (a flat append-only file) and **block bodies**. We
> already treat those as logs. And the COW trie is itself log-structured *in its
> writes*: COW copies go to fresh, sequentially-allocated pages and GC reclaims the
> dead ones. We capture the log-structured benefit exactly where it fits, without
> paying for an in-RAM index or losing versioning on the state that needs it.

---

## 5. Page model and buffer pool

- **Page = 512 B = one disk sector = one I/O request.** Page number == sector
  number. Pages 0 and 1 are the meta (§7); data pages start at 2.
- **Buffer pool** (`bp_*`): one LRU-approximation (**CLOCK**, second-chance) cache
  of fixed page frames, allocated once at startup. It serves **both** reads
  (page-in) and writes (dirty pages held until commit). Frames are *interleaved*
  (data + metadata together) so one pointer addresses both:

  ```
  frame (stride 0x210):  data[0x200]  page@0x200 (FFFFFFFF=empty)
                         flags@0x204 (bit0 dirty, bit1 ref, bit2 filling)
                         pin@0x208    slot@0x20C (in-flight read's slot id)
  ```

- **Page-in is non-blocking.** A frame can be in three states: *valid* (resident),
  *empty*, or *filling* (a `vread` is in flight into its data buffer, slot id in
  `slot@0x20C`, `flags` bit2 set). The pool words split accordingly:

  - `bp_probe ( page -- frame|0 )` — pool hit check; returns a *valid* pinned frame
    or 0.
  - `bp_start ( page -- frame )` — on a miss, clock-evict a victim, pin a frame for
    `page`, issue a `vread` into it, mark it *filling*, record the slot. Returns the
    (not-yet-valid) frame; the caller must not read it until §6's fiber sees the
    completion.
  - `bp_ready ( frame -- frame done? )` — `vstat` the frame's slot; on completion
    clear *filling*, mark *valid*, release the slot.
  - `bp_alloc` (fresh page, no read — dirty + pinned + valid), `bp_dirty`,
    `bp_unpin`, `bp_wb` / `bp_flush` (write back one / all dirty; writebacks may
    pipeline across the 5 slots).
  - `bp_get` — the **blocking** convenience (`bp_start` then pump `vpoll` until
    `bp_ready`). **Boot path only** (§6.4); using it while serving is a bug.

> **The key property that makes one pool serve reads and writes:** because COW
> writes go to **fresh** pages that are invisible until the meta flips, dirty
> *uncommitted* pages can be evicted to disk safely — they are unreferenced garbage
> until a commit points at them. So a transaction is **never bounded by RAM**, and
> rollback of an evicted page is just "return its page number to the allocator."

---

## 6. Asynchronous, non-blocking access

The live node is a single cooperative event loop. `evloop` already interleaves the
background disk-save (`dsk_step`, a resumable state machine over the multi-slot
primitives) with peer serving (`serve1`, one packet per pass):

```
: evloop begin dsk_step serve1 0 lit until ;
```

A storage lookup that *blocked* on a page read would freeze that loop — no packets
served, no other disk completions advanced — for an entire disk round-trip **per
uncached level**. On a tree 2–4 levels deep, every cache miss while serving a peer
is several such stalls. So the engine must run **inside** `evloop`, not around it.
This is the whole reason the disk layer is multi-slot and non-blocking.

### 6.1 Operations are resumable fibers

A disk-touching operation (trie descent, PMMR/bitmap read, commit writeback) is a
**fiber**: a small caller-allocated context block plus a `step` word that advances
it by at most one page-read's worth of work and **never blocks**. A trie-descent
fiber's context holds:

- the key (or position) being looked up,
- the descent cursor: current node page#, level,
- the frame it is reading into, and the slot id of the in-flight read,
- a phase, and a place for the result.

```
lk_step ( ctx -- ctx done? )
  outstanding read?  -> bp_ready ; not done -> return pending
                     -> page now valid: read this level's child pointer
                        (or, at a leaf, scan the bucket)
                        next page -> bp_start, record slot, return pending
                        leaf hit  -> fill result, return done
```

The fiber folds into the loop exactly like `dsk_step`:

```
: evloop begin dsk_step eng_step serve1 0 lit until ;
```

where `eng_step` pumps `vpoll` once and advances every active engine fiber by one
step. `serve1` still runs every pass, so peer serving never starves behind storage
work and vice-versa.

### 6.2 Concurrency is across fibers, not within a descent

A single descent is inherently serial: level N's page contains the pointer to
level N+1, so you cannot read them in parallel. The win from the 5 in-flight slots
is **independent** operations overlapping:

- different peers' lookups in flight at once,
- a block-apply that reads the trie, the PMMR, and the bitmap — three independent
  descents that can each occupy a slot,
- the background image-save and commit writebacks (which *can* pipeline: many
  independent sector writes).

So throughput under serving load comes from many concurrent fibers, each
contributing one outstanding read — not from accelerating any one descent. The
descent's *latency* is reduced instead by keeping the tree shallow (§15) and the
top levels cached.

### 6.3 Slot ownership above the rotating allocator

`disk.fam`'s `nslot` hands out slot ids 0..4 round-robin and assumes you reap a
slot's completion before it comes around again (true for the single-in-flight
background save). With several fibers outstanding that invariant breaks: a 6th
request would reuse slot 0 and clobber an unreaped completion. The engine
therefore keeps a **5-entry slot-ownership table** above `disk.fam`: a fiber
*claims* a free slot, holds it until its completion is consumed, then releases it;
`eng_step` only issues a new read for a fiber when a slot is free. This caps
concurrent disk-bound fibers at 5 and makes back-pressure explicit — a fiber that
can't get a slot simply waits its turn in `evloop`. Bounded, no queue growth.

### 6.4 The blocking path is the exception, by design

Two paths may still block, and only because nothing is being served yet:

- **Boot** (`mt_boot`, PoW-table load): runs before the event loop starts; `vwait`
  is fine.
- **Genesis / `tr_init`**: one-time startup.

Everything that runs while the node is live — every lookup that serves a peer, and
the commit writeback that overlaps serving — uses the non-blocking fiber path. The
blocking `bp_get` / `vwait` convenience exists *only* for the boot path; calling it
on the serving path is a bug.

### 6.5 Commit overlaps serving via the COW snapshot

Because readers always read a *committed* root (§9, §11) and COW writes go to fresh
pages invisible until the meta flips (§7), a commit's dirty-page writeback can run
as its own fiber, pipelined across slots, **while peers are still served from the
previous committed snapshot**. The single meta flip at the end is one sector write
plus its flush. So even a multi-second block-apply or reorg never blocks serving —
the requirement from §1 and §2.

---

## 7. Meta sector — the crash-safe commit point

The entire engine state lives in **one 512 B meta sector, double-buffered across
pages 0 and 1**:

```
+0x000 magic(4)=0x54524945   +0x004 counter(4)   +0x008 trie_root(4 page#)
+0x00C next_page(4, bump alloc hi-water)   +0x010 free_head(4, GC later)
... reserved: pmmr_len, bitmap_root, chain tip ...   +0x1FC checksum(4)
```

- **Commit** writes the **off** slot (`1 - current`) — the one not currently live
  — bumps the counter, recomputes the checksum, and `vflush`es. A single sector
  write makes it durable.
- **Boot** reads both slots and takes the one with a **valid checksum and the
  higher counter**. A torn or interrupted commit fails its checksum, so boot
  simply falls back to the previous slot. A fresh disk (neither valid) → genesis.

> This is the whole crash-safety story: a power loss mid-commit either leaves the
> new meta fully durable (higher counter, valid checksum) or falls back to the
> previous committed meta. There is no in-between.

---

## 8. Page allocator

`pg_new` allocates a fresh disk page: pull from the free-list head if non-empty,
else bump `next_page` in the working meta. **Rollback resets `next_page`**, so a
rolled-back transaction's pages are simply reused — no per-transaction tracking
list (and therefore no RAM allocation) is needed.

Reclaiming *superseded* pages (those belonging to roots that age out past the
reorg horizon) is **online garbage collection** via the free-list — a later
concern, not on the commit path. Until then disk grows monotonically; that is a GC
problem, not a RAM leak. This online page GC is **separate** from the offline
spent-output pruning described in §1 (which shrinks the live data set and is out of
scope here).

---

## 9. The transaction

The transaction is thin, because the pool and meta do the work:

- **`tx_begin`** — copy the committed meta into the working meta (start from the
  committed state).
- **`tx_commit`** — `bp_flush` (dirty data pages out, pipelined across slots) →
  `vflush` (data durable) → `mt_save` (write the off meta slot → `vflush` → flip).
  The **data-before-meta** flush ordering is the barrier: the meta only ever points
  at pages already durable. On the live node this runs as a fiber so serving
  continues from the committed snapshot throughout (§6.5).
- **`tx_rollback`** — invalidate the pool's dirty frames (discard the txn's COW
  copies), reset `next_page`, restore the working meta from the committed copy. The
  committed meta never moved.

> **The validate-by-applying pattern** (from the Rust PoC) falls out for free, and
> it's exactly what block validation needs: speculatively apply the block (COW into
> fresh pages), **read the resulting PMMR/bitmap roots back from the new root** —
> the structure maintained those hashes as a side effect of the apply, so you avoid
> re-deriving them in a separate in-memory pass — compare against the block header,
> then `tx_commit` if valid or `tx_rollback` if not. Rollback touches no disk
> (dirty pages stayed in the pool); commit is one meta flip. **Single writer, one
> transaction at a time** — no concurrency control needed (readers ride the
> committed snapshot, §6.5).

---

## 10. The trie

A copy-on-write **radix / HAMT** trie keyed by `table_id ‖ key`.

**Node format — sized to fill the page (this is the crux of the read-cost story).**
Each internal node is **one page** and stores **child pointers only** (the key bits
are positional; no keys stored internally), packed sparsely with a bitmap +
popcount so a sparse node stays compact:

- ~512 B / 4 B-per-pointer → **fanout ~64–128** (vs a B+Tree's ~14, which must
  store 32-byte keys + pointers). Higher fanout → **shallower tree → fewer page
  reads → fewer async round-trips** (§6, §15).
- COW per write copies one page per level on the path; a shallower tree means
  fewer copies per write.

**Leaves are dense bucket pages.** A leaf is a packed array of `(key, value)`
entries. A bucket **splits only when it overflows its page**, by descending one
more hash bit (uniform keys → ~50/50 split). This gives the same ~69% average
fill a B+Tree leaf reaches under random inserts — *without* sorted order or
rebalancing. Large values (block bodies) go **out-of-line** in their own sector
runs with the bucket holding `key → pointer`; small values (input hash, position)
stay **inline**.

**Partitioning by prefix.** Tables are logical, not physical: prefix each table's
keys (`\0`=…, `\1`=…), and the trie self-partitions — the top-level node's children
*are* the tables. One shared page pool, no per-table reservation, no wasted space,
grows organically (the LMDB property, native to a trie). Keep the prefix **literal**
(don't hash it away) so each table stays in its own iterable subtree.

---

## 11. Snapshot, retained roots, and reorg

Copy-on-write gives the reorg/snapshot requirements directly:

- **A commit is one new root** (`trie_root` in the meta). **Retain one root per
  block across the reorg horizon** (a few thousand blocks): a reader uses any
  retained root for a consistent snapshot, and rewind to block *B* is "use root
  R_B" — instant, no replay of the rewound prefix.
- **Reorg** = take the common-ancestor's retained root and **replay the winning
  branch forward** via COW into a new root, then flip the meta. The old chain's
  root stays valid and **servable the entire time**, so the reorg never blocks
  serving — the property an undo-log could not give and the one that defuses the
  deep-reorg DoS.
- **Cleanup at the horizon** GCs pages unreachable from any retained root (the
  online page GC of §8).

The chain model this serves (standard Bitcoin/Grin): **one materialized
chainstate** at the tip; competing blocks are stored as block *data* within the
horizon (not materialized); a reorg rewinds + replays the single state. Validation
(which needs the block's proof) is orthogonal to rewinding (mechanical, always
needed).

---

## 12. What lives where

- **PMMR** — a flat **append-only file**, not in the trie (sequential nodes don't
  want path-copy; it's servable directly and rewinds by truncation). Its length
  rides in the meta.
- **Input lookup (PMMR index → 32-B input hash)** — the canonical **COW trie**
  table: an integer position keys a 32-byte value. Positions are dense, so the trie
  over big-endian position is near-full and shallow.
- **Bitmap** — a COW **Merkle tree** (its root is consensus). COW path-copy *is*
  the Merkle-root recompute we already do. Its logical shape is fixed by consensus
  (deep/binary), but its **on-disk layout is ours** — pack a subtree per page so a
  traversal isn't one read per level.
- **Headers / blocks** — entries in the **COW trie** (point lookups by height or
  hash; bodies out-of-line per §10).
- **Small fixed items** (known peers, etc.) — a small fixed partition carved at
  startup.

All of their roots/lengths live in the one meta sector, so a single flip commits
everything atomically. This is the "one engine, three structures" shape: a shared
COW page-store (pool + meta + allocator + txn + async scheduler) with the trie,
the PMMR, and the bitmap as distinct node layouts committing together.

---

## 13. Allocation discipline

> **The engine calls `alloc` only at startup (`tr_init`) and reuses those
> structures for the node's whole life.** There is one writer and one transaction
> at a time, so the working/committed meta buffers, the pool, the slot-ownership
> table, and the engine fibers' contexts are fixed and reused; the dirty-page set
> *is* the pool (not a per-txn list). Nothing is allocated per block or per
> operation, so nothing leaks through the bump allocator. The only thing allocated
> repeatedly is **disk pages**, via the free-list/`next_page` — which reclaims by
> design.

If a genuinely variable-size, per-operation RAM need ever appears, *that* is when
we build a slab allocator on top of bump — not before.

---

## 14. Security framing

In a young, low-work chain you cannot prevent deep reorgs, so the engine's job is
to **survive arbitrary reorgs** without stall, crash, corruption, or resource
exhaustion — the reorg path is adversarial input.

- **Crash-safe atomic flip** (§7) means a crash or a maliciously-truncated reorg
  mid-apply can never corrupt committed state.
- **Non-blocking reorg** (§11, COW snapshot; §6, fibered commit) means a reorg is
  not a serving-DoS.
- **Bounded resources** are explicit parameters: the **horizon depth K** (retained
  roots), **fork-tree pruning** (drop branches that can't overtake the tip),
  **page GC** of superseded pages, and the **5-slot cap** on concurrent disk-bound
  fibers (§6.3). A reorg deeper than K degrades to a safe re-sync from peers
  (verified against the new tip's proven roots), never a crash.
- **Cost asymmetry via the proof:** validating a candidate branch from its
  header/proof is cheap, so junk branches cost ~nothing; only a genuinely heavier
  valid chain (real proof-of-work) forces a materialization. That bound is what
  keeps reorg handling from being an amplification DoS. *(v1 may ship without the
  recursive proof — per-block STARKs still shrink transactions and you download all
  blocks; the recursion is added independently later. Either way each header
  commits the PMMR root + bitmap root.)*

---

## 15. Read-amplification analysis

For a point lookup the cost is **tree depth = page reads = sequential async
round-trips** (§6: each uncached level is a `vread` + yield + resume), and depth is
set by **fanout per page**:

| | entry stored in internal node | bytes/entry | fanout per 512 B | depth for 10M keys |
|---|---|---|---|---|
| B+Tree | key + pointer | ~36 | ~14 | ⌈log₁₄(10M)⌉ ≈ **7** |
| COW trie | pointer only | 4 | ~64–128 | ⌈log₆₄(10M)⌉ ≈ **4** |

The trie is **shallower**, because its internal nodes carry no keys (the key bits
are positional). The full key compare happens once, at the leaf bucket. With the
top 1–2 levels always cached (a handful of pages), a lookup is ~2–3 *uncached*
round-trips — at or below a B+Tree. The B+Tree's dense key packing helps range
scans (which we never do), not point lookups (one entry per page used either way).
Because each uncached level is a serial round-trip (§6.2), shallower depth
translates directly into lower per-lookup serving latency.

The residual cost is sparse internal nodes under-filling a page; bounded by using
a HAMT bitmap (compact sparse nodes) + dense leaf buckets (the bulk of the data),
with the dense, cached top levels carrying most lookups.

---

## 16. Status

The **transactional COW page store, the COW trie, and the async lookup fibers are
built and device-tested** (`src/node_disk_store.fam`, `src/node_disk_trie.fam`);
what remains is the other structures (PMMR/bitmap), snapshot/retained-roots/GC, and
wiring the engine into the live node. An earlier prototype
(recorded in project notes) built the pool/meta/txn/trie against a now-removed
*single-slot* `src/node_disk.fam`; that code is **not present here**, and the async,
multi-slot model in §6 supersedes it.

| Layer | Status (this tree) | Notes |
|-------|--------------------|-------|
| Block primitives (`src/disk.fam`) | **done** | multi-slot non-blocking `vreq`/`vread`/`vwrite`/`vpoll`/`vstat`/`vflush` (+ blocking `vwait`); inline logic tests + real-device path via `tools/fam --test --disk=` |
| Buffer pool (§5) | **done** | CLOCK eviction; non-blocking page-in (`bp_probe`/`bp_start`/`bp_ready`) + blocking `bp_get` (boot only) + `bp_alloc`/`bp_dirty`/`bp_unpin`/`bp_wb`/`bp_flush`/`bp_drop`. Logic tests `pool_ini`/`frm_mth`/`probe_ms`/`probe_ht`/`evict_c`/`alloc_t`/`dirty_t`; device `evict_rt` |
| Meta sector + allocator (§7, §8) | **done** | double-buffered meta (magic/counter/checksum) across pages 0/1; `mt_boot`/`mt_save`/`mt_gen`, `pg_new` bump allocator; the single `eng_init` allocation point owns all RAM (§13). Logic `meta_gen`/`meta_ck`/`meta_cp`/`pgnew_t`; device `mt_cycle` (genesis/commit/reboot/flip/torn-fallback) |
| Transaction (§9) | **done** | `tx_begin`/`commit`/`rollback`; data-before-meta flush barrier. Device `tx_rt` (commit persists across a fresh-pool reboot) + `tx_rb` (rollback restores root + next_page) |
| COW trie (§10) | **done** | 32-B key -> 32-B value; bucket leaves (CAP 7) + 128-way internal nodes (7 bits/level via a 16-bit window); `tr_get`/`tr_put` with path-recording descent, COW ascend (`in_cow`), and single-level `bk_split`. Pre-allocated trie context `tc` (in reserved `eng+0x10`) keeps the data stack shallow. Device `trie_rt` + `trie_spl`. **Refinements pending**: cascade splits (a child sharing the split level's bits could overflow), large values out-of-line, HAMT-compact sparse internal nodes, integer-key shallowness for the input-lookup table |
| Async scheduler / fibers (§6) | **done** | resumable lookup fiber `lk` (DESCEND/WAIT/PROCESS/DONE) over `bp_probe`/`bp_start`/`bp_ready` — issues a `vread` and yields, resumes on completion; `lk_step` is the per-pass primitive evloop calls, `lk_run` the blocking boot/test driver. Each fiber owns a fixed disk slot (set into `ds.next` before `bp_start`) — the §6 slot-ownership table for ≤5 concurrent fibers. Device `async_rt` (single fiber, fresh-pool real reads) + `async_2` (two fibers interleaved on slots 0/1). **Pending**: wiring `lk_step` into `full_node.fam`'s `evloop` (engine not yet in the node); async writeback so the commit path can overlap serving (read path assumes a clean pool); dynamic slot free-list for >5 fiber churn |
| Structures: PMMR / bitmap (§12) | **not started** | |
| Snapshot / retained roots / page GC (§11) | **not started** | |

CI: `src/disk.fam` + `src/node_disk_store.fam` inline logic tests run under the fam
test framework; the device tests (`tests/node_disk_store_dev.fam`) run with `--disk=`.
A `test_node_disk` job will gate these engine layers as they settle.
