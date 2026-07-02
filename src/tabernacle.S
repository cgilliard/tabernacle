# ──────────────────────────────────────────────────────────────────────────────
# src/tabernacle.S — sealed bootstrap loader for famchain.
#
# Built via:
#     python3 tools/s2fam0_tabernacle.py src/tabernacle.S src/tabernacle.fam0
#     run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
# (src/tabernacle.fam0 is checked in; scripts/build.sh runs only the second
#  step — rerun the generator after editing this file.)
#
# Boot ABI (we set up our own gp via auto-prologue below):
#     PC = 0x80000000     entry of this binary
#     gp = end_marker     byte just past tabernacle.bin
#                         (full_node.bin is concatenated after, so
#                          gp = full_node base; gp-40 = config [nchunks,bin_size,hash].)
#
# Calling convention — NO JALR.  Subroutines are reached via direct `j`
# with a per-call-site dispatch tag.  Mirrors the CALL/BST macros in
# src/fam.S; pinned registers:
#     s11 = current return ID (set by CALL)
#     s10 = RID-stack ptr     (decreases on push)
#     s9  = RID-stack bottom  (bounds check)
#     s7  = full_node base    (page-aligned, persists for handoff)
# Callee saves nothing on RID stack itself; CALL pushes/pops s11.
# ──────────────────────────────────────────────────────────────────────────────

	.text
	.globl _start

# ── Constants ─────────────────────────────────────────────────────────────
	.equ UART_BASE,         0x10000000
	.equ UART_LSR,                 0x5
	.equ UART_RX_READY,            0x1
	.equ SHUTDOWN_ADDR,       0x100000
	.equ SHUTDOWN_PASS,         0x5555
	.equ SHUTDOWN_FAIL,        0x13333

	.equ STACK_SIZE,         0x100000      # 1 MiB data stack
	.equ RID_BASE_OFF,       0x100000      # RID stack lives just above sp top
	.equ RID_SIZE,             0x1000      # 256 frames × 16 B header (overkill)
	.equ PAGE_SIZE,             0x1000
	.equ NEG_PAGE_SIZE,     0xFFFFF000
	.equ PAGE_MASK,              0xFFF

	# BIN_SIZE and NCHUNKS are data words at gp-36 and gp-40,
	# patched by scripts/build.sh after compiling tabernacle.fam0.

	.equ SEED_LIST_OFFSET,      0xA000
	.equ TIMETIK,               0x9FFC
	.equ BPSAVE,                0x9FF8
	.equ NS_RTRY,               0x9FE8      # last retry-send mtime (4 B)
	.equ NP_CNT,                0x9FE4      # no-progress poll counter (4 B, transitional)
	.equ WD_TICK,               0x9FE0      # watchdog: last-progress mtime (4 B)
	.equ RND_START,             0x9FDC      # random probe-iteration start (1 B), set once
	.equ DBGFLAG,               0x9FD8      # debug flag (4 B): 0=quiet, 1=verbose
	.equ BATCH_START,           0x9FDA      # current batch start chunk (2 B)
	.equ NB_SIZE,                  64       # chunks per batch
	.equ NF_CNT,                0x9FF2      # blacklist fail count (2 B)
	.equ NF_MASK,               0x9FF4      # blacklist bitmask, bit i = seed i failed
	.equ MAX_SEEDS,                 16
	.equ DEFAULT_TIMEOUT_TK, 0x05F5E100
	.equ MTIME_ADDR,         0x200BFF8      # CLINT mtime (RV virt machine)
	.equ MT_KHZ,                 10000      # mtime frequency in kHz (10 MHz)
	.equ IPS_TICKS,           0x7A120      # 500000 ticks = 50 ms inter-probe spacing
	.equ NRTRY_TK,           0x1E8480      # 2,000,000 ticks = 200 ms min retry interval
	# NB_BMAP — chunk-received bitmap.  ceil(NCHUNKS / 8) bytes.
	# At 8 KB max NCHUNKS supported (= 64K bits).
	.equ NB_BMAP,               0xA080
	.equ NB_BMAP_BYTES,           1024


# ── Static-dispatch macros (no JALR), lifted from src/fam.S ───────────────
	.altmacro
	.set _CSN, 0

.macro CALL target
	.set _CSN, _CSN + 1
	addi    s10, s10, -4
	bgeu    s10, s9, .L_call_ok_\@
	j       panic
.L_call_ok_\@:
	sw      s11, 0(s10)
	li      s11, _CSN
	j       \target
	EMIT_LABEL %_CSN
	lw      s11, 0(s10)
	addi    s10, s10, 4
.endm

.macro EMIT_LABEL n
.L_csret_\n:
.endm

.macro BST lo, hi
	BST_R %\lo, %\hi
.endm
.macro BST_R lo, hi
	.if \hi == \lo
.L_bst_\lo\()_\hi:
		j .L_csret_\lo
	.else
		.set _BST_MID, (\lo + \hi) / 2
		BST_NODE %\lo, %\hi, %_BST_MID, %(_BST_MID - 1), %(_BST_MID + 1)
	.endif
.endm
.macro BST_NODE lo, hi, mid, lhi, rlo
.L_bst_\lo\()_\hi:
	li      t0, \mid
	.if \lhi >= \lo
		bge s11, t0, .L_bst_\lo\()_\hi\()_R
		j   .L_bst_\lo\()_\lhi
.L_bst_\lo\()_\hi\()_R:
	.endif
	.if \rlo <= \hi
		ble s11, t0, .L_bst_\lo\()_\hi\()_E
		j   .L_bst_\rlo\()_\hi
.L_bst_\lo\()_\hi\()_E:
	.endif
	j       .L_csret_\mid
	.if \lhi >= \lo
		BST_R %\lo, %\lhi
	.endif
	.if \rlo <= \hi
		BST_R %\rlo, %\hi
	.endif
.endm

# PC-relative load-address (avoids `la` which doesn't relax under -march=rv32i).
.macro LOAD_ADDRESS reg, label
_base\@:
	.equ _offset\@, (\label - _base\@)
	auipc   \reg, %pcrel_hi(\label)
	addi    \reg, \reg, %pcrel_lo(_base\@)
.endm

# ──────────────────────────────────────────────────────────────────────────────
# _start
# ──────────────────────────────────────────────────────────────────────────────

_start:
	# ── §0 Auto-prologue (NOP magic + gp = end_marker). ──────────────
	addi    zero, zero, 0
	LOAD_ADDRESS gp, end_marker

	# ── §1 Page-align s7, then carve sp / s10 / s9 above it. ─────────
	# s7 = full_node base (page-aligned).
	# sp     = s7 + STACK_SIZE              (data stack top, grows down)
	# s10    = s7 + STACK_SIZE + RID_SIZE   (RID stack top, grows down)
	# s9     = s7 + STACK_SIZE              (RID stack bottom — when s10
	#                                        reaches s9 we're full)
	mv      s7, gp
	lw      t0, -36(gp)
	add     s7, s7, t0
	li      t0, PAGE_MASK
	add     s7, s7, t0
	li      t0, NEG_PAGE_SIZE
	and     s7, s7, t0

	li      t0, STACK_SIZE
	add     sp, s7, t0
	mv      s9, sp                          # RID bottom = sp top
	li      t0, RID_SIZE
	add     s10, s9, t0                     # RID top
	# Per fam.S convention, s11 starts at 0 (no enclosing call frame).
	li      s11, 0

	# ── §2 Zero 0xB000 bytes at s7 (covers virtio queues + buffers + the
	#     control / seed-list / chunk-bitmap region around 0xA000). ──
	mv      t0, s7
	li      t1, 0x2C00                     # 0xB000 / 4 = 0x2C00 words
zero_top:
	sw      zero, 0(t0)
	addi    t0, t0, 4
	addi    t1, t1, -1
	bne     t1, zero, zero_top

	# UART base in s8 (callee-saved across CALL).
	lui     s8, %hi(UART_BASE)
	li      t3, 0                           # skip_phase2 flag


# ──────────────────────────────────────────────────────────────────────────────
# UART config parser — reads "<bind_port> <debug> <timeout_ms> <ip:port> ...\004"
# Storing parsed state at:
#   s4               = bind_port
#   s7 + DBGFLAG     = debug flag (0=quiet, 1=verbose)
#   s7 + TIMETIK     = timeout in MTIME ticks
#   s7 + BPSAVE      = bind_port (mirror)
#   s7 + SEED_LIST_OFFSET = [u8 count][N × 6 B (4 IP + 2 LE port)]
# ──────────────────────────────────────────────────────────────────────────────

# ── Phase 1: bind_port ────────────────────────────────────────────────────
	li      s6, 0
ph1_top:
	lbu     t0, UART_LSR(s8)
	andi    t0, t0, UART_RX_READY
	beqz    t0, ph1_top
	lbu     t6, 0(s8)

	li      t0, 4
	bne     t6, t0, 1f
	li      t3, 1
	j       ph1_done
1:	addi    t0, t6, -'0'
	li      t1, 10
	bgeu    t0, t1, ph1_done

	slli    t1, s6, 3
	slli    t4, s6, 1
	add     s6, t1, t4
	add     s6, s6, t0
	j       ph1_top
ph1_done:
	mv      s4, s6

# ── Phase 1a: debug flag ─────────────────────────────────────────────────
	bnez    t3, ph1a_skip
	li      s6, 0
ph1a_top:
	lbu     t0, UART_LSR(s8)
	andi    t0, t0, UART_RX_READY
	beqz    t0, ph1a_top
	lbu     t6, 0(s8)

	li      t0, 4
	bne     t6, t0, 1f
	li      t3, 1
	j       ph1a_done
1:	addi    t0, t6, -'0'
	li      t1, 10
	bgeu    t0, t1, ph1a_done

	slli    t1, s6, 3
	slli    t4, s6, 1
	add     s6, t1, t4
	add     s6, s6, t0
	j       ph1a_top
ph1a_done:
ph1a_skip:
	li      t0, DBGFLAG
	add     t0, s7, t0
	sw      s6, 0(t0)

# ── Phase 1b: timeout_ms ──────────────────────────────────────────────────
	bnez    t3, ph1b_skip
	li      s6, 0
ph1b_top:
	lbu     t0, UART_LSR(s8)
	andi    t0, t0, UART_RX_READY
	beqz    t0, ph1b_top
	lbu     t6, 0(s8)

	li      t0, 4
	bne     t6, t0, 1f
	li      t3, 1
	j       ph1b_done
1:	addi    t0, t6, -'0'
	li      t1, 10
	bgeu    t0, t1, ph1b_done

	slli    t1, s6, 3
	slli    t4, s6, 1
	add     s6, t1, t4
	add     s6, s6, t0
	j       ph1b_top
ph1b_done:
ph1b_skip:


# ── Compute timeout in MTIME ticks → mem[s7 + TIMETIK] ───────────────────
	beqz    s6, timeout_default
	slli    t0, s6, 13
	slli    t1, s6, 11;  add t0, t0, t1
	slli    t1, s6, 8;   sub t0, t0, t1
	slli    t1, s6, 4;   add t0, t0, t1
	j       timeout_store
timeout_default:
	li      t0, DEFAULT_TIMEOUT_TK
timeout_store:
	li      t1, TIMETIK
	add     t1, s7, t1
	sw      t0, 0(t1)


# ── Phase 2: seed list ────────────────────────────────────────────────────
	li      s5, 0                           # seed count
	bnez    t3, ph2_skip

	li      t2, SEED_LIST_OFFSET
	add     t2, s7, t2
	addi    t2, t2, 1                       # entries base (skip count byte)
	li      s6, 0                           # accumulator
	li      t3, 0                           # field 0..3 = octets, 4 = port

ph2_top:
	lbu     t0, UART_LSR(s8)
	andi    t0, t0, UART_RX_READY
	beqz    t0, ph2_top
	lbu     t6, 0(s8)

	li      t0, 4
	bne     t6, t0, ph2_not_eot
	li      t0, 4
	bne     t3, t0, ph2_done
	li      t0, MAX_SEEDS
	bge     s5, t0, ph2_done
	sh      s6, 4(t2)
	addi    s5, s5, 1
	j       ph2_done

ph2_not_eot:
	addi    t0, t6, -'0'
	li      t1, 10
	bgeu    t0, t1, ph2_sep
	slli    t1, s6, 3
	slli    t4, s6, 1
	add     s6, t1, t4
	add     s6, s6, t0
	j       ph2_top

ph2_sep:
	li      t0, '.'
	bne     t6, t0, ph2_not_dot
	li      t0, 3
	bge     t3, t0, ph2_top
	j       ph2_store_advance
ph2_not_dot:
	li      t0, ':'
	bne     t6, t0, ph2_space
	li      t0, 3
	bne     t3, t0, ph2_top
ph2_store_advance:
	add     t4, t2, t3
	sb      s6, 0(t4)
	addi    t3, t3, 1
	li      s6, 0
	j       ph2_top
ph2_space:
	li      t0, 4
	bne     t3, t0, ph2_reset
	li      t0, MAX_SEEDS
	bge     s5, t0, ph2_reset
	sh      s6, 4(t2)
	addi    s5, s5, 1
	addi    t2, t2, 6
ph2_reset:
	li      s6, 0
	li      t3, 0
	j       ph2_top

ph2_done:
ph2_skip:

	li      t0, SEED_LIST_OFFSET
	add     t0, s7, t0
	sb      s5, 0(t0)
	li      t0, BPSAVE
	add     t0, s7, t0
	sw      s4, 0(t0)


# ──────────────────────────────────────────────────────────────────────────────
# §3 Disk boot:
#     scan_disk → init virtio-blk → read full_node into [s7..s7+BIN_SIZE)
#     → gimli_hash → compare to hash_data → handoff.
# A missing block device or a read error halts (halt_no_disk); a successful
# read whose hash does not match falls through to §5 net boot.
# ──────────────────────────────────────────────────────────────────────────────

	CALL    scan_disk                       # → s3 = disk MMIO base, or fall to halt_d

	# ── Virtio-blk handshake (legacy MMIO) ──
	sw      zero, 0x70(s3)                  # status = 0
	li      t1, 1
	sw      t1, 0x70(s3)                    # status = 1 (ACKNOWLEDGE)
	lw      t1, 0x70(s3)
	ori     t1, t1, 2
	sw      t1, 0x70(s3)                    # status |= 2 (DRIVER)
	sw      zero, 0x20(s3)                  # driver_features = 0
	lw      t1, 0x70(s3)
	ori     t1, t1, 8
	sw      t1, 0x70(s3)                    # status |= 8 (FEATURES_OK)
	lw      t1, 0x70(s3)
	andi    t2, t1, 8
	beqz    t2, halt_no_disk                # FEATURES_OK didn't stick

	li      t1, PAGE_SIZE
	sw      t1, 0x28(s3)                    # V_GPS = 0x1000
	sw      zero, 0x30(s3)                  # V_QSEL = 0
	sw      t1, 0x3C(s3)                    # V_QALGN = 0x1000
	li      t1, 16
	sw      t1, 0x38(s3)                    # V_QNUM = 16
	srli    t1, s7, 12
	sw      t1, 0x40(s3)                    # V_QPFN = s7 >> 12
	lw      t1, 0x70(s3)
	ori     t1, t1, 4
	sw      t1, 0x70(s3)                    # status |= 4 (DRIVER_OK)


# ── Read loop: load BIN_SIZE bytes from disk into [gp..gp+BIN_SIZE). ─────
# gp = full_node base (where the bin gets loaded); s7 = queue/stack base
# (post-full_node, page-aligned).  We mustn't write disk data into s7's
# region or we'd clobber descriptors / status / stack.
	mv      s0, gp                          # dest walker = full_node base
	lw      t0, -36(gp)
	mv      s1, t0                          # bytes remaining
	li      s2, 0                           # sector counter
	li      s6, 0                           # avail idx (was s7 in old; conflict)

read_loop_top:
	beqz    s1, read_done

	# chunk = min(remaining, DSK_CHK), rounded up to sector (512 B).
	li      t0, 0x10000                     # DSK_CHK = 64 KiB
	mv      a3, t0
	bge     s1, t0, 1f
	addi    a3, s1, 0x1FF                   # round up to 512
	li      t0, 0xFFFFFE00                  # NEG_SECT
	and     a3, a3, t0
1:
	mv      a0, s2                          # sector
	addi    s6, s6, 1
	mv      a1, s6                          # avail idx
	mv      a2, s0                          # dest

	# disk_read clobbers a3; save chunk on stack.
	addi    sp, sp, -4
	sw      a3, 0(sp)
	CALL    disk_read
	lw      t0, 0(sp)
	addi    sp, sp, 4

	# disk_read returns a0 = status byte (0 = success).
	bnez    a0, halt_no_disk

	srli    t1, t0, 9                       # chunk / 512
	add     s2, s2, t1

	# s0 += min(t0, s1); s1 -= min(t0, s1).
	bge     s1, t0, 1f
	mv      t0, s1
1:	add     s0, s0, t0
	sub     s1, s1, t0
	j       read_loop_top

read_done:

# ── Hash + check ─────────────────────────────────────────────────────────
	# Allocate 32-B scratch on stack for computed hash.
	addi    sp, sp, -32
	mv      a2, sp                          # output buf
	mv      a0, gp                          # data = full_node base
	lw      a1, -36(gp)
	CALL    gimli_hash

	# Compare 32 bytes at sp vs hash_data (= gp − 32).
	mv      t0, sp
	addi    t1, gp, -32
	li      t2, 8                           # 8 words
hash_cmp:
	lw      t3, 0(t0)
	lw      t4, 0(t1)
	bne     t3, t4, hash_mismatch
	addi    t0, t0, 4
	addi    t1, t1, 4
	addi    t2, t2, -1
	bnez    t2, hash_cmp

	# Match!  Free scratch, set handoff regs, jal over hash data to gp.
	addi    sp, sp, 32

	li      t0, SEED_LIST_OFFSET
	add     a0, s7, t0                      # a0 = seed list ptr
	li      a1, 0                           # a1 = boot source (0 = disk)
	mv      a2, s4                          # a2 = bind_port
	addi    t0, a0, DBGFLAG - SEED_LIST_OFFSET   # t0 = s7 + DBGFLAG (= a0 - 40)
	lw      a3, 0(t0)                       # a3 = debug flag
	mv      a4, gp                          # a4 = full_node base address (handoff arg)
	nop                                     # layout pad
	j       end_marker                      # gp = end_marker = full_node entry


hash_mismatch:
	addi    sp, sp, 32
	li      t6, 'H'
	sb      t6, 0(s8)
	li      t6, '\n'
	sb      t6, 0(s8)
	# Fall through to scan_net.


# ──────────────────────────────────────────────────────────────────────────────
# §5 Net boot.
#   scan_net → (or halt if no virtio-net) → handshake → RX/TX queue setup
#   → mark DRIVER_OK → kick RX → enter the REQ_RANGE seed-fetch loop
#   (probe → lock → batch-fetch via chunk bitmap → gimli_hash → handoff).
# Layout in s7's region:
#     s7 + 0x0000  RX queue 0 page (descriptors, avail, used)
#     s7 + 0x2000  16 × 1536 B RX buffers (= 0x6000 B)
#     s7 + 0x8000  TX queue 1 page
# ──────────────────────────────────────────────────────────────────────────────

	CALL    scan_net                        # → s3 = virtio-net MMIO base

	# ── Reset used.idx after disk path. ────────────────────────────────
	# disk_read uses the same V_QPFN = s7 (legacy MMIO 1-page-per-queue
	# layout) as the net RX queue.  Each disk read bumps the device's
	# used.idx at s7+0x1002 and writes a status entry at s7+0x1004.
	# After the 48 disk reads needed to load a 3 MiB full_node.bin,
	# used.idx = 48; net rx_loop would then walk through 48 phantom
	# 1-byte "packets" pointing into zero-filled buffers, never see a
	# real BIN0 reply in time, and halt 'N'.  Just zero used.flags +
	# used.idx (4 B) — stale used.ring[] entries are harmless since the
	# device overwrites them as it processes new packets.  Don't touch
	# the FSM control region at s7+0x9FDA..0x9FFF (TIMETIK lives there)
	# nor the seed list at s7+0xA000.
	li      t0, 0x1000
	add     t0, s7, t0
	sw      zero, 0(t0)                     # used.flags = used.idx = 0

	# ── Virtio-net handshake (legacy MMIO) ─────────────────────────────
	sw      zero, 0x70(s3)                  # status = 0
	li      t1, 1
	sw      t1, 0x70(s3)                    # status = 1 (ACK)
	lw      t1, 0x70(s3)
	ori     t1, t1, 2
	sw      t1, 0x70(s3)                    # status |= 2 (DRIVER)
	li      t1, 0x8020                      # negotiate F_MAC | F_MRG_RXBUF
	sw      t1, 0x20(s3)                    # V_DRVF
	lw      t1, 0x70(s3)
	ori     t1, t1, 8
	sw      t1, 0x70(s3)                    # status |= 8 (FEATURES_OK)
	li      t1, PAGE_SIZE
	sw      t1, 0x28(s3)                    # V_GPS = 0x1000

	# ── RX queue (queue 0, 16 entries × 1536 B buffers) ───────────────
	sw      zero, 0x30(s3)                  # V_QSEL = 0
	li      t1, 16
	sw      t1, 0x38(s3)                    # V_QNUM = 16
	li      t1, PAGE_SIZE
	sw      t1, 0x3C(s3)                    # V_QALGN
	srli    t1, s7, 12
	sw      t1, 0x40(s3)                    # V_QPFN = s7 >> 12 (RX queue at s7)

	# Populate 16 RX descriptors.  desc base = s7; buffer base = s7+0x2000.
	mv      t0, s7                          # descriptor walker
	li      t6, 0x2000
	add     t2, s7, t6                      # buffer walker = s7 + 0x2000
	li      t3, 0                           # i
	li      t5, 1536
rx_desc_top:
	li      t6, 16
	bge     t3, t6, rx_desc_done
	sw      t2, 0(t0)                       # desc[i].addr = buffer
	sw      zero, 4(t0)                     # addr_hi = 0
	sw      t5, 8(t0)                       # desc[i].len = 1536
	li      t6, 2
	sh      t6, 12(t0)                      # flags = WRITE
	sh      zero, 14(t0)                    # next = 0
	# avail.ring[i] = i  (avail ring at s7 + 256+4)
	addi    t6, s7, 260                     # &avail.ring[0]
	slli    t4, t3, 1                       # i*2
	add     t4, t6, t4                      # &avail.ring[i]
	sh      t3, 0(t4)
	# advance
	addi    t0, t0, 16                      # next descriptor
	add     t2, t2, t5                      # next buffer
	addi    t3, t3, 1
	j       rx_desc_top
rx_desc_done:
	li      t1, 16
	addi    t6, s7, 258                     # avail.idx
	sh      t1, 0(t6)

	# ── TX queue (queue 1, SIZE = 1) ──────────────────────────────────
	# V_QNUM = 1 forces every TX to drain before the next is posted.
	# With V_QNUM = 16, repeated tx_req_range calls let avail.idx run
	# 16+ entries ahead of used.idx whenever slirp couldn't deliver
	# responses (e.g., non-loopback IPs while ARP is pending), tripping
	# QEMU's "Guest moved used index" virtio violation and wedging the
	# device.  Hence V_QNUM = 1.
	li      t1, 1
	sw      t1, 0x30(s3)                    # V_QSEL = 1
	sw      t1, 0x38(s3)                    # V_QNUM = 1
	li      t1, PAGE_SIZE
	sw      t1, 0x3C(s3)
	li      t6, 0x8000
	add     t1, s7, t6
	srli    t1, t1, 12
	sw      t1, 0x40(s3)                    # V_QPFN = (s7+0x8000) >> 12

	# ── Driver ready + kick RX ────────────────────────────────────────
	fence   iorw, ow
	lw      t1, 0x70(s3)
	ori     t1, t1, 4
	sw      t1, 0x70(s3)                    # status |= 4 (DRIVER_OK)
	fence   iorw, ow
	sw      zero, 0x50(s3)                  # notify queue 0 (RX)


# ──────────────────────────────────────────────────────────────────────────────
# §6 Net seed-fetch state machine.
#
# Probe → lock → batch with bitmap retry, MTIME watchdog, blacklist+reprobe.
#
# Layout in s7's region used here:
#     +0x8000  TX queue page (desc @ +0..+32, avail @ +256, used @ +0x1000)
#     +0x8200  REQ_RANGE vnet hdr (12 B) + frame (51 B)
#     +0x8400  ARP reply  vnet hdr (12 B) + frame (54 B)
#     +0xA000  seed list (count + 6 × N entries)
#     +0xA080  chunk-received bitmap (NB_BMAP_BYTES)
#     +0x9FF4  fail mask (2 B), +0x9FF2 fail count (2 B)
#
# Pinned regs (across reprobe):
#     s0 = consumed RX used.idx
#     s1 = received chunk count
#     s2 = NCHUNKS
#     s3 = virtio-net MMIO base
#     s4 = bind_port
#     s5 = seed count (parsed)
#     s6 = locked seed idx (0xFF = not locked yet)
#     s7 = data region base
#     s8 = UART base
#     gp = full_node base (write target)
# ──────────────────────────────────────────────────────────────────────────────

	# Select TX queue once for V_QSEL config (not needed for V_QNTFY).
	li      t1, 1
	sw      t1, 0x30(s3)                    # V_QSEL = 1
	fence   iorw, ow

	# ── Init FSM state: fail_mask=0, fail_count=0, RX consumed=0,
	#    random probe-iteration start (WD_TICK is refreshed inside
	#    reprobe_entry after the post-reprobe RX drain + wait).
	li      t0, NF_CNT
	add     t0, s7, t0
	sh      zero, 0(t0)
	sh      zero, 2(t0)
	li      s0, 0                           # consumed used.idx (one-time)
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
	# Random probe-iteration start: r = mtime mod s5.  Picked once on
	# startup so different clients hit seeds in different orders, spreading
	# the load.  Reused on every reprobe — no need to re-randomize.
	#
	# If s5 == 0 (no seeds parsed), skip the mod loop entirely — `bltu
	# t2, 0` is always false, so the unguarded loop never terminates.
	# RND_START stays whatever it was zeroed to, but reprobe_entry's
	# all-failed check (`bge NF_CNT, s5` with NF_CNT=0, s5=0) halts
	# immediately so we never read it.
	beqz    s5, 2f
	andi    t2, t1, 0x1F                    # mtime low 5 bits
1:	bltu    t2, s5, 2f
	sub     t2, t2, s5
	j       1b
2:	li      t0, RND_START
	add     t0, s7, t0
	sb      t2, 0(t0)

reprobe_entry:
	# All-failed check: if every seed is blacklisted, halt 'N'.
	li      t0, NF_CNT
	add     t0, s7, t0
	lhu     t1, 0(t0)
	bge     t1, s5, halt_no_net
	# Reset per-attempt state: locked_idx, received count, bitmap.
	li      s6, 0xFF
	li      s1, 0
	lw      s2, -40(gp)
	# Zero the bitmap (NB_BMAP_BYTES = 1024 → 256 words).
	li      t0, NB_BMAP
	add     t0, s7, t0
	li      t1, NB_BMAP_BYTES / 4
1:	sw      zero, 0(t0)
	addi    t0, t0, 4
	addi    t1, t1, -1
	bnez    t1, 1b
	# BATCH_START = 0 (bitmap in REQ_RANGE lets server skip chunk 0).
	li      t0, BATCH_START
	add     t0, s7, t0
	li      t1, 0
	sh      t1, 0(t0)

	# ── Drain RX queue: consume any in-flight packets from the previous
	# seed by syncing s0 = used.idx.  Stale chunks would otherwise reset
	# NP_CNT each iteration and starve the watchdog.
	li      t0, 0x1000
	add     t0, s7, t0                      # RX used ring base
	lhu     s0, 2(t0)                       # s0 = used.idx

	# Refresh WD_TICK so the watchdog budget for the new attempt starts
	# at this point in time (not when the previous attempt entered).
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
	li      t0, WD_TICK
	add     t0, s7, t0
	sw      t1, 0(t0)

	# ── Probe phase: REQ_RANGE 0..0 to every non-failed seed, IPS_TICKS
	#    apart, walked starting at the per-client random index from RND_START.
	li      t0, RND_START
	add     t0, s7, t0
	lbu     a3, 0(t0)                       # a3 = random start
	li      t6, 0                           # i = 0..s5-1
probe_top:
	bge     t6, s5, probe_done
	# actual_idx = (a3 + t6) mod s5  (single-wrap suffices; both terms < s5)
	add     a0, a3, t6
	bltu    a0, s5, 1f
	sub     a0, a0, s5
1:	# Skip if blacklisted: fail_mask & (1 << a0).
	li      t0, NF_MASK
	add     t0, s7, t0
	lhu     t1, 0(t0)
	li      t2, 1
	sll     t2, t2, a0
	and     t2, t1, t2
	bnez    t2, probe_advance
	# a0 already = seed idx; fill the rest of the call args.
	li      a1, 0
	li      a2, 0
	# Save iter idx + random start across CALL.
	addi    sp, sp, -8
	sw      t6, 0(sp)
	sw      a3, 4(sp)
	CALL    tx_req_range
	lw      t6, 0(sp)
	lw      a3, 4(sp)
	addi    sp, sp, 8
	# Inter-probe spacing.
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
2:	lw      t2, 0(t0)
	sub     t2, t2, t1
	li      t3, IPS_TICKS
	blt     t2, t3, 2b
probe_advance:
	addi    t6, t6, 1
	j       probe_top
probe_done:

# ──────────────────────────────────────────────────────────────────────────────
# RX poll loop — wait for RSP_CHUNK packets, copy into [gp + seq*1400 ..)
# until all NCHUNKS have arrived.  Locks onto first responder via s6.
#
# RX queue layout (NRX=16, QALGN=PAGE_SIZE):
#     s7 + 0x000   descriptor table (16 × 16 = 256 B)
#     s7 + 0x100   avail ring
#     s7 + 0x1000  used ring
# ──────────────────────────────────────────────────────────────────────────────

	# Reset no-progress counter (watchdog is initialized once before
	# reprobe_entry and refreshed only on actual progress).
	li      t0, NP_CNT
	add     t0, s7, t0
	sw      zero, 0(t0)

rx_loop:
	bge     s1, s2, rx_done

	# Brief delay between RX polls so slirp can deliver.  500K iters
	# ≈ 5–10 ms at QEMU's RV32 emulation speed.
	li      t6, 500000
1:	addi    t6, t6, -1
	bnez    t6, 1b
	fence   iorw, iorw
	li      t6, 0x1000
	add     t0, s7, t6                      # t0 = used ring base
	lhu     t1, 2(t0)                       # device's used.idx
	beq     t1, s0, rx_no_progress          # nothing new
	# Progress: reset NP_CNT.
	li      t5, NP_CNT
	add     t5, s7, t5
	sw      zero, 0(t5)

	# used.ring[s0 % 16] at t0 + 4 + (s0 % 16) * 8.
	andi    t2, s0, 15
	slli    t2, t2, 3
	add     t2, t0, t2
	lw      a0, 4(t2)                       # desc_idx
	lw      a1, 8(t2)                       # bytes written

	# Buffer = desc[desc_idx].addr (at s7 + desc_idx * 16, offset 0).
	slli    t3, a0, 4
	add     t3, s7, t3
	lw      a2, 0(t3)                       # buffer ptr

	# Check ethertype at offset 24..25 (LE halfword).
	lhu     t4, 24(a2)
	li      t5, 0x0608
	beq     t4, t5, arp_reply               # 0x0806 → ARP
	li      t5, 0x0008
	bne     t4, t5, rx_refill               # not 0x0800 → drop

	# Check UDP dst port matches bind_port (s4).
	lbu     t4, 48(a2)
	slli    t4, t4, 8
	lbu     t5, 49(a2)
	or      t4, t4, t5
	bne     t4, s4, rx_refill

	# IPv4: validate BIN0 magic at a2 + 54 (LE halfwords).
	lhu     t4, 54(a2)
	li      t5, 0x4942                      # "BI" LE
	bne     t4, t5, rx_refill
	lhu     t4, 56(a2)
	li      t5, 0x304E                      # "N0" LE
	bne     t4, t5, rx_refill
	lbu     t4, 58(a2)
	li      t5, 0x82                        # RSP_CHUNK
	bne     t4, t5, rx_refill

	# ── Source-seed match ──
	# If s6 == 0xFF (unlocked), scan all non-failed seeds for first match
	#   on (src IP, src UDP port).  On match, lock s6 = idx.
	# If s6 != 0xFF (locked), accept only if (src IP, src UDP port) ==
	#   seed[s6]; otherwise drop.
	# Packet src IP at a2+38..41 (BE), src UDP port at a2+46..47 (BE).
	# Seed[idx] base = s7 + SEED_LIST_OFFSET + 1 + idx*6 with layout
	#   [4 IP bytes][LE u16 port].
	li      t6, 0xFF
	beq     s6, t6, sm_unlocked
	# Locked: only accept from seed[s6].
	mv      t3, s6
	j       sm_compare
sm_unlocked:
	li      t3, 0
sm_scan_top:
	bge     t3, s5, rx_refill               # past end, no match → drop
	# Skip blacklisted seeds during scan.
	li      t0, NF_MASK
	add     t0, s7, t0
	lhu     t1, 0(t0)
	li      t2, 1
	sll     t2, t2, t3
	and     t2, t1, t2
	bnez    t2, sm_scan_next
sm_compare:
	# Compute &seed[t3].
	li      t0, SEED_LIST_OFFSET
	add     t0, s7, t0
	addi    t0, t0, 1
	slli    t1, t3, 2
	add     t0, t0, t1
	slli    t1, t3, 1
	add     t0, t0, t1                      # t0 = seed[t3] base
	# Compare 4 IP bytes.
	# Compare 4 IP bytes.
	lbu     t1, 0(t0); lbu t2, 38(a2); bne t1, t2, sm_mismatch
	lbu     t1, 1(t0); lbu t2, 39(a2); bne t1, t2, sm_mismatch
	lbu     t1, 2(t0); lbu t2, 40(a2); bne t1, t2, sm_mismatch
	lbu     t1, 3(t0); lbu t2, 41(a2); bne t1, t2, sm_mismatch
	# Compare port: seed[5]=BE-hi==pkt[46], seed[4]=BE-lo==pkt[47].
	lbu     t1, 5(t0); lbu t2, 46(a2); bne t1, t2, sm_mismatch
	lbu     t1, 4(t0); lbu t2, 47(a2); bne t1, t2, sm_mismatch
	# Match.
	li      t6, 0xFF
	bne     s6, t6, sm_done                 # already locked, no change
	mv      s6, t3                          # lock!
	j       sm_done
sm_mismatch:
	# Locked path: any mismatch → drop.
	li      t6, 0xFF
	bne     s6, t6, rx_refill
	# Unlocked path: try next seed.
sm_scan_next:
	addi    t3, t3, 1
	j       sm_scan_top
sm_done:

	# seq = BE u16 at a2 + 59..60.
	lbu     t4, 59(a2)
	slli    t4, t4, 8
	lbu     t5, 60(a2)
	or      t4, t4, t5                      # t4 = seq

	# Bounds: drop seq >= NCHUNKS (corrupt/replay).
	lw      t6, -40(gp)
	bge     t4, t6, rx_refill

	# Bitmap test/set: byte = bitmap[seq>>3], bit = 1 << (seq & 7).
	# Already-received chunks (duplicates) are dropped without copy and
	# without bumping the received counter.
	srli    t6, t4, 3                       # byte index
	li      t3, NB_BMAP
	add     t3, s7, t3
	add     t3, t3, t6                      # &bitmap[byte]
	lbu     t6, 0(t3)                       # current byte
	andi    t2, t4, 7
	li      t1, 1
	sll     t1, t1, t2                      # 1 << (seq & 7)
	and     t2, t6, t1
	bnez    t2, rx_refill                   # already received → drop
	or      t6, t6, t1
	sb      t6, 0(t3)                       # mark received

	# dst = gp + seq * 1400
	#     1400 = 0x578 = 1024 + 256 + 128 - 8
	slli    t5, t4, 10
	slli    t6, t4, 8;  add t5, t5, t6
	slli    t6, t4, 7;  add t5, t5, t6
	slli    t6, t4, 3;  sub t5, t5, t6
	add     t5, gp, t5                      # dst pointer

	# src = a2 + 61, length = a1 - 61.
	addi    a2, a2, 61
	addi    a1, a1, -61
	bltz    a1, rx_refill                   # runt packet (< 61 B) → drop
	beqz    a1, rx_done_chunk
	# Clamp copy length so last chunk can't overflow past BIN_SIZE.
	lw      t6, -36(gp)
	add     t6, gp, t6                      # end of valid region
	sub     t6, t6, t5                      # remaining = end - dst
	blt     a1, t6, rx_copy
	mv      a1, t6
rx_copy:
	lbu     t6, 0(a2)
	sb      t6, 0(t5)
	addi    a2, a2, 1
	addi    t5, t5, 1
	addi    a1, a1, -1
	bnez    a1, rx_copy
rx_done_chunk:
	addi    s1, s1, 1                       # received++
	# Refresh watchdog: WD_TICK = current mtime.
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
	li      t0, WD_TICK
	add     t0, s7, t0
	sw      t1, 0(t0)
	j       rx_refill

arp_reply:
	# Build ARP reply directly into the shared TX buffer at s7+0x820C
	# (vnet hdr at s7+0x8200, 12 B).  tx_req_range rebuilds the REQ_RANGE
	# from scratch on each call, so overwriting it here is safe.
	# Single NTX_BUF at +0x8200.  42-byte frame.
	li      t6, 0x820C
	add     a3, s7, t6                      # frame base
	# Ethernet: dst = sender of ARP req (a2+18, 6 bytes) via halfwords.
	lhu     t4, 18(a2); sh t4, 0(a3)
	lhu     t4, 20(a2); sh t4, 2(a3)
	lhu     t4, 22(a2); sh t4, 4(a3)
	# src MAC = 52:54:00:12:34:56 via halfwords
	li      t4, 0x5452; sh t4, 6(a3)
	li      t4, 0x1200; sh t4, 8(a3)
	li      t4, 0x5634; sh t4, 10(a3)
	# ethertype 0x0806 (LE: {06,08})
	li      t4, 0x0608; sh t4, 12(a3)
	# ARP body: HW type, proto, lengths (6 B) via halfwords.
	lhu     t4, 26(a2); sh t4, 14(a3)
	lhu     t4, 28(a2); sh t4, 16(a3)
	lhu     t4, 30(a2); sh t4, 18(a3)
	# op = 2 (reply) BE: {00,02} → LE halfword 0x0200
	li      t4, 0x0200; sh t4, 20(a3)
	# sender (us): MAC copied from Ethernet src (offset 6), IP 10.0.2.15
	lhu     t4, 6(a3);  sh t4, 22(a3)
	lhu     t4, 8(a3);  sh t4, 24(a3)
	lhu     t4, 10(a3); sh t4, 26(a3)
	li      t4, 0x000A; sh t4, 28(a3)
	li      t4, 0x0F02; sh t4, 30(a3)
	# target = incoming sender MAC (pkt+34) + IP (pkt+40) via halfwords.
	lhu     t4, 34(a2); sh t4, 32(a3)
	lhu     t4, 36(a2); sh t4, 34(a3)
	lhu     t4, 38(a2); sh t4, 36(a3)
	lhu     t4, 40(a2); sh t4, 38(a3)
	lhu     t4, 42(a2); sh t4, 40(a3)

	mv      a1, a0                          # save desc_idx for rx_refill
	li      a0, 54                          # 12 vnet + 42 ARP frame
	CALL    tx_submit
	mv      a0, a1                          # restore desc_idx
	j       rx_refill

rx_refill:
	# Repost the consumed descriptor.  a0 = desc_idx from used.ring entry.
	addi    t0, s7, 256                     # RX avail base
	lhu     t1, 2(t0)                       # avail.idx
	andi    t2, t1, 15
	slli    t2, t2, 1
	add     t2, t0, t2
	sh      a0, 4(t2)                       # ring[idx%16] = desc_idx
	addi    t1, t1, 1
	sh      t1, 2(t0)                       # avail.idx += 1
	fence   iorw, ow
	sw      zero, 0x50(s3)                  # notify RX queue 0

	addi    s0, s0, 1                       # consumed++
	j       rx_loop

# ──────────────────────────────────────────────────────────────────────────────
# rx_no_progress — bumps a stall counter; once the threshold is hit, scans the
# chunk bitmap for the first un-received seq and re-sends REQ_RANGE
# [first_missing .. NCHUNKS-1] to the same seed.  The bitmap drops the
# duplicates the server re-bursts, so we converge on the missing tail.
# ──────────────────────────────────────────────────────────────────────────────
rx_no_progress:
	# Increment NP_CNT; bail back to rx_loop until threshold.
	li      t0, NP_CNT
	add     t0, s7, t0
	lw      t1, 0(t0)
	addi    t1, t1, 1
	sw      t1, 0(t0)
	li      t6, 10                          # poll threshold
	blt     t1, t6, rx_loop
	sw      zero, 0(t0)                     # reset

	# ── Watchdog: check elapsed since last progress against TIMETIK ──
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)                       # current mtime
	li      t0, WD_TICK
	add     t0, s7, t0
	lw      t2, 0(t0)
	sub     t2, t1, t2                      # elapsed
	li      t0, TIMETIK
	add     t0, s7, t0
	lw      t3, 0(t0)
	blt     t2, t3, wd_ok
	# Timeout!  Either blacklist + reprobe or halt.
	li      t6, 0xFF
	beq     s6, t6, halt_no_net             # never locked → halt
	# Locked seed went silent.  Blacklist and reprobe.
	li      t6, 'T'
	sb      t6, 0(s8)
	li      t6, '\n'
	sb      t6, 0(s8)
	j       blacklist_reprobe
wd_ok:

	# Without a lock yet, do NOT reprobe automatically.  The watchdog
	# will fire after TIMETIK and either halt N (if still unlocked) or
	# blacklist + reprobe (if locked): probe-poll just waits until lock
	# or timeout.
	li      t6, 0xFF
	beq     s6, t6, rx_loop

	# Rate-limit batch retries: skip if NS_RTRY (last retry-send mtime)
	# was less than NRTRY_TK ago.  Without this, a partial-data attacker
	# (or undersized seed) makes us spam the wire as we keep asking for
	# chunks that won't come.  WD_TICK still ticks toward TIMETIK based
	# on accepted-chunk freshness, so we'll blacklist after the watchdog
	# fires regardless.
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
	li      t0, NS_RTRY
	add     t0, s7, t0
	lw      t2, 0(t0)
	sub     t3, t1, t2
	li      t4, NRTRY_TK
	blt     t3, t4, rx_loop                 # too soon since last retry

	# Batch logic:
	#   1. Re-send REQ_RANGE for [BATCH_START..BATCH_START+63] with bitmap
	#      every NRTRY_TK ms (gated by NS_RTRY) until all 64 land.
	#   2. When the current batch is fully received, advance BATCH_START by 64.
	#   3. Watchdog (TIMETIK on no-new-chunk) handles seed-died blacklist.
	li      t0, BATCH_START
	add     t0, s7, t0
	lhu     t2, 0(t0)                       # t2 = batch start
	# Done?
	lw      t6, -40(gp)
	bge     t2, t6, rx_loop                 # batch start past end → nothing left

	# Compute batch end = min(start + NB_SIZE-1, NCHUNKS - 1).
batch_clamp:
	addi    t1, t2, NB_SIZE - 1             # candidate end
	lw      t6, -40(gp)
	addi    t6, t6, -1
	blt     t1, t6, 1f
	mv      t1, t6                          # clamp
1:
	# Check whether the current batch is fully filled in the bitmap.
	# Walk seq from t2 to t1 inclusive; if any bit is 0, batch incomplete.
	mv      t3, t2                          # walker
batch_check:
	bgt     t3, t1, batch_advance           # walked past end → all set
	srli    t4, t3, 3                       # byte index
	li      t5, NB_BMAP
	add     t5, s7, t5
	add     t5, t5, t4
	lbu     t4, 0(t5)
	andi    t6, t3, 7
	li      t5, 1
	sll     t5, t5, t6
	and     t6, t4, t5
	beqz    t6, batch_send                  # bit clear → re-request same range
	addi    t3, t3, 1
	j       batch_check

batch_advance:
	# All chunks in [t2..t1] received.  Advance BATCH_START past this batch.
	addi    t2, t1, 1
	li      t0, BATCH_START
	add     t0, s7, t0
	sh      t2, 0(t0)
	# Are we done?
	lw      t6, -40(gp)
	bge     t2, t6, rx_loop
	j       batch_clamp
batch_send:
	# Send REQ_RANGE [t2..t1] to locked seed s6.
	mv      a0, s6
	mv      a1, t2
	mv      a2, t1
	CALL    tx_req_range

	# Stamp NS_RTRY = current mtime to gate the next batch retry.
	li      t0, MTIME_ADDR
	lw      t1, 0(t0)
	li      t0, NS_RTRY
	add     t0, s7, t0
	sw      t1, 0(t0)
	j       rx_loop

rx_done:
	# Now run the existing hash check by jumping back to it.  The hash
	# check expects: gp..gp+BIN_SIZE = candidate full_node bytes;
	# scratch buf gets gimli_hash output, compared to hash_data.
	addi    sp, sp, -32
	mv      a2, sp
	mv      a0, gp
	lw      a1, -36(gp)
	CALL    gimli_hash

	mv      t0, sp
	addi    t1, gp, -32
	li      t2, 8
net_hash_cmp:
	lw      t3, 0(t0)
	lw      t4, 0(t1)
	bne     t3, t4, net_hash_mismatch
	addi    t0, t0, 4
	addi    t1, t1, 4
	addi    t2, t2, -1
	bnez    t2, net_hash_cmp

	# Match!
	addi    sp, sp, 32
	li      t0, SEED_LIST_OFFSET
	add     a0, s7, t0
	li      a1, 1                           # boot source = net
	mv      a2, s4
	addi    t0, a0, DBGFLAG - SEED_LIST_OFFSET   # t0 = s7 + DBGFLAG (= a0 - 40)
	lw      a3, 0(t0)                       # a3 = debug flag
	mv      a4, gp                          # a4 = full_node base address (handoff arg)
	nop                                     # layout pad
	j       end_marker

net_hash_mismatch:
	addi    sp, sp, 32
	li      t6, 'H'
	sb      t6, 0(s8)
	li      t6, '\n'
	sb      t6, 0(s8)
	# Blacklist the locked seed and reprobe.  s6 holds the locked idx.
blacklist_reprobe:
	li      t0, NF_CNT
	add     t0, s7, t0
	lhu     t1, 2(t0)
	li      t2, 1
	sll     t2, t2, s6
	or      t1, t1, t2
	sh      t1, 2(t0)
	lhu     t1, 0(t0)
	addi    t1, t1, 1
	sh      t1, 0(t0)
	j       reprobe_entry


halt_no_disk:
panic:
	li      t6, 'N'
	j       halt_tail

halt_no_net:
	li      t6, 'N'
	beqz    s1, halt_tail
	li      t6, 'H'
halt_tail:
	sb      t6, 0(s8)
	li      t6, '\n'
	sb      t6, 0(s8)
	lui     t0, %hi(SHUTDOWN_ADDR)
	li      t1, SHUTDOWN_FAIL
	sw      t1, 0(t0)
1:	j       1b


# ──────────────────────────────────────────────────────────────────────────────
# scan_disk — walk virtio MMIO from V_SCAN_S down to V_SCAN_E looking for
#             a device with magic = 'virt' and device_id = 2 (block).
# Out:    s3 = MMIO base of the found device.
# Trashes: t0..t2.  Returns via dispatch.
# Falls through to caller's halt_no_disk path if no device found (back-jumps
# via `j halt_no_disk` instead of dispatching, so we don't pollute the BST).
# ──────────────────────────────────────────────────────────────────────────────

scan_disk:
	li      t1, 2                           # device_id we want (virtio-blk)
	j       scan_common

# ──────────────────────────────────────────────────────────────────────────────
# scan_net — same as scan_disk but looking for device_id=1 (virtio-net).
# ──────────────────────────────────────────────────────────────────────────────

scan_net:
	li      t1, 1                           # virtio-net

scan_common:
	lui     s3, 0x10008                     # start at top virtio-mmio slot
	lui     t2, 0x10001                     # lower bound (s3 >= t2)
	lui     t3, 0xFFFFF                     # -PAGE_SIZE (sign-extended u20<<12)
1:	bge     s3, t2, 2f
	j       halt_no_disk
2:	lw      t0, 8(s3)                       # device_id
	beq     t0, t1, dispatch                # found → return
	add     s3, s3, t3                      # next slot down
	j       1b


# ──────────────────────────────────────────────────────────────────────────────
# disk_read — issue a virtio-blk READ for one chunk.
#   In:   a0 = sector,  a1 = avail idx,  a2 = dest,  a3 = byte count.
#         s3 = MMIO base, s7 = queue base (page-aligned).
#   Out:  a0 = status byte (0 = success, nonzero = failure).
#   Trashes: t0..t6.  Returns via dispatch.
# Layout (offsets from s7):
#   0x000..0x180  descriptor table (3 descs × 16 B = 48 B used)
#   0x100..       available ring   (offset 256 from descriptor table)
#   0x1200        status byte   (1 B)
#   0x1202        request header (16 B)
# ──────────────────────────────────────────────────────────────────────────────

disk_read:
	mv      t1, s7                          # t1 = queue base
	li      t3, 0x1200
	add     t3, s7, t3                      # t3 = status byte addr
	addi    t2, t3, 2                       # t2 = req hdr addr

	# Request header (16 B at t2): type=READ(0), reserved=0, sector(lo,hi).
	sw      zero, 0(t2)
	sw      zero, 4(t2)
	sw      a0, 8(t2)
	sw      zero, 12(t2)

	# Descriptor[0]: req hdr.
	sw      t2, 0(t1)
	sw      zero, 4(t1)
	li      t4, 16
	sw      t4, 8(t1)
	li      t4, 1
	sh      t4, 12(t1)                      # flags = NEXT
	sh      t4, 14(t1)                      # next  = 1
	sw      t4, 0x28(t1)                    # desc[2].len = 1

	# Descriptor[1]: data buffer.
	sw      a2, 16(t1)
	sw      zero, 20(t1)
	sw      a3, 24(t1)
	li      t4, 2
	sh      t4, 30(t1)                      # next  = 2
	sh      t4, 0x2C(t1)                    # desc[2].flags = WRITE
	li      t4, 3
	sh      t4, 28(t1)                      # desc[1].flags = NEXT|WRITE

	# Descriptor[2]: status byte.
	sw      t3, 32(t1)
	sw      zero, 36(t1)
	sh      zero, 0x2E(t1)                  # next = 0

	# Available ring at t1+256.
	addi    t4, t1, 256
	sh      zero, 0(t4)                     # avail.flags = 0
	li      t5, 0xFF
	sb      t5, 0(t3)                       # status byte = 0xFF (init)
	sh      a1, 2(t4)                       # avail.ring[0]
	sh      zero, 4(t4)                     # avail.idx (placeholder)

	fence   iorw, ow
	# Notify device.
	sw      zero, 0x50(s3)

	# Poll status byte (no watchdog yet — virtio-blk under qemu always responds).
dr_poll:
	lbu     t4, 0(t3)
	li      t5, 0xFF
	beq     t4, t5, dr_poll

	fence   ir, iorw
	mv      a0, t4
	j       dispatch


# ──────────────────────────────────────────────────────────────────────────────
# gimli_permute — 384-bit Gimli permutation, 24 rounds.
#   In/out:  state at a0 (12 × 32-bit LE words).
#   Trashes: t0..t6, s0, s1.
#   Returns via `j dispatch`.
#
# Per round (r descending 24..1):
#   for col in 0..3:
#       x = rotl(state[col],     24)
#       y = rotl(state[col + 4],  9)
#       z =       state[col + 8]
#       state[col + 8] = x ^ (z << 1) ^ ((y & z) << 2)
#       state[col + 4] = y ^ x        ^ ((x | z) << 1)
#       state[col]     = z ^ y        ^ ((x & y) << 3)
#   if r % 4 == 0: small-swap + state[0] ^= 0x9e377900 | r
#   if r % 4 == 2: big-swap
# ──────────────────────────────────────────────────────────────────────────────

gimli_permute:
	# Save s0/s1 — callees must per RISC-V ABI; gimli_hash relies on s1.
	addi    sp, sp, -8
	sw      s0, 0(sp)
	sw      s1, 4(sp)
	mv      s0, a0                          # state base
	li      s1, 24                          # round counter

gp_round:
	mv      a0, s0
	li      t6, 4

gp_col:
	lw      t3, 0(a0)
	lw      t4, 16(a0)
	lw      t5, 32(a0)

	# x = rotl(t3, 24)
	slli    t0, t3, 24
	srli    t1, t3, 8
	or      t0, t0, t1

	# y = rotl(t4, 9)
	slli    t1, t4, 9
	srli    t2, t4, 23
	or      t1, t1, t2

	# state[col]     = z ^ y ^ ((x & y) << 3)
	and     t3, t0, t1
	slli    t3, t3, 3
	xor     t3, t3, t5
	xor     t3, t3, t1
	sw      t3, 0(a0)

	# state[col + 4] = y ^ x ^ ((x | z) << 1)
	or      t4, t0, t5
	slli    t4, t4, 1
	xor     t4, t4, t1
	xor     t4, t4, t0
	sw      t4, 16(a0)

	# state[col + 8] = x ^ (z << 1) ^ ((y & z) << 2)
	and     t2, t1, t5
	slli    t2, t2, 2
	slli    t5, t5, 1
	xor     t5, t5, t0
	xor     t5, t5, t2
	sw      t5, 32(a0)

	addi    a0, a0, 4
	addi    t6, t6, -1
	bnez    t6, gp_col

	andi    t0, s1, 3
	bnez    t0, gp_check_2
	# Small swap.
	lw      t0, 0(s0)
	lw      t1, 4(s0)
	sw      t1, 0(s0)
	sw      t0, 4(s0)
	lw      t0, 8(s0)
	lw      t1, 12(s0)
	sw      t1, 8(s0)
	sw      t0, 12(s0)
	# Round constant.
	li      t0, 0x9E377900
	or      t0, t0, s1
	lw      t1, 0(s0)
	xor     t1, t1, t0
	sw      t1, 0(s0)
	j       gp_next

gp_check_2:
	li      t1, 2
	bne     t0, t1, gp_next
	# Big swap.
	lw      t0, 0(s0)
	lw      t1, 8(s0)
	sw      t1, 0(s0)
	sw      t0, 8(s0)
	lw      t0, 4(s0)
	lw      t1, 12(s0)
	sw      t1, 4(s0)
	sw      t0, 12(s0)

gp_next:
	addi    s1, s1, -1
	bnez    s1, gp_round
	lw      s0, 0(sp)
	lw      s1, 4(sp)
	addi    sp, sp, 8
	j       dispatch


# ──────────────────────────────────────────────────────────────────────────────
# gimli_hash — sponge construction over gimli_permute.
#   a0 = data ptr,  a1 = length,  a2 = 32-byte output buf.
#   Uses s0..s3 internally; saves and restores all of them so callers'
#   pinned values survive (s3 in particular is the virtio-net MMIO base,
#   without which post-hash net I/O would silently target stack memory).
#   Returns via `j dispatch`.
# ──────────────────────────────────────────────────────────────────────────────

gimli_hash:
	addi    sp, sp, -64
	sw      s0,  0(sp)                      # save callee-saved s-regs we
	sw      s1,  4(sp)                      # use as scratch (s3 in
	sw      s2,  8(sp)                      # particular is the virtio-net
	sw      s3, 12(sp)                      # MMIO base — must be preserved)
	# state base = sp + 16 (12 words = 48 bytes, fits in sp+16..sp+64)

	li      t0, 12
	addi    t1, sp, 16
gh_zero:
	sw      zero, 0(t1)
	addi    t1, t1, 4
	addi    t0, t0, -1
	bnez    t0, gh_zero

	addi    s0, sp, 16                      # state base
	mv      s1, a0                          # data ptr
	mv      s2, a1                          # remaining
	mv      s3, a2                          # output buf

gh_absorb:
	li      t0, 16
	blt     s2, t0, gh_pad

	mv      t2, s0
	mv      t3, s1
	li      t4, 4
gh_xor_abs:
	lw      t0, 0(t3)
	lw      t1, 0(t2)
	xor     t1, t1, t0
	sw      t1, 0(t2)
	addi    t2, t2, 4
	addi    t3, t3, 4
	addi    t4, t4, -1
	bnez    t4, gh_xor_abs

	mv      a0, s0
	CALL    gimli_permute

	addi    s1, s1, 16
	addi    s2, s2, -16
	j       gh_absorb

gh_pad:
	beqz    s2, gh_pad_skipcopy
	mv      t2, s0
	mv      t3, s1
	mv      t4, s2
gh_pad_copy:
	lbu     t0, 0(t3)
	lbu     t1, 0(t2)
	xor     t1, t1, t0
	sb      t1, 0(t2)
	addi    t2, t2, 1
	addi    t3, t3, 1
	addi    t4, t4, -1
	bnez    t4, gh_pad_copy
gh_pad_skipcopy:

	add     t0, s0, s2
	lbu     t1, 0(t0)
	xori    t1, t1, 0x01
	sb      t1, 0(t0)

	lbu     t1, 15(s0)
	xori    t1, t1, 0x80
	sb      t1, 15(s0)

	lbu     t1, 47(s0)
	xori    t1, t1, 0x01
	sb      t1, 47(s0)

	mv      a0, s0
	CALL    gimli_permute

	# Squeeze first 16 B.
	lw      t0, 0(s0)
	sw      t0, 0(s3)
	lw      t0, 4(s0)
	sw      t0, 4(s3)
	lw      t0, 8(s0)
	sw      t0, 8(s3)
	lw      t0, 12(s0)
	sw      t0, 12(s3)

	mv      a0, s0
	CALL    gimli_permute

	# Squeeze second 16 B.
	lw      t0, 0(s0)
	sw      t0, 16(s3)
	lw      t0, 4(s0)
	sw      t0, 20(s3)
	lw      t0, 8(s0)
	sw      t0, 24(s3)
	lw      t0, 12(s0)
	sw      t0, 28(s3)

	lw      s0,  0(sp)
	lw      s1,  4(sp)
	lw      s2,  8(sp)
	lw      s3, 12(sp)
	addi    sp, sp, 64
	j       dispatch


# ──────────────────────────────────────────────────────────────────────────────
# tx_req_range — build a BIN0 REQ_RANGE [a1..a2] frame in the TX buffer at
# s7+0x8200, addressed to seed[a0], and post + notify on TX queue 1.
#
# In:  a0 = seed index (0..MAX_SEEDS-1)
#      a1 = start chunk seq
#      a2 = end chunk seq
# Trashes: t0..t6, a0..a4.
# Uses pinned: s3 (net MMIO), s4 (bind_port), s7 (data region), s8 (UART)
# ──────────────────────────────────────────────────────────────────────────────
tx_req_range:
	# a3 = &seed[a0] = s7 + SEED_LIST_OFFSET + 1 + a0*6
	li      t0, SEED_LIST_OFFSET
	add     a3, s7, t0
	addi    a3, a3, 1
	slli    t0, a0, 2                       # a0*4
	add     a3, a3, t0
	slli    t0, a0, 1                       # a0*2
	add     a3, a3, t0                      # a3 = seed[a0] base

	# a4 = frame base = s7 + 0x820C
	li      t0, 0x820C
	add     a4, s7, t0

	# ── Ethernet (14 B): dst gateway MAC, src guest MAC, ethertype 0x0800 ──
	li      t1, 0x52; sb t1, 0(a4)
	li      t1, 0x55; sb t1, 1(a4)
	li      t1, 0x0A; sb t1, 2(a4)
	sb      zero, 3(a4)
	li      t1, 0x02; sb t1, 4(a4); sb t1, 5(a4)
	li      t1, 0x52; sb t1, 6(a4)
	li      t1, 0x54; sb t1, 7(a4)
	sb      zero, 8(a4)
	li      t1, 0x12; sb t1, 9(a4)
	li      t1, 0x34; sb t1, 10(a4)
	li      t1, 0x56; sb t1, 11(a4)
	li      t1, 0x08; sb t1, 12(a4)
	sb      zero, 13(a4)

	# ── IPv4 (20 B) at frame + 14 ──
	addi    t0, a4, 14
	li      t1, 0x45; sb t1, 0(t0)
	sb      zero, 1(t0)
	sb      zero, 2(t0)
	li      t1, 45; sb t1, 3(t0)             # total len = 20+8+9+8(bitmap)
	sh      zero, 4(t0)
	sh      zero, 6(t0)
	li      t1, 64; sb t1, 8(t0)
	li      t1, 17; sb t1, 9(t0)             # UDP
	sh      zero, 10(t0)                     # checksum placeholder
	li      t1, 10; sb t1, 12(t0)
	sb      zero, 13(t0)
	li      t1, 2;  sb t1, 14(t0)
	li      t1, 15; sb t1, 15(t0)
	# dst IP from seed: bytes a3+0..a3+3
	lbu     t1, 0(a3); sb t1, 16(t0)
	lbu     t1, 1(a3); sb t1, 17(t0)
	lbu     t1, 2(a3); sb t1, 18(t0)
	lbu     t1, 3(a3); sb t1, 19(t0)

	# IPv4 header checksum.
	mv      t1, t0
	li      t2, 10
	li      t3, 0
1:	lbu     t4, 0(t1)
	slli    t4, t4, 8
	lbu     t5, 1(t1)
	or      t4, t4, t5
	add     t3, t3, t4
	addi    t1, t1, 2
	addi    t2, t2, -1
	bnez    t2, 1b
	srli    t4, t3, 16
	li      t5, 0xFFFF
	and     t3, t3, t5
	add     t3, t3, t4
	srli    t4, t3, 16
	add     t3, t3, t4
	and     t3, t3, t5
	xor     t3, t3, t5
	srli    t1, t3, 8
	sb      t1, 10(t0)
	sb      t3, 11(t0)

	# ── UDP (8 B) at frame + 34 ──
	addi    t0, a4, 34
	srli    t1, s4, 8
	sb      t1, 0(t0)
	sb      s4, 1(t0)
	# dst port = seed[a0].port (LE u16 at a3+4..5)
	lbu     t1, 4(a3); sb t1, 3(t0)
	lbu     t1, 5(a3); sb t1, 2(t0)
	sb      zero, 4(t0)
	li      t1, 25; sb t1, 5(t0)             # 8+9+8(bitmap)
	sh      zero, 6(t0)                     # UDP csum (optional in IPv4)

	# ── BIN0 REQ_RANGE (9 B) + bitmap (8 B) at frame + 42 ──
	addi    t0, a4, 42
	li      t1, 'B'; sb t1, 0(t0)
	li      t1, 'I'; sb t1, 1(t0)
	li      t1, 'N'; sb t1, 2(t0)
	li      t1, '0'; sb t1, 3(t0)
	li      t1, 0x02; sb t1, 4(t0)
	srli    t1, a1, 8
	sb      t1, 5(t0)                       # start hi
	sb      a1, 6(t0)                       # start lo
	srli    t1, a2, 8
	sb      t1, 7(t0)                       # end hi
	sb      a2, 8(t0)                       # end lo

	# ── Bitmap (8 B): copy NB_BMAP bytes for this batch so the server
	#    can skip already-received chunks. ──
	srli    t1, a1, 3                       # byte offset = start / 8
	li      t2, NB_BMAP
	add     t2, s7, t2
	add     t1, t2, t1                      # t1 = &NB_BMAP[start/8]
	addi    t0, t0, 9                       # t0 = frame + 51
	li      t3, 8                           # counter
1:	lbu     t2, 0(t1)
	sb      t2, 0(t0)
	addi    t1, t1, 1
	addi    t0, t0, 1
	addi    t3, t3, -1
	bnez    t3, 1b

	li      a0, 71                          # 12 vnet + 59 frame (9 BIN0 + 8 bitmap)
	CALL    tx_submit
	j       dispatch


# ──────────────────────────────────────────────────────────────────────────────
# tx_submit — post the shared TX buffer (s7+0x8200) as desc[0], bump
# avail.idx, fence+notify, and spin-wait for the device to drain.
#
# In:  a0 = total frame length (vnet hdr + Ethernet frame)
# Uses pinned: s3 (net MMIO), s7 (data region)
# Trashes: t0..t5.  Returns via dispatch.
# ──────────────────────────────────────────────────────────────────────────────
tx_submit:
	li      t0, 0x8200
	add     t0, s7, t0
	sw      zero, 0(t0)                     # zero vnet hdr (12 B)
	sw      zero, 4(t0)
	sw      zero, 8(t0)
	li      t1, 0x8000
	add     t1, s7, t1                      # TX queue base
	sw      t0, 0(t1)                       # desc[0].addr
	sw      zero, 4(t1)
	sw      a0, 8(t1)                       # desc[0].len
	sh      zero, 12(t1)
	sh      zero, 14(t1)
	addi    t2, t1, 16                      # avail ring (queue_size=1)
	sh      zero, 4(t2)                     # ring[0] = desc 0
	lhu     t3, 2(t2)
	addi    t3, t3, 1
	sh      t3, 2(t2)                       # avail.idx += 1
	fence   iorw, ow
	li      t3, 1
	sw      t3, 0x50(s3)                    # V_QNTFY = 1 (TX queue)
	li      t5, 1000000
	li      t3, 0x9000
	add     t3, s7, t3                      # TX used ring base
	li      t4, 0x8010
	add     t4, s7, t4                      # TX avail ring base
	lhu     t0, 2(t4)                       # avail.idx target
1:	lhu     t1, 2(t3)                       # used.idx
	beq     t1, t0, 2f
	addi    t5, t5, -1
	bnez    t5, 1b
2:	j       dispatch


# ──────────────────────────────────────────────────────────────────────────────
# dispatch — single shared resume point.  Looks up s11 (return ID) in the
# BST and jumps to the corresponding .L_csret_<N> label (which sits right
# after each CALL site, where execution resumes).
# ──────────────────────────────────────────────────────────────────────────────

dispatch:
	BST 1, %_CSN


# ──────────────────────────────────────────────────────────────────────────────
# ── Embedded config (patched by scripts/build.sh). ────────────────────────
# gp-40 = nchunks, gp-36 = bin_size, gp-32 = hash_data.
nchunks_data:
	.word 0
bin_size_data:
	.word 0
hash_data:
	.include "src/tabernacle_dat.S"

end_marker:
