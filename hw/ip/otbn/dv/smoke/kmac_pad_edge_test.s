/* KMAC/SHA3 pad edge test — pad=1 / pad=2 boundary cases
 *
 * pad=1: single pad word must contain BOTH 0x06/0x1F (low byte) AND 0x80 (high byte).
 * pad=2: boundary where pad skip optimisation does NOT trigger (pad_words > 2 is skip).
 *
 * BUG: when pad_words_needed == 1, RTL only wrote 0x06, missing 0x80.
 *
 * Uses csr.yml / wsr.yml interface:
 *   0x7D9 = kmac_if_status (read: bit0=msg_rdy, bit3=digest_valid)
 *   0x7DB = kmac_cfg (write: bit0=EN, bits[3:1]=strength, bits[5:4]=mode)
 *   0x7DD = kmac_cmd (write: START=0x1D, PROCESS=0x2E, RUN=0x31, DONE=0x16)
 *   0xFC2 = kmac_status (read: bit0=idle, bit1=absorb, bit2=squeeze)
 *   WSR 8 = kmac_data_s0, WSR 9 = kmac_data_s1
 */

.section .text.start
.globl main
main:

    /* ── pad=1 边界: 单 pad word 必须含 0x06(0x1F)+0x80 ── */
    jal     x1, test_sha3_256_pad1     /* 128B=16w, rate=17, pad=1 */
    jal     x1, test_sha3_512_pad1     /*  64B= 8w, rate= 9, pad=1 ← BUG */
    jal     x1, test_shake128_pad1     /* 160B=20w, rate=21, pad=1 */
    jal     x1, test_shake256_pad1     /* 128B=16w, rate=17, pad=1 */

    /* ── pad=2 边界: pad_words>2 才触发 skip ── */
    jal     x1, test_sha3_256_pad2     /* 120B=15w, rate=17, pad=2 */
    jal     x1, test_sha3_512_pad2     /*  56B= 7w, rate= 9, pad=2 */

    /* ── 多 block 尾部 pad=1 ── */
    jal     x1, test_sha3_256_multi_p1 /* 264B=136+128, 末 block pad=1 */

    /* ── 满 rate block (pos=0, 会触发 auto keccak) ── */
    /* TODO: re-enable after PROCESS counter 1-cycle fix
    jal     x1, test_shake128_full      168B=21w=rate */

    ecall

/* ========== Driver (matches csr.yml) ========== */

/* kmac_start(x10 = cfg value): write cfg, then START cmd */
kmac_start:
    csrrw   x0, 0x7DB, x10
    addi    x5, x0, 0x1D
    csrrw   x0, 0x7DD, x5
    ret

/* kmac_feed(x10=msg_ptr, x11=byte_len) */
kmac_feed:
    bn.xor  w1, w1, w1
    bn.xor  w31, w31, w31
    srli    x5, x11, 5
    beq     x5, x0, kmac_feed_tail
    slli    x5, x5, 5
    add     x5, x10, x5
kmac_feed_full_loop:
    beq     x10, x5, kmac_feed_tail
kmac_feed_wait_rdy:
    csrrs   x6, 0x7D9, x0
    andi    x6, x6, 0x1
    beq     x6, x0, kmac_feed_wait_rdy
    bn.lid  x0, 0(x10)
    addi    x10, x10, 32
    bn.wsrw 8, w0
    bn.wsrw 9, w1
    addi    x6, x0, -1
    csrrw   x0, 0x7DE, x6
    addi    x6, x0, 1
    csrrw   x0, 0x7DC, x6
    jal     x0, kmac_feed_full_loop
kmac_feed_tail:
    andi    x5, x11, 31
    beq     x5, x0, kmac_feed_done
kmac_feed_wait_tail:
    csrrs   x6, 0x7D9, x0
    andi    x6, x6, 0x1
    beq     x6, x0, kmac_feed_wait_tail
    bn.lid  x0, 0(x10)
    bn.addi w1, w1, 1
    addi    x7, x5, 0
kmac_feed_mask_loop:
    beq     x7, x0, kmac_feed_mask_done
    addi    x7, x7, -1
    bn.rshi w1, w1, w31 >> 248
    jal     x0, kmac_feed_mask_loop
kmac_feed_mask_done:
    bn.subi w1, w1, 1
    bn.and  w0, w0, w1
    bn.wsrw 8, w0
    bn.wsrw 9, w31
    addi    x6, x0, 1
    sll     x6, x6, x5
    addi    x6, x6, -1
    csrrw   x0, 0x7DE, x6
    addi    x6, x0, 1
    csrrw   x0, 0x7DC, x6
kmac_feed_done:
    ret

/* kmac_process: send PROCESS=0x2E, wait digest_valid */
kmac_process:
    addi    x5, x0, 0x2E
    csrrw   x0, 0x7DD, x5
    addi    x6, x0, 8               /* kmac_if_status[3]: DIGEST_VALID */
kmac_proc_wait:
    csrrs   x5, 0x7D9, x0
    and     x5, x5, x6
    beq     x5, x0, kmac_proc_wait
    ret

/* _ensure_digest: auto-RUN if DIGEST_VALID not set */
_ensure_digest:
    csrrs   x5, 0x7d9, x0
    andi    x5, x5, 0x8
    bne     x5, x0, _ed_ret
    addi    x3, x1, 0
    addi    x4, x6, 0
    jal     x1, kmac_run
    addi    x6, x4, 0
    addi    x1, x3, 0
_ed_ret:
    jalr    x0, x1, 0

/* kmac_squeeze_32B(x10=out_ptr) */
kmac_squeeze_32B:
    bn.xor  w31, w31, w31
    addi    x6, x0, 8
    jal     x1, _ensure_digest
    bn.wsrr w8, 8
    bn.wsrr w9, 9
    bn.xor  w8, w8, w9
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 192
    bn.or   w8, w8, w10
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 128
    bn.or   w8, w8, w10
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 64
    bn.or   w8, w8, w10
    addi    x5, x0, 8
    bn.sid  x5, 0(x10)
    ret

/* kmac_run: send RUN=0x31, wait absorb then squeeze */
kmac_run:
    addi    x5, x0, 0x31
    csrrw   x0, 0x7DD, x5
    addi    x6, x0, 2
kmac_run_wait_absorb:
    csrrs   x5, 0xFC2, x0
    and     x5, x5, x6
    beq     x5, x0, kmac_run_wait_absorb
    addi    x6, x0, 4
kmac_run_wait_squeeze:
    csrrs   x5, 0xFC2, x0
    and     x5, x5, x6
    beq     x5, x0, kmac_run_wait_squeeze
    ret

/* kmac_done: send DONE=0x16, wait idle */
kmac_done:
    addi    x5, x0, 0x16
    csrrw   x0, 0x7DD, x5
kmac_done_wait:
    csrrs   x5, 0xFC2, x0
    andi    x5, x5, 0x1
    beq     x5, x0, kmac_done_wait
    ret

/* ========== pad=1 边界测试 ========== */

/* SHA3-256(128B): 16 words, rate=17, pad=1 — single word with 0x06+0x80 */
test_sha3_256_pad1:
    addi    x31, x1, 0
    addi    x10, x0, 0x05            /* SHA3-256: EN=1, MODE=0, STRENGTH=2 */
    jal     x1, kmac_start
    la      x10, msg_128b
    addi    x11, x0, 128
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_pad1_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* SHA3-512(64B): 8 words, rate=9, pad=1 ← BUG: 0x80 missing in single pad word */
test_sha3_512_pad1:
    addi    x31, x1, 0
    addi    x10, x0, 0x09            /* SHA3-512: EN=1, MODE=0, STRENGTH=4 */
    jal     x1, kmac_start
    la      x10, msg_64b_rep
    addi    x11, x0, 64
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_512_pad1_out
    jal     x1, kmac_squeeze_32B
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* SHAKE128(160B): 20 words, rate=21, pad=1 — single word with 0x1F+0x80 */
test_shake128_pad1:
    addi    x31, x1, 0
    addi    x10, x0, 0x21            /* SHAKE128: EN=1, MODE=2, STRENGTH=0 */
    jal     x1, kmac_start
    la      x10, msg_160b
    addi    x11, x0, 160
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_pad1_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* SHAKE256(128B): 16 words, rate=17, pad=1 */
test_shake256_pad1:
    addi    x31, x1, 0
    addi    x10, x0, 0x25            /* SHAKE256: EN=1, MODE=2, STRENGTH=2 */
    jal     x1, kmac_start
    la      x10, msg_128b_shake
    addi    x11, x0, 128
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake256_pad1_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== pad=2 边界测试 ========== */

/* SHA3-256(120B): 15 words, rate=17, pad=2 */
test_sha3_256_pad2:
    addi    x31, x1, 0
    addi    x10, x0, 0x05
    jal     x1, kmac_start
    la      x10, msg_120b
    addi    x11, x0, 120
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_pad2_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* SHA3-512(56B): 7 words, rate=9, pad=2 */
test_sha3_512_pad2:
    addi    x31, x1, 0
    addi    x10, x0, 0x09
    jal     x1, kmac_start
    la      x10, msg_56b
    addi    x11, x0, 56
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_512_pad2_out
    jal     x1, kmac_squeeze_32B
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== 多 block 尾部 pad=1 ========== */

/* SHA3-256(264B): 136+128, 首 block 17w(满), 末 block 16w pad=1 */
test_sha3_256_multi_p1:
    addi    x31, x1, 0
    addi    x10, x0, 0x05
    jal     x1, kmac_start
    la      x10, msg_264b
    addi    x11, x0, 264
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_multi_p1_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== 满 rate block (pos=0 → pad=rate_words, >2 skip→3) ========== */

/* SHAKE128(168B): 21 words = rate, pos=0, pad=21(>2 skip→3) */
test_shake128_full:
    addi    x31, x1, 0
    addi    x10, x0, 0x21
    jal     x1, kmac_start
    la      x10, msg_168b
    addi    x11, x0, 168
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_full_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== Data ========== */
.data

/* ── pad=1 测试输入 ── */

.balign 32
msg_128b:              .zero 128

.balign 32
msg_64b_rep:
    .rept 8
    .word 0x74616877
    .word 0x206f6420
    .endr

.balign 32
msg_160b:              .zero 160

.balign 32
msg_128b_shake:        .zero 128

/* ── pad=2 测试输入 ── */

.balign 32
msg_120b:              .zero 120

.balign 32
msg_56b:
    .rept 7
    .word 0x74616877
    .word 0x206f6420
    .endr

/* ── 多 block 输入 ── */

.balign 32
msg_264b:              .zero 264

/* ── 满 rate 输入 ── */

.balign 32
msg_168b:              .zero 168

/* ── 输出缓冲区 ── */

.balign 32
sha3_256_pad1_out:     .zero 32

.balign 32
sha3_512_pad1_out:     .zero 64

.balign 32
shake128_pad1_out:     .zero 32

.balign 32
shake256_pad1_out:     .zero 32

.balign 32
sha3_256_pad2_out:     .zero 32

.balign 32
sha3_512_pad2_out:     .zero 64

.balign 32
sha3_256_multi_p1_out: .zero 32

.balign 32
shake128_full_out:     .zero 32
