/* KMAC SHAKE128 with explicit RUN — edge-case coverage
 * Tests the critical RUN→keccak-f→absorb→squeeze path that ML-KEM uses.
 *
 * Test cases:
 *   1. SHAKE128("what do "): process→sqz32B→RUN→sqz32B→done
 *   2. SHAKE128("what do "): process→sqz32B→RUN→sqz32B→RUN→sqz32B→RUN→sqz32B→done
 *   3. SHAKE256("what do "): process→sqz32B→RUN→sqz32B→done
 */
.section .text.start
.globl main
main:
    jal     x1, test_shake128_1run
    jal     x1, test_shake128_3run
    jal     x1, test_shake256_1run
    jal     x1, test_shake128_rate_cross

    bn.xor  w0, w0, w0
    bn.xor  w1, w1, w1
    bn.xor  w2, w2, w2
    bn.xor  w3, w3, w3
    bn.xor  w4, w4, w4
    bn.xor  w5, w5, w5
    bn.xor  w6, w6, w6
    bn.xor  w7, w7, w7
    bn.xor  w8, w8, w8
    bn.xor  w9, w9, w9
    xor     x2, x2, x2
    xor     x3, x3, x3
    xor     x4, x4, x4
    xor     x5, x5, x5
    xor     x6, x6, x6
    xor     x7, x7, x7
    xor     x8, x8, x8
    xor     x9, x9, x9
    xor     x10, x10, x10
    xor     x11, x11, x11
    ecall

/* ========== KMAC Driver ========== */

kmac_start:  /* x10 = cfg value */
    csrrw   x0, 0x7DB, x10
    addi    x5, x0, 0x1D
    csrrw   x0, 0x7DD, x5
    ret

kmac_feed:   /* x10=msg_ptr, x11=byte_len */
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

kmac_process:
    addi    x5, x0, 0x2E
    csrrw   x0, 0x7DD, x5
kmac_proc_wait:
    csrrs   x5, 0xFC2, x0
    andi    x5, x5, 0x4
    beq     x5, x0, kmac_proc_wait
    ret

_ensure_digest:
    csrrs   x5, 0x7d9, x0
    andi    x5, x5, 0x8
    bne     x5, x0, _ed_ret
    addi    x3, x1, 0               /* save x1 (return addr) */
    addi    x4, x6, 0               /* save x6 (DIGEST_VALID mask) */
    jal     x1, kmac_run
    addi    x6, x4, 0               /* restore mask */
    addi    x1, x3, 0               /* restore return addr */
_ed_ret:
    jalr    x0, x1, 0

kmac_squeeze_32B:  /* x10=out_ptr */
    bn.xor  w31, w31, w31
    addi    x6, x0, 8
    /* Word 0 */
    jal     x1, _ensure_digest
    bn.wsrr w8, 8
    bn.wsrr w9, 9
    bn.xor  w8, w8, w9
    /* Word 1 */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 192
    bn.or   w8, w8, w10
    /* Word 2 */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 128
    bn.or   w8, w8, w10
    /* Word 3 */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 64
    bn.or   w8, w8, w10
    addi    x5, x0, 8
    bn.sid  x5, 0(x10)
    ret

kmac_run:  /* wait absorb then squeeze */
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

kmac_done:
    addi    x5, x0, 0x16
    csrrw   x0, 0x7DD, x5
kmac_done_wait:
    csrrs   x5, 0xFC2, x0
    andi    x5, x5, 0x1
    beq     x5, x0, kmac_done_wait
    ret

/* ========== Test Cases ========== */

/* 1. SHAKE128("what do "): squeeze 32B x2 (auto-RUN at block boundary) */
test_shake128_1run:
    addi    x31, x1, 0
    addi    x10, x0, 0x21          /* SHAKE128 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 256
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_1r_b1
    jal     x1, kmac_squeeze_32B   /* batch 1 */
    la      x10, shake128_1r_b2
    jal     x1, kmac_squeeze_32B   /* batch 2 */
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* 2. SHAKE128("what do "): 4× squeeze 32B (auto-RUN at block boundary) */
test_shake128_3run:
    addi    x31, x1, 0
    addi    x10, x0, 0x21          /* SHAKE128 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 256
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_3r_b1
    jal     x1, kmac_squeeze_32B
    la      x10, shake128_3r_b2
    jal     x1, kmac_squeeze_32B
    la      x10, shake128_3r_b3
    jal     x1, kmac_squeeze_32B
    la      x10, shake128_3r_b4
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* 3. SHAKE256("what do "): squeeze 32B x2 (auto-RUN at block boundary) */
test_shake256_1run:
    addi    x31, x1, 0
    addi    x10, x0, 0x25          /* SHAKE256 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 256
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake256_1r_b1
    jal     x1, kmac_squeeze_32B
    la      x10, shake256_1r_b2
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* 4. SHAKE128 rate-cross: 6 squeezes → 24 lanes > 21 rate (auto-RUN at boundary) */
test_shake128_rate_cross:
    addi    x31, x1, 0
    addi    x10, x0, 0x21          /* SHAKE128 */
    jal     x1, kmac_start
    la      x10, msg_256b
    addi    x11, x0, 256
    jal     x1, kmac_feed
    jal     x1, kmac_process
    /* 5 squeezes: 20 lanes, within rate=21 */
    la      x10, rcx_b1
    jal     x1, kmac_squeeze_32B
    la      x10, rcx_b2
    jal     x1, kmac_squeeze_32B
    la      x10, rcx_b3
    jal     x1, kmac_squeeze_32B
    la      x10, rcx_b4
    jal     x1, kmac_squeeze_32B
    la      x10, rcx_b5
    jal     x1, kmac_squeeze_32B
    /* 6th squeeze crosses rate boundary → auto-RUN inside _ensure_digest */
    la      x10, rcx_b6
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== Data ========== */
.data
.balign 32
my_message:
    .rept 32
    .word 0x74616877    /* "what" little-endian */
    .word 0x206f6420    /* " do " little-endian */
    .endr

/* SHAKE128 1-run outputs */
.balign 32
shake128_1r_b1:  .zero 32
.balign 32
shake128_1r_b2:  .zero 32

/* SHAKE128 3-run outputs */
.balign 32
shake128_3r_b1:  .zero 32
.balign 32
shake128_3r_b2:  .zero 32
.balign 32
shake128_3r_b3:  .zero 32
.balign 32
shake128_3r_b4:  .zero 32

/* SHAKE256 1-run outputs */
.balign 32
shake256_1r_b1:  .zero 32
.balign 32
shake256_1r_b2:  .zero 32

.balign 32
msg_256b:
    .rept 32
    .word 0x74616877    /* "what" little-endian */
    .word 0x206f6420    /* " do " little-endian */
    .endr

.balign 32
rcx_b1:  .zero 32
.balign 32
rcx_b2:  .zero 32
.balign 32
rcx_b3:  .zero 32
.balign 32
rcx_b4:  .zero 32
.balign 32
rcx_b5:  .zero 32
.balign 32
rcx_b6:  .zero 32
