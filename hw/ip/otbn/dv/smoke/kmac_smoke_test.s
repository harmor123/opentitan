/* KMAC/SHA3 hardware smoke test — 19 test cases
 *
 * Uses csr.yml / wsr.yml interface:
 *   0x7D9 = kmac_if_status (read: bit0=msg_rdy, bit3=digest_valid)
 *   0x7DB = kmac_cfg (write: bit0=EN, bits[3:1]=strength, bits[5:4]=mode)
 *   0x7DD = kmac_cmd (write: START=0x1D, PROCESS=0x2E, RUN=0x31, DONE=0x16)
 *   0xFC2 = kmac_status (read: bit0=idle, bit1=absorb, bit2=squeeze)
 *   WSR 8 = kmac_data_s0, WSR 9 = kmac_data_s1
 *
 * MODE: 0=SHA3, 2=SHAKE
 * STRENGTH: 0=L128, 1=L224, 2=L256, 3=L384, 4=L512
 *
 * FIPS 202 pad10*1: both SHA3 and SHAKE MUST pad empty messages
 *   SHA3 empty:  suffix 01 → pad  = 0x06 || 0x00… || 0x80 (full rate block)
 *   SHAKE empty: suffix 1111 → pad = 0x1F || 0x00… || 0x80 (full rate block)
 */

.section .text.start
.globl main
main:

    /* ———— SHA3 tests ———— */
    jal     x1, test_sha3_256_empty
    jal     x1, test_sha3_512_empty
    jal     x1, test_sha3_256_msg
    jal     x1, test_sha3_512_msg
    jal     x1, test_sha3_256_32b
    jal     x1, test_sha3_256_33b
    jal     x1, test_sha3_256_35b
    jal     x1, test_sha3_256_64b
    jal     x1, test_sha3_256_2048b
    jal     x1, test_sha3_256_127b
    jal     x1, test_sha3_256_136b       /* edge: exact rate block, pad into new block */
    jal     x1, test_sha3_256_136b_plus1 /* edge: rate+1 byte, partial last word */

    /* ———— SHAKE tests ———— */
    jal     x1, test_shake128_empty      
    jal     x1, test_shake256_empty       
    jal     x1, test_shake128_msg
    jal     x1, test_shake256_msg
    jal     x1, test_shake128_64b_run
    jal     x1, test_shake128_4096b
    jal     x1, test_shake256_4096b
/*
     */


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

/* kmac_process: send PROCESS=0x2E, wait squeeze */
kmac_process:
    addi    x5, x0, 0x2E
    csrrw   x0, 0x7DD, x5
kmac_proc_wait:
    csrrs   x5, 0xFC2, x0
    andi    x5, x5, 0x4
    beq     x5, x0, kmac_proc_wait
    ret

/* _ensure_digest: auto-RUN if DIGEST_VALID not set */
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

/* kmac_squeeze_32B(x10=out_ptr) -- reads 4 x 64-bit words, assembles 256-bit digest */
kmac_squeeze_32B:
    bn.xor  w31, w31, w31        /* w31 = 0 for bn.rshi shifts */
    addi    x6, x0, 8             /* DIGEST_VALID mask */

    /* Word 0: bits[63:0] */
    jal     x1, _ensure_digest
    bn.wsrr w8, 8
    bn.wsrr w9, 9
    bn.xor  w8, w8, w9

    /* Word 1: bits[127:64] */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 192  /* w10 <<= 64 */
    bn.or   w8, w8, w10

    /* Word 2: bits[191:128] */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 128  /* w10 <<= 128 */
    bn.or   w8, w8, w10

    /* Word 3: bits[255:192] */
    jal     x1, _ensure_digest
    bn.wsrr w10, 8
    bn.wsrr w9, 9
    bn.xor  w10, w10, w9
    bn.rshi w10, w10, w31 >> 64   /* w10 <<= 192 */
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

/* ========== 11 Test Cases ========== */

/* cfg: MODE=2(SHA3) STRENGTH=2(L256) EN=1 => 0x25 */
test_sha3_256_empty:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 */
    jal     x1, kmac_start
    jal     x1, kmac_process
    la      x10, sha3_256_empty_out
    jal     x1, kmac_squeeze_32B     /* read 1st 64-bit digest word */
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

/* cfg: MODE=0(SHA3) STRENGTH=4(L512) EN=1 => bit[5:4]=00,bit[3:1]=100,bit[0]=1 = 0x09 */
test_sha3_512_empty:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x09            /* SHA3-512: MODE=0 SHA3, STRENGTH=4 L512, EN=1 */
    jal     x1, kmac_start
    jal     x1, kmac_process
    la      x10, sha3_512_empty_out
    jal     x1, kmac_squeeze_32B
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

/* ———— SHAKE empty-message tests (FIPS 202: pad10*1 required for all messages) ———— */

/* cfg: MODE=SHAKE(2) STRENGTH=L128(0) EN=1 => 0x21
 * SHAKE-128 empty: 1111 || pad10*1 → 0x1F || 0x00×165 || 0x80 (168 bytes = full rate block)
 * No data is fed — kmac_process triggers pad10*1 directly from StMsgFeed → StPad */
test_shake128_empty:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x21            /* SHAKE128: mode=2(SHAKE), strength=0(L128) */
    jal     x1, kmac_start
    /* ★ NO kmac_feed call — empty message */
    jal     x1, kmac_process         /* triggers pad10*1 of empty msg → full rate block */
    la      x10, shake128_empty_out
    jal     x1, kmac_squeeze_32B     /* squeeze first 256 bits from padded-empty state */
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* cfg: MODE=SHAKE(2) STRENGTH=L256(2) EN=1 => 0x25
 * SHAKE-256 empty: 1111 || pad10*1 → 0x1F || 0x00×133 || 0x80 (136 bytes = full rate block) */
test_shake256_empty:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x25            /* SHAKE256: mode=2(SHAKE), strength=2(L256) */
    jal     x1, kmac_start
    /* ★ NO kmac_feed call — empty message */
    jal     x1, kmac_process
    la      x10, shake256_empty_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

test_sha3_256_msg:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_msg_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

test_sha3_512_msg:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x09            /* SHA3-512: MODE=0 SHA3, STRENGTH=4 L512, EN=1 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_512_msg_out
    jal     x1, kmac_squeeze_32B     /* first 256 bits */
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B     /* next 256 bits */
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

/* cfg: MODE=SHAKE(2) STRENGTH=L128(0) EN=1 => 0x21 */
test_shake128_msg:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x21            /* SHAKE128: mode=2, strength=0 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

/* cfg: MODE=SHAKE(2) STRENGTH=L256(2) EN=1 => 0x25 */
test_shake256_msg:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x25            /* SHAKE256: mode=2(SHAKE), strength=2(L256) */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake256_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

test_sha3_256_32b:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 */
    jal     x1, kmac_start
    la      x10, msg_32b
    addi    x11, x0, 32
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_32b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

test_sha3_256_33b:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x05            /* SHA3-256 */
    jal     x1, kmac_start
    la      x10, msg_33b
    addi    x11, x0, 33
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_33b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

test_sha3_256_35b:
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 (ISS needs EN=1) */
    jal     x1, kmac_start
    la      x10, msg_35b
    addi    x11, x0, 35
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_35b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_64b:
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 (ISS needs EN=1) */
    jal     x1, kmac_start
    la      x10, msg_64b
    addi    x11, x0, 64
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_64b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_127b:
    addi    x10, x0, 0x05            /* SHA3-256 */
    jal     x1, kmac_start
    la      x10, msg_127b
    addi    x11, x0, 127             /* 3 WDR + 31B tail, pos=16, pad=2 */
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_127b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_shake128_64b_run:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x21            /* SHAKE128: mode=2, strength=0 */
    jal     x1, kmac_start
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, shake128_64b_out_1
    jal     x1, kmac_squeeze_32B
    la      x10, shake128_64b_out_2
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

/* cfg: MODE=0(SHA3) STRENGTH=2(L256) EN=1 => 0x05
   2048-bit (256-byte) message: "what do " repeated 32 times */
test_sha3_256_2048b:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0 SHA3, STRENGTH=2 L256, EN=1 */
    jal     x1, kmac_start
    la      x10, msg_2048b
    addi    x11, x0, 256             /* 256 bytes = 2048 bits */
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_2048b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */


/* cfg: MODE=SHAKE(2) STRENGTH=L256(2) EN=1 => 0x25
   4096-byte message: "what do " repeated 512 times */
test_shake256_4096b:
    addi    x31, x1, 0               /* save ra */
    addi    x10, x0, 0x25            /* SHAKE256: mode=2(SHAKE), strength=2(L256) */
    jal     x1, kmac_start
    la      x10, msg_4096b
    addi    x11, x0, 1024
    slli    x11, x11, 2              /* x11 = 4096 */
    jal     x1, kmac_feed            /*  4096 bytes */
    jal     x1, kmac_process
    la      x10, shake256_4096b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0               /* return via saved ra */

  test_shake128_4096b:
      addi    x31, x1, 0
      addi    x10, x0, 0x21
      jal     x1, kmac_start
      la      x10, msg_4096b
      addi    x11, x0, 1024
      slli    x11, x11, 2
      jal     x1, kmac_feed
      jal     x1, kmac_process
      la      x10, shake128_4096b_out
      jal     x1, kmac_squeeze_32B
      jal     x1, kmac_done
      jalr    x0, x31, 0

/* Edge: SHA3-256, 136-byte message (exact SHA3-256 rate = 1088 bits).
   Last WDR (bytes 128-135) fills all 8 bytes of the last 64-bit word.
   Requires last_valid_bytes=8, pad starts in NEW block.
   With the [2:0] bug, last_valid_bytes=0 causes spurious 0x06 at word 0 of pad block. */
test_sha3_256_136b:
    addi    x31, x1, 0
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0, STRENGTH=2, EN=1 */
    jal     x1, kmac_start
    la      x10, msg_136b
    addi    x11, x0, 136             /* exact SHA3-256 rate */
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_136b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* Edge: SHA3-256, 137-byte message (rate+1 byte).
   Last byte of last 64-bit word is valid, rest are not → last_valid_bytes=1.
   Verifies partial last word padding works correctly. */
test_sha3_256_136b_plus1:
    addi    x31, x1, 0
    addi    x10, x0, 0x05            /* SHA3-256: MODE=0, STRENGTH=2, EN=1 */
    jal     x1, kmac_start
    la      x10, msg_136b_plus1
    addi    x11, x0, 137
    jal     x1, kmac_feed
    jal     x1, kmac_process
    la      x10, sha3_256_136b_plus1_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    jalr    x0, x31, 0

/* ========== Data ========== */
.data

.balign 32
my_message:
    .word 0x74616877    /* "what" little-endian */
    .word 0x206f6420    /* " do " little-endian */
    
/* edge test specific input data */
.balign 32
msg_32b:
    .zero 32

.balign 32
msg_33b:
    .zero 32
    .word 0x00000001

.balign 32
msg_35b:
    .zero 32
    .word 0x00030201

.balign 32
msg_64b:
    .zero 64

/* basic test output buffer */
.balign 32
sha3_256_empty_out:   .zero 32

.balign 32
sha3_512_empty_out:   .zero 64

.balign 32
sha3_256_msg_out:     .zero 32

.balign 32
sha3_512_msg_out:     .zero 64

.balign 32
shake128_out:         .zero 32

.balign 32
shake256_out:         .zero 32

/* SHAKE empty-message output buffers (FIPS 202 expected values computed from reference impl) */
.balign 32
shake128_empty_out:   .zero 32   /* SHAKE128("") first 256 bits */

.balign 32
shake256_empty_out:   .zero 32   /* SHAKE256("") first 256 bits */

/* edge test specific output buffer */
.balign 32
sha3_256_32b_out:     .zero 32

.balign 32
sha3_256_33b_out:     .zero 32

.balign 32
sha3_256_35b_out:     .zero 32

.balign 32
sha3_256_64b_out:     .zero 32

.balign 32
shake128_64b_out_1:   .zero 32

.balign 32
shake128_64b_out_2:   .zero 32

/* 2048-bit (256-byte) message = "what do " repeated 32 times */
.balign 32
msg_2048b:
    .rept 32
    .word 0x74616877    /* "what" little-endian */
    .word 0x206f6420    /* " do " little-endian */
    .endr

.balign 32
sha3_256_2048b_out:   .zero 32

/* 4096-byte message = "what do " repeated 512 times */
.balign 32
msg_4096b:
    .rept 512
    .word 0x74616877
    .word 0x206f6420
    .endr

.balign 32
shake256_4096b_out:   .zero 32

.balign 32
shake128_4096b_out:   .zero 32
.balign 32
msg_127b:
    .zero 96
    .zero 31

.balign 32
sha3_256_127b_out:    .zero 32

/* 136-byte message = exact SHA3-256 rate (1088 bits).
   "SHA3-256 rate edge: exactly 136 bytes — pad into new block."
   Repeating 8-byte pattern "rate136!" x17 */
.balign 32
msg_136b:
    .rept 17
    .word 0x65746172  /* "rate" little-endian */
    .word 0x21363331  /* "136!" little-endian */
    .endr

.balign 32
sha3_256_136b_out:    .zero 32

/* 137-byte message = SHA3-256 rate + 1 byte.
   136 bytes same as above, plus 1 extra byte 0xFF */
.balign 32
msg_136b_plus1:
    .rept 17
    .word 0x65746172
    .word 0x21363331
    .endr
    .word 0x000000FF

.balign 32
sha3_256_136b_plus1_out: .zero 32
