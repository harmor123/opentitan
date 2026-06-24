/* MODP256 ISS functional test — bn.modp256 instruction
 *
 * Tests 256-bit modular multiplication for NIST P-256.
 * ISS-only (no Verilator co-sim), results checked against .dexp.
 */

.section .text.start
.globl main
main:
    la      x2, stack_end
    addi    x2, x2, -64

    /* === Test 1: 0 * 0 mod p = 0 === */
    li      x3, 2
    la      x10, op_zero
    bn.lid  x3++, 0(x10)         /* w2 = 0, x3=3 */
    bn.lid  x3, 0(x10)           /* w3 = 0 */
    bn.modp256 w4, w2, w3        /* w4 = 0 */
    li      x9, 4
    la      x10, result1
    bn.sid  x9, 0(x10)

    /* === Test 2: 1 * 1 mod p = 1 === */
    li      x3, 5
    la      x10, op_one
    bn.lid  x3++, 0(x10)         /* w5 = 1, x3=6 */
    bn.lid  x3, 0(x10)           /* w6 = 1 */
    bn.modp256 w7, w5, w6        /* w7 = 1 */
    li      x9, 7
    la      x10, result2
    bn.sid  x9, 0(x10)

    /* === Test 3: 3 * 5 mod p = 15 === */
    li      x3, 8
    la      x10, op_3
    bn.lid  x3++, 0(x10)         /* w8 = 3, x3=9 */
    la      x10, op_5
    bn.lid  x3, 0(x10)           /* w9 = 5 */
    bn.modp256 w10, w8, w9       /* w10 = 15 */
    li      x9, 10
    la      x10, result3
    bn.sid  x9, 0(x10)

    /* === Test 4: (p-1) * 1 mod p = p-1 === */
    li      x3, 11
    la      x10, op_pminus1
    bn.lid  x3++, 0(x10)         /* w11 = p-1, x3=12 */
    la      x10, op_one
    bn.lid  x3, 0(x10)           /* w12 = 1 */
    bn.modp256 w13, w11, w12     /* w13 = p-1 */
    li      x9, 13
    la      x10, result4
    bn.sid  x9, 0(x10)

    /* === Test 5: (p-1) * 2 mod p = p-2 === */
    li      x3, 14
    la      x10, op_pminus1
    bn.lid  x3++, 0(x10)         /* w14 = p-1, x3=15 */
    la      x10, op_2
    bn.lid  x3, 0(x10)           /* w15 = 2 */
    bn.modp256 w16, w14, w15     /* w16 = p-2 */
    li      x9, 16
    la      x10, result5
    bn.sid  x9, 0(x10)

    /* === Test 6: (p-1)^2 mod p = 1 === */
    li      x3, 17
    la      x10, op_pminus1
    bn.lid  x3++, 0(x10)         /* w17 = p-1, x3=18 */
    bn.lid  x3, 0(x10)           /* w18 = p-1 */
    bn.modp256 w19, w17, w18     /* w19 = 1 */
    li      x9, 19
    la      x10, result6
    bn.sid  x9, 0(x10)

    /* === Test 7: Gx * Gy mod p (real P-256 curve values) === */
    li      x3, 20
    la      x10, op_p256_gx
    bn.lid  x3++, 0(x10)         /* w20 = Gx, x3=21 */
    la      x10, op_p256_gy
    bn.lid  x3, 0(x10)           /* w21 = Gy */
    bn.modp256 w22, w20, w21     /* w22 = Gx*Gy mod p */
    li      x9, 22
    la      x10, result7
    bn.sid  x9, 0(x10)

    /* === Test 8: large random a * b mod p (stress test) === */
    li      x3, 23
    la      x10, value_a
    bn.lid  x3++, 0(x10)         /* w23 = a, x3=24 */
    la      x10, value_b
    bn.lid  x3, 0(x10)           /* w24 = b */
    bn.modp256 w25, w23, w24     /* w25 = a*b mod p */
    li      x9, 25
    la      x10, result8
    bn.sid  x9, 0(x10)

    /* === Test 9: p * 1 = 0 === */
    li      x3, 26
    la      x10, op_p256p
    bn.lid  x3++, 0(x10)         /* w26 = p, x3=27 */
    la      x10, op_one
    bn.lid  x3, 0(x10)           /* w27 = 1 */
    bn.modp256 w28, w26, w27     /* w28 = 0 */
    li      x9, 28
    la      x10, result9
    bn.sid  x9, 0(x10)

    /* === Test 10: (p+1) * 1 = 1 === */
    li      x3, 29
    la      x10, op_p256p_plus1
    bn.lid  x3++, 0(x10)         /* w29 = p+1, x3=30 */
    la      x10, op_one
    bn.lid  x3, 0(x10)           /* w30 = 1 */
    bn.modp256 w31, w29, w30     /* w31 = 1 */

    /* === Test 11: max^2 mod p === */
    /* w31 already = 1, reuse next available WDRs beyond w30 */
    /* Can't use w31 as dest since we just used it, spill first */
    li      x9, 31
    la      x10, result10
    bn.sid  x9, 0(x10)

    li      x3, 2
    la      x10, op_max
    bn.lid  x3++, 0(x10)         /* w2 = max */
    bn.lid  x3, 0(x10)           /* w3 = max */
    bn.modp256 w4, w2, w3        /* w4 = max^2 mod p */
    li      x9, 4
    la      x10, result11
    bn.sid  x9, 0(x10)

    /* === Test 12: max * 1 = max mod p === */
    bn.modp256 w5, w2, w31       /* w5 = max * 1 mod p, w2=op_max, w31=1 */
    li      x9, 5
    la      x10, result12
    bn.sid  x9, 0(x10)

    /* === Test 13: max * (p-1) mod p === */
    la      x10, op_pminus1
    bn.lid  x3++, 0(x10)         /* w3 = p-1 (x3 was 3) */
    bn.lid  x3++, 0(x10)         /* w4 = p-1 */
    addi    x3, x3, 1
    bn.modp256 w6, w2, w4        /* w6 = max * (p-1) mod p, w2=op_max */
    li      x9, 6
    la      x10, result13
    bn.sid  x9, 0(x10)

    ecall


.data

/* ---- Stack ---- */
.balign 32
.globl stack
stack:
    .zero 512
stack_end:

/* ---- Operands ---- */

.balign 32
.globl op_zero
op_zero:
    .zero 32

.balign 32
.globl op_one
op_one:
    .word 0x00000001
    .zero 28

.balign 32
.globl op_3
op_3:
    .word 0x00000003
    .zero 28

.balign 32
.globl op_5
op_5:
    .word 0x00000005
    .zero 28

.balign 32
.globl op_2
op_2:
    .word 0x00000002
    .zero 28

.balign 32
.globl op_pminus1
op_pminus1:
    .word 0xfffffffe
    .word 0xffffffff
    .word 0xffffffff
    .word 0x00000000
    .word 0x00000000
    .word 0x00000000
    .word 0x00000001
    .word 0xffffffff

.balign 32
.globl op_p256_gx
op_p256_gx:
    .word 0xd898c296
    .word 0xf4a13945
    .word 0x2deb33a0
    .word 0x77037d81
    .word 0x63a440f2
    .word 0xf8bce6e5
    .word 0xe12c4247
    .word 0x6b17d1f2

.balign 32
.globl op_p256_gy
op_p256_gy:
    .word 0x37bf51f5
    .word 0xcbb64068
    .word 0x6b315ece
    .word 0x2bce3357
    .word 0x7c0f9e16
    .word 0x8ee7eb4a
    .word 0xfe1a7f9b
    .word 0x4fe342e2

.balign 32
.globl value_a
value_a:
    .word 0xa3175abc
    .word 0xace17a9d
    .word 0x4bb3295c
    .word 0x08a32b36
    .word 0xbcd32666
    .word 0x030a5a44
    .word 0xfce03337
    .word 0xa8da539f

.balign 32
.globl value_b
value_b:
    .word 0x3c873171
    .word 0x96a2db31
    .word 0x0df8714c
    .word 0x04a0e433
    .word 0x60cb522e
    .word 0xb2a1c47c
    .word 0xc94cf13a
    .word 0x72c7c6be

/* ---- Results ---- */

.balign 32
.globl result1
result1:
    .zero 32

.balign 32
.globl result2
result2:
    .zero 32

.balign 32
.globl result3
result3:
    .zero 32

.balign 32
.globl result4
result4:
    .zero 32

.balign 32
.globl result5
result5:
    .zero 32

.balign 32
.globl result6
result6:
    .zero 32

.balign 32
.globl result7
result7:
    .zero 32

.balign 32
.globl result8
result8:
    .zero 32

/* ---- New operands ---- */

.balign 32
.globl op_p256p
op_p256p:
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0x00000000
    .word 0x00000000
    .word 0x00000000
    .word 0x00000001
    .word 0xffffffff

.balign 32
.globl op_p256p_plus1
op_p256p_plus1:
    .word 0x00000000
    .word 0x00000000
    .word 0x00000000
    .word 0x00000001
    .word 0x00000000
    .word 0x00000000
    .word 0x00000001
    .word 0xffffffff

.balign 32
.globl op_max
op_max:
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff
    .word 0xffffffff

/* ---- New results ---- */

.balign 32
.globl result9
result9:
    .zero 32

.balign 32
.globl result10
result10:
    .zero 32

.balign 32
.globl result11
result11:
    .zero 32

.balign 32
.globl result12
result12:
    .zero 32

.balign 32
.globl result13
result13:
    .zero 32
