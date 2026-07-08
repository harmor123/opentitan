/* Smoke test for bn.modp256 — same 10 cases as modp256_test.s
 *
 * Tests: basic multiply, square, zero, identity, self-reference,
 *        back-to-back, (p-1)^2=1, bn.lid->bn.modp256, Gx*Gy.
 */
.section .text.start
.globl main
main:
    bn.xor    w31, w31, w31

    /* Test 1: 3*5=15 */
    bn.addi   w0, w31, 3
    bn.addi   w1, w31, 5
    bn.modp256 w2, w0, w1
    la        x16, t1_3x5
    li        x17, 2
    bn.sid    x17, 0(x16)

    /* Test 2: 2*2=4 */
    bn.addi   w3, w31, 2
    bn.modp256 w4, w3, w3
    la        x16, t2_sq
    li        x17, 4
    bn.sid    x17, 0(x16)

    /* Test 3: 0*3=0 */
    bn.modp256 w5, w31, w0
    la        x16, t3_zero
    li        x17, 5
    bn.sid    x17, 0(x16)

    /* Test 4: 3*1=3 */
    bn.addi   w6, w31, 1
    bn.modp256 w7, w0, w6
    la        x16, t4_id
    li        x17, 7
    bn.sid    x17, 0(x16)

    /* Test 5: wrd==wrs1 self-ref (w0 = w0 * w1 = 3*5=15) */
    bn.modp256 w0, w0, w1
    la        x16, t5_selfref
    li        x17, 0
    bn.sid    x17, 0(x16)

    /* Test 6: wrd==wrs2 self-ref */
    bn.addi   w8, w31, 7
    bn.modp256 w8, w6, w8      /* w8 = 1*7 = 7 */
    la        x16, t6_wrd2
    li        x17, 8
    bn.sid    x17, 0(x16)

    /* Test 7: back-to-back bn.modp256 */
    bn.addi   w9, w31, 4
    bn.addi   w10, w31, 9
    bn.modp256 w11, w9, w10    /* 4*9=36 */
    la        x16, t7_bb1
    li        x17, 11
    bn.sid    x17, 0(x16)
    bn.modp256 w12, w11, w9    /* 36*4=144 */
    la        x16, t7_bb2
    li        x17, 12
    bn.sid    x17, 0(x16)

    /* Test 8: (p-1)^2 = 1 mod p */
    la        x16, p_minus_1
    li        x17, 13
    bn.lid    x17, 0(x16)
    bn.modp256 w14, w13, w13
    la        x16, t8_pm1sq
    li        x17, 14
    bn.sid    x17, 0(x16)

    /* Test 9: bn.lid -> bn.modp256 */
    la        x16, operand_a
    li        x17, 15
    bn.lid    x17, 0(x16)
    bn.modp256 w16, w15, w6
    la        x16, t9_lid
    li        x17, 16
    bn.sid    x17, 0(x16)

    /* Test 10: Gx * Gy mod P256 */
    la        x16, operand_b
    li        x17, 17
    bn.lid    x17, 0(x16)
    bn.modp256 w18, w15, w17
    la        x16, t10_GxGy
    li        x17, 18
    bn.sid    x17, 0(x16)

    ecall

.data
.balign 32

p_minus_1:
  .word 0xfffffffe
  .word 0xffffffff
  .word 0xffffffff
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000001
  .word 0xffffffff

operand_a:
  .word 0xd898c296
  .word 0xf4a13945
  .word 0x2deb33a0
  .word 0x77037d81
  .word 0x63a440f2
  .word 0xf8bce6e5
  .word 0xe12c4247
  .word 0x6b17d1f2

operand_b:
  .word 0x37bf51f5
  .word 0xcbb64068
  .word 0x6b315ece
  .word 0x2bce3357
  .word 0x7c0f9e16
  .word 0x8ee7eb4a
  .word 0xfe1a7f9b
  .word 0x4fe342e2

/* Result labels */
.balign 32
t1_3x5:       .zero 32
t2_sq:        .zero 32
t3_zero:      .zero 32
t4_id:        .zero 32
t5_selfref:   .zero 32
t6_wrd2:      .zero 32
t7_bb1:       .zero 32
t7_bb2:       .zero 32
t8_pm1sq:     .zero 32
t9_lid:       .zero 32
t10_GxGy:     .zero 32
