/* Smoke test for bn.modp256 — P-256 modular multiplication
 * Aligned with ISS test modp256_test.s register usage (x3 auto-inc, x10 addr).
 * x2/x8 are NOT used.
 */

.section .text.start
.globl main
main:
  /* Zeroize all WDRs for clean state */
  bn.xor w0,  w0,  w0
  bn.xor w1,  w1,  w1
  bn.xor w2,  w2,  w2
  bn.xor w3,  w3,  w3
  bn.xor w4,  w4,  w4
  bn.xor w5,  w5,  w5
  bn.xor w6,  w6,  w6
  bn.xor w7,  w7,  w7
  bn.xor w8,  w8,  w8
  bn.xor w9,  w9,  w9
  bn.xor w10, w10, w10
  bn.xor w11, w11, w11
  bn.xor w12, w12, w12
  bn.xor w13, w13, w13
  bn.xor w14, w14, w14
  bn.xor w15, w15, w15
  bn.xor w16, w16, w16
  bn.xor w17, w17, w17
  bn.xor w18, w18, w18
  bn.xor w19, w19, w19
  bn.xor w20, w20, w20
  bn.xor w21, w21, w21
  bn.xor w22, w22, w22
  bn.xor w23, w23, w23
  bn.xor w24, w24, w24
  bn.xor w25, w25, w25
  bn.xor w26, w26, w26
  bn.xor w27, w27, w27
  bn.xor w28, w28, w28
  bn.xor w29, w29, w29
  bn.xor w30, w30, w30
  bn.xor w31, w31, w31

  /* Zeroize GPRs except x2 (sp) and x8 (reserved) */
  xor x3,  x3,  x3
  xor x4,  x4,  x4
  xor x5,  x5,  x5
  xor x6,  x6,  x6
  xor x7,  x7,  x7
  xor x9,  x9,  x9
  xor x10, x10, x10
  xor x11, x11, x11
  xor x12, x12, x12
  xor x13, x13, x13
  xor x14, x14, x14
  xor x15, x15, x15
  xor x16, x16, x16
  xor x17, x17, x17
  xor x18, x18, x18
  xor x19, x19, x19
  xor x20, x20, x20
  xor x21, x21, x21
  xor x22, x22, x22
  xor x23, x23, x23
  xor x24, x24, x24
  xor x25, x25, x25
  xor x26, x26, x26
  xor x27, x27, x27
  xor x28, x28, x28
  xor x29, x29, x29
  xor x30, x30, x30
  xor x31, x31, x31

  /* === Test 1: 0 * 0 mod p = 0 === */
  bn.modp256 w2, w0, w0

  /* === Test 2: 1 * 1 mod p = 1 === */
  li      x3, 3
  la      x10, op_one
  bn.lid  x3++, 0(x10)          /* w3 = 1, x3=4 */
  bn.lid  x3, 0(x10)            /* w4 = 1 */
  bn.modp256 w5, w3, w4

  /* === Test 3: 3 * 5 mod p = 15 === */
  li      x3, 6
  la      x10, op_3
  bn.lid  x3++, 0(x10)          /* w6 = 3, x3=7 */
  la      x10, op_5
  bn.lid  x3, 0(x10)            /* w7 = 5 */
  bn.modp256 w8, w6, w7

  /* === Test 4: (p-1) * 1 mod p = p-1 === */
  li      x3, 9
  la      x10, op_pminus1
  bn.lid  x3++, 0(x10)          /* w9 = p-1, x3=10 */
  la      x10, op_one
  bn.lid  x3, 0(x10)            /* w10 = 1 */
  bn.modp256 w11, w9, w10

  /* === Test 5: (p-1) * 2 mod p = p-2 === */
  li      x3, 12
  la      x10, op_pminus1
  bn.lid  x3++, 0(x10)          /* w12 = p-1, x3=13 */
  la      x10, op_2
  bn.lid  x3, 0(x10)            /* w13 = 2 */
  bn.modp256 w14, w12, w13

  /* === Test 6: (p-1)^2 mod p = 1 === */
  li      x3, 15
  la      x10, op_pminus1
  bn.lid  x3++, 0(x10)          /* w15 = p-1, x3=16 */
  bn.lid  x3, 0(x10)            /* w16 = p-1 */
  bn.modp256 w17, w15, w16

  /* === Test 7: Gx * Gy mod p (real P-256 curve values) === */
  li      x3, 18
  la      x10, op_p256_gx
  bn.lid  x3++, 0(x10)          /* w18 = Gx, x3=19 */
  la      x10, op_p256_gy
  bn.lid  x3, 0(x10)            /* w19 = Gy */
  bn.modp256 w20, w18, w19

  /* === Test 8: large a * b mod p === */
  li      x3, 21
  la      x10, value_a
  bn.lid  x3++, 0(x10)          /* w21 = a, x3=22 */
  la      x10, value_b
  bn.lid  x3, 0(x10)            /* w22 = b */
  bn.modp256 w23, w21, w22

  /* === Test 9: p * 1 mod p = 0 === */
  li      x3, 24
  la      x10, op_p256p
  bn.lid  x3++, 0(x10)          /* w24 = p, x3=25 */
  la      x10, op_one
  bn.lid  x3, 0(x10)            /* w25 = 1 */
  bn.modp256 w26, w24, w25

  /* === Test 10: (p+1) * 1 mod p = 1 === */
  li      x3, 27
  la      x10, op_p256p_plus1
  bn.lid  x3++, 0(x10)          /* w27 = p+1, x3=28 */
  la      x10, op_one
  bn.lid  x3, 0(x10)            /* w28 = 1 */
  bn.modp256 w29, w27, w28

  ecall

.data
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
