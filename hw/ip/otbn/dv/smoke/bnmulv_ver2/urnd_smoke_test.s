/* URND/RND PRNG test — verifies ISS and RTL produce same random values */
/* Test reads URND and RND WSRs, writes them to WDRs for comparison */

.section .text.start

.globl main
main:
  /* Request URND seed */
  csrrw x0, 0x7c0, x0

  /* w0 = URND (WSR 0x2) */
  bn.wsrr w0, 0x2

  /* w1 = RND (WSR 0x1) — needs prefetch first */
  csrrw x0, 0x7c1, x0
  bn.wsrr w1, 0x1

  /* Zero out unused WDRs */
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
  bn.xor w4, w4, w4
  bn.xor w5, w5, w5
  bn.xor w6, w6, w6
  bn.xor w7, w7, w7
  bn.xor w8, w8, w8
  bn.xor w9, w9, w9
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

  /* Zero out GPRs used */
  xor x2, x2, x2
  xor x3, x3, x3
  xor x4, x4, x4
  xor x5, x5, x5
  xor x6, x6, x6
  xor x7, x7, x7
  xor x8, x8, x8
  xor x9, x9, x9
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

  ecall
