/* Smoke test for bn.addv / bn.subv — comprehensive coverage
 *
 * BUG suspicion: bare bn.addv (no suffix) may differ between RTL and ISS
 * in default element width. ML-KEM encap uses bn.addv w1,w1,w3 with
 * w3 = 0x0681 in every 16-bit lane (KYBER reduction constant).
 *
 * Test matrix:
 *   Explicit: addv.16H, addv.8S, subv.16H, subv.8S (edge cases)
 *   Bare:     addv, subv (default element width behavior)
 *   ML-KEM:   addv with w3 = 0x0681 pattern (encap reduction path)
 */
.section .text.start
.globl main
main:
  /* ── 1. Load explicit-suffix test vectors ── */
  addi   x2, x0, 2
  la     x3, vec_a_16h
  bn.lid x2++, 0(x3)
  la     x3, vec_b_16h
  bn.lid x2++, 0(x3)

  bn.addv.16H  w10, w2, w3       /* result[0]: 16H add */
  bn.subv.16H  w11, w2, w3       /* result[1]: 16H sub */

  addi   x2, x0, 4
  la     x3, vec_a_8s
  bn.lid x2++, 0(x3)
  la     x3, vec_b_8s
  bn.lid x2++, 0(x3)

  bn.addv.8S   w12, w4, w5       /* result[2]: 8S add */
  bn.subv.8S   w13, w4, w5       /* result[3]: 8S sub */

  /* ── 2. Bare (no-suffix) addv/subv — default element width ── */
  /* Same 16H inputs in w2,w3 — verify bare addv matches .16H */
  bn.addv      w14, w2, w3       /* result[4]: bare addv (should = w10) */
  bn.subv      w15, w2, w3       /* result[5]: bare subv (should = w11) */

  /* Same 8S inputs in w4,w5 — also test bare addv on 32-bit data */
  bn.addv      w16, w4, w5       /* result[6]: bare addv on 8S-sized data */
  bn.subv      w17, w4, w5       /* result[7]: bare subv on 8S-sized data */

  /* ── 3. ML-KEM encap reduction pattern ── */
  /* w3 = 0x0681 in every 16-bit lane (KYBER_Q over 2 for reduction) */
  addi   x2, x0, 18
  la     x3, vec_mlkem
  bn.lid x2++, 0(x3)             /* w18 = test data */
  bn.lid x2, 32(x3)              /* w19 = 0x0681 constant */

  bn.shv.8S   w20, w18 >> 16     /* result[8]:  shift right 16 (32-bit) */
  bn.addv      w21, w18, w19     /* result[9]:  bare addv with 0x0681 const */
  bn.subv      w22, w18, w19     /* result[10]: bare subv with 0x0681 const */
  bn.addv.16H  w23, w18, w19     /* result[11]: explicit 16H addv w/ 0x0681 */
  bn.addv.8S   w24, w20, w19     /* result[12]: explicit 8S addv w/ 0x0681 */

  /* Store results */
  la     x7, result
  addi   x10, x0, 10
  bn.sid x10, 0(x7)
  addi   x11, x0, 11
  bn.sid x11, 32(x7)
  addi   x12, x0, 12
  bn.sid x12, 64(x7)
  addi   x13, x0, 13
  bn.sid x13, 96(x7)
  addi   x14, x0, 14
  bn.sid x14, 128(x7)
  addi   x15, x0, 15
  bn.sid x15, 160(x7)
  addi   x16, x0, 16
  bn.sid x16, 192(x7)
  addi   x17, x0, 17
  bn.sid x17, 224(x7)
  addi   x20, x0, 20
  bn.sid x20, 256(x7)
  addi   x21, x0, 21
  bn.sid x21, 288(x7)
  addi   x22, x0, 22
  bn.sid x22, 320(x7)
  addi   x23, x0, 23
  bn.sid x23, 352(x7)
  addi   x24, x0, 24
  bn.sid x24, 384(x7)

  /* Clear working registers */
  bn.xor w2,  w2,  w2
  bn.xor w3,  w3,  w3
  bn.xor w4,  w4,  w4
  bn.xor w5,  w5,  w5
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

  addi x2, x0, 0
  addi x3, x0, 0
  xor  x7, x7, x7
  xor  x8, x8, x8
  xor  x9, x9, x9
  xor  x10, x10, x10
  xor  x11, x11, x11
  xor  x12, x12, x12
  xor  x13, x13, x13
  xor  x14, x14, x14
  xor  x15, x15, x15
  xor  x16, x16, x16
  xor  x17, x17, x17
  xor  x18, x18, x18
  xor  x19, x19, x19
  xor  x20, x20, x20
  xor  x21, x21, x21
  xor  x22, x22, x22
  xor  x23, x23, x23
  xor  x24, x24, x24

  ecall

.section .data

/*
  16-bit vector vec_a
  Elements (MSB→LSB): [0x8000,0x7fff, 0xffff,0x0000, 0x0001,0x0001, 0x7fff,0x8000,
                        0x8000,0x7fff, 0x0000,0xffff, 0x5555,0xaaaa, 0x7fff,0x0001]
*/
vec_a_16h:
  .word 0x00017fff
  .word 0xaaaa5555
  .word 0xffff0000
  .word 0x7fff8000
  .word 0x80007fff
  .word 0x00010001
  .word 0x0000ffff
  .word 0x7fff8000

/*
  16-bit vector vec_b
  Elements: [0x0001,0x0001, 0x0001,0x0001, 0xffff,0x7fff, 0x8000,0x8000,
             0x7fff,0x8000, 0x0001,0x0001, 0x5555,0x5555, 0x8000,0xffff]
*/
vec_b_16h:
  .word 0xffff8000
  .word 0x55555555
  .word 0x00010001
  .word 0x80007fff
  .word 0x80008000
  .word 0x7fffffff
  .word 0x00010001
  .word 0x00010001

/*
  32-bit vector vec_a
  Elements: [0x80000000, 0x7fffffff, 0xffffffff, 0x00000000,
             0x00000001, 0x7fffffff, 0x80000000, 0xffffffff]
*/
vec_a_8s:
  .word 0xffffffff
  .word 0x80000000
  .word 0x7fffffff
  .word 0x00000001
  .word 0x00000000
  .word 0xffffffff
  .word 0x7fffffff
  .word 0x80000000

/*
  32-bit vector vec_b
  Elements: [0x00000001, 0x00000001, 0x00000001, 0x00000001,
             0xffffffff, 0x80000000, 0x80000000, 0x7fffffff]
*/
vec_b_8s:
  .word 0x7fffffff
  .word 0x80000000
  .word 0x80000000
  .word 0xffffffff
  .word 0x00000001
  .word 0x00000001
  .word 0x00000001
  .word 0x00000001

/*
  ML-KEM encap reduction pattern:
  w18 = test data (matches encap SHV <<10 output pattern)
  w19 = 0x0681 in every 16-bit lane (KYBER_Q over 2 for signed reduction)

  Expected bare bn.addv w18, w19 (16-bit default):
    Each 16-bit lane += 0x0681

  Expected bare bn.addv w18, w19 (32-bit default):
    Each 32-bit lane += 0x06810681  ← THIS IS THE BUG IF RTL USES 16-bit
*/
vec_mlkem:
  /* w18: test data — each 32b element similar to encap SHV output */
  .word 0x28800000
  .word 0x0008dc00
  .word 0x00010000
  .word 0x001ce800
  .word 0x00184800
  .word 0x00007c00
  .word 0x0002f400
  .word 0x0015f000
  /* w19: 0x0681 repeated in every 16-bit lane */
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681

/*
  Expected results:

  result[0] (w10): bn.addv.16H w2,w3 — same as original test
  result[1] (w11): bn.subv.16H w2,w3 — same as original test
  result[2] (w12): bn.addv.8S  w4,w5 — same as original test
  result[3] (w13): bn.subv.8S  w4,w5 — same as original test

  result[4] (w14): bare bn.addv w2,w3 — must match w10
  result[5] (w15): bare bn.subv w2,w3 — must match w11
  result[6] (w16): bare bn.addv w4,w5
  result[7] (w17): bare bn.subv w4,w5

  result[8]  (w20): bn.shv.8S w18 >> 16
  result[9]  (w21): bare bn.addv w18, w19 (with 0x0681)
  result[10] (w22): bare bn.subv w18, w19
  result[11] (w23): bn.addv.16H w18, w19
  result[12] (w24): bn.addv.8S w20, w19
*/

.balign 32
.globl result
result:
  .zero 512   /* 13 WDRs */
