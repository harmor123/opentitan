/* Smoke test for bn.shv.16H, bn.shv.8S — edge cases */
.section .text.start
.globl main
main:
  /* Load test vector */
  addi   x2, x0, 0
  la     x3, vec_orig
  bn.lid x2, 0(x3)

  /* bn.shv.8S right by 1: 32-bit element shift */
  bn.shv.8S   w10, w0 >> 1

  /* bn.shv.8S right by 31: maximum 32-bit shift */
  bn.shv.8S   w11, w0 >> 31

  /* bn.shv.16H right by 1: 16-bit element shift */
  bn.shv.16H  w12, w0 >> 1

  /* bn.shv.16H right by 15: maximum 16-bit shift */
  bn.shv.16H  w13, w0 >> 15

  /* bn.shv.16H left by 1 */
  bn.shv.16H  w14, w0 << 1

  /* Store results */
  la     x7, result
  bn.sid x10, 0(x7)
  bn.sid x11, 32(x7)
  bn.sid x12, 64(x7)
  bn.sid x13, 96(x7)
  bn.sid x14, 128(x7)

  /* Clear working registers */
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

  addi x2, x0, 0
  addi x3, x0, 0

  xor  x8,  x8,  x8
  xor  x9,  x9,  x9
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
  xor  x25, x25, x25
  xor  x26, x26, x26
  xor  x27, x27, x27
  xor  x28, x28, x28
  xor  x29, x29, x29
  xor  x30, x30, x30
  xor  x31, x31, x31

  ecall

.section .data

/*
  Test vector for shv — each 32-bit element has recognizable pattern
  Elements: [0x80000000, 0x7fffffff, 0x00000001, 0xffffffff,
             0x55555555, 0xaaaaaaaa, 0x12345678, 0x00000000]
  (INT32_MIN, INT32_MAX, 1, -1, alternating bits, inverse alt, pattern, zero)
*/
vec_orig:
  .word 0x00000000
  .word 0x12345678
  .word 0xaaaaaaaa
  .word 0x55555555
  .word 0xffffffff
  .word 0x00000001
  .word 0x7fffffff
  .word 0x80000000

/*
  Expected bn.shv.8S >> 1:
  elem[0]: 0x80000000 >> 1 = 0x40000000
  elem[1]: 0x7fffffff >> 1 = 0x3fffffff
  elem[2]: 0x00000001 >> 1 = 0x00000000
  elem[3]: 0xffffffff >> 1 = 0x7fffffff
  elem[4]: 0x55555555 >> 1 = 0x2aaaaaaa
  elem[5]: 0xaaaaaaaa >> 1 = 0x55555555
  elem[6]: 0x12345678 >> 1 = 0x091a2b3c
  elem[7]: 0x00000000 >> 1 = 0x00000000
  res = 0x00000000_091a2b3c_55555555_2aaaaaaa_7fffffff_00000000_3fffffff_40000000
*/

/*
  Expected bn.shv.8S >> 31:
  elem[0]: 0x80000000 >> 31 = 0x00000001
  elem[1]: 0x7fffffff >> 31 = 0x00000000
  elem[2]: 0x00000001 >> 31 = 0x00000000
  elem[3]: 0xffffffff >> 31 = 0x00000001
  elem[4]: 0x55555555 >> 31 = 0x00000000
  elem[5]: 0xaaaaaaaa >> 31 = 0x00000001
  elem[6]: 0x12345678 >> 31 = 0x00000000
  elem[7]: 0x00000000 >> 31 = 0x00000000
  res = 0x00000000_00000000_00000001_00000000_00000001_00000000_00000000_00000001
*/

/*
  Expected bn.shv.16H >> 1 (16-bit elements):
  Original 256-bit split into 16 16-bit elements:
  [0x0000, 0x8000, 0x7fff, 0xffff, 0x0000, 0x0001, 0xffff, 0xffff,
   0x5555, 0x5555, 0xaaaa, 0xaaaa, 0x5678, 0x1234, 0x0000, 0x0000]
  After >>1:
  [0x0000, 0x4000, 0x3fff, 0x7fff, 0x0000, 0x0000, 0x7fff, 0x7fff,
   0x2aaa, 0x2aaa, 0x5555, 0x5555, 0x2b3c, 0x091a, 0x0000, 0x0000]
  res = 0x00000000_091a2b3c_55555555_2aaa2aaa_7fff7fff_00000000_7fff3fff_40000000
*/

/*
  Expected bn.shv.16H >> 15 (max 16-bit shift):
  [0x0000>>15=0, 0x8000>>15=1, 0x7fff>>15=0, 0xffff>>15=1,
   0x0000>>15=0, 0x0001>>15=0, 0xffff>>15=1, 0xffff>>15=1,
   0x5555>>15=0, 0x5555>>15=0, 0xaaaa>>15=1, 0xaaaa>>15=1,
   0x5678>>15=0, 0x1234>>15=0, 0x0000>>15=0, 0x0000>>15=0]
  res = 0x00000000_00000000_00010001_00000000_00010001_00000000_00000001_00000000
*/

/*
  Expected bn.shv.16H << 1:
  [0x0000<<1=0x0000, 0x8000<<1=0x0000(overflow), 0x7fff<<1=0xfffe,
   0xffff<<1=0xfffe, 0x0000<<1=0, 0x0001<<1=0x0002,
   0xffff<<1=0xfffe, 0xffff<<1=0xfffe,
   0x5555<<1=0xaaaa, 0x5555<<1=0xaaaa,
   0xaaaa<<1=0x5554, 0xaaaa<<1=0x5554,
   0x5678<<1=0xacf0, 0x1234<<1=0x2468,
   0x0000<<1=0, 0x0000<<1=0]
  res = 0x00000000_2468acf0_55545554_aaaaaaaa_fffefffe_00020000_fffefffe_00000000
*/

.balign 32
.globl result
result:
  .zero 256
