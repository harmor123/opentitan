/* Smoke test for bn.addv.16H, bn.addv.8S, bn.subv.16H, bn.subv.8S — edge cases */
.section .text.start
.globl main
main:
  addi   x2, x0, 2
  la     x3, vec_a_16h
  bn.lid x2++, 0(x3)
  la     x3, vec_b_16h
  bn.lid x2++, 0(x3)

  /* bn.addv.16H: 16-bit vector add, edge cases */
  bn.addv.16H  w10, w2, w3

  /* bn.subv.16H: 16-bit vector sub, edge cases */
  bn.subv.16H  w11, w2, w3

  /* bn.addv.8S: 32-bit vector add, edge cases */
  addi   x2, x0, 4
  la     x3, vec_a_8s
  bn.lid x2++, 0(x3)
  la     x3, vec_b_8s
  bn.lid x2++, 0(x3)

  bn.addv.8S   w12, w4, w5

  /* bn.subv.8S: 32-bit vector sub */
  bn.subv.8S   w13, w4, w5

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

  /* Clear working registers */
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
  bn.xor w4, w4, w4
  bn.xor w5, w5, w5
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
  16-bit vector vec_a for addv/subv
  Elements: [0x8000, 0x7fff, 0xffff, 0x0000, 0x0001, 0x0001, 0x7fff, 0x8000,
             0x8000, 0x7fff, 0x0000, 0xffff, 0x5555, 0xaaaa, 0x7fff, 0x0001]
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
  16-bit vector vec_b for addv/subv
  Elements: [0x0001, 0x0001, 0x0001, 0x0001, 0xffff, 0x7fff, 0x8000, 0x8000,
             0x7fff, 0x8000, 0x0001, 0x0001, 0x5555, 0x5555, 0x8000, 0xffff]
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
  32-bit vector vec_a for addv/subv
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
  32-bit vector vec_b for addv/subv
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

.balign 32
.globl result
result:
  .zero 256
