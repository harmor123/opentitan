/* Minimal: addv.16H only */
.section .text.start
.globl main
main:
  li     x2, 2
  la     x3, vec_a
  bn.lid x2, 0(x3)
  li     x2, 3
  la     x3, vec_b
  bn.lid x2, 0(x3)
  bn.addv.16H  w10, w2, w3
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
  ecall

.data
.balign 32
vec_a:
  .word 0x00017fff
  .word 0xaaaa5555
  .word 0xffff0000
  .word 0x7fff8000
  .word 0x80007fff
  .word 0x00010001
  .word 0x0000ffff
  .word 0x7fff8000
vec_b:
  .word 0xffff8000
  .word 0x55555555
  .word 0x00010001
  .word 0x80007fff
  .word 0x80008000
  .word 0x7fffffff
  .word 0x00010001
  .word 0x00010001
