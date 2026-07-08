.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  jal x1, setup_modp
  li x2, 20
  la x3, bench_a
  bn.lid x2, 0(x3)
  li x5, 32
  LOOP x5, 3
    bn.mov w24, w20
    bn.mov w25, w20
    jal x1, mul_modp
  ecall

.data
.balign 32
bench_a:
  .word 0x01234567, 0x89abcdef, 0x11111111, 0x22222222
  .word 0x33333333, 0x44444444, 0x55555555, 0x66666666
