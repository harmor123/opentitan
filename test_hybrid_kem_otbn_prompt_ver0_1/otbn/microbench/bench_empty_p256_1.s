.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  jal x1, setup_modp

  li x2, 20
  la x3, bench_a
  bn.lid x2, 0(x3)

  li x2, 21
  la x3, bench_b
  bn.lid x2, 0(x3)

  li x5, 32
  LOOP x5, 1
    bn.mov w19, w20

  ecall

.data
.balign 32
.globl bench_a
bench_a:
  .word 0x01234567, 0x89abcdef, 0x11111111, 0x22222222
  .word 0x33333333, 0x44444444, 0x55555555, 0x66666666

.balign 32
.globl bench_b
bench_b:
  .word 0x76543210, 0xfedcba98, 0x77777777, 0x88888888
  .word 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc