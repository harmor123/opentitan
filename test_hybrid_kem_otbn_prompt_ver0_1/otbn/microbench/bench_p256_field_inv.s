.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  jal x1, setup_modp
  li x2, 10
  la x3, bench_z
  bn.lid x2, 0(x3)
  jal x1, p256_field_inv_once
  ecall

p256_field_inv_once:
  bn.addm w10, w10, w31

  bn.mov w24, w10
  bn.mov w25, w10
  jal x1, mul_modp

  bn.mov w24, w19
  bn.mov w25, w10
  jal x1, mul_modp
  bn.mov w12, w19

  bn.mov w24, w19
  bn.mov w25, w19
  jal x1, mul_modp

  bn.mov w24, w19
  bn.mov w25, w10
  jal x1, mul_modp
  bn.mov w13, w19

  bn.mov w24, w19
  loopi 3, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w13
  jal x1, mul_modp
  bn.mov w14, w19

  bn.mov w24, w19
  loopi 6, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w14
  jal x1, mul_modp
  bn.mov w15, w19

  bn.mov w24, w19
  loopi 3, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w13
  jal x1, mul_modp
  bn.mov w16, w19

  bn.mov w24, w19
  loopi 15, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w16
  jal x1, mul_modp
  bn.mov w17, w19

  bn.mov w24, w19
  loopi 2, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w12
  jal x1, mul_modp
  bn.mov w18, w19

  bn.mov w24, w19
  loopi 32, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w10
  jal x1, mul_modp

  bn.mov w24, w19
  loopi 128, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w18
  jal x1, mul_modp

  bn.mov w24, w19
  loopi 32, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w18
  jal x1, mul_modp

  bn.mov w24, w19
  loopi 30, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w17
  jal x1, mul_modp

  bn.mov w24, w19
  loopi 2, 3
    bn.mov w25, w19
    jal x1, mul_modp
    bn.mov w24, w19
  bn.mov w25, w10
  jal x1, mul_modp
  bn.mov w14, w19
  ret

.data
.balign 32
bench_z:
  .word 0x01234567, 0x89abcdef, 0x11111111, 0x22222222
  .word 0x33333333, 0x44444444, 0x55555555, 0x00000001
