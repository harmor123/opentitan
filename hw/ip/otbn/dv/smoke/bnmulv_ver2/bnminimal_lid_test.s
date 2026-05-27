/* Minimal: bn.lid + bn.or + bn.wsrw MOD (baseline only, no ver2) */
.section .text.start
.globl main
main:
  li      x5, 2
  la      x6, modulus
  bn.lid  x5++, 0(x6)
  la      x6, modulus_inv
  bn.lid  x5, 0(x6)
  bn.or   w2, w2, w3 << 32
  bn.wsrw MOD, w2
  ecall

.section .data
.balign 32
modulus:
  .word 0x00000d01
  .zero 28

modulus_inv:
  .word 0x00000cff
  .zero 28
