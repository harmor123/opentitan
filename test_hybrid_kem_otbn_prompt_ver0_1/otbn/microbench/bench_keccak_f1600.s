.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x10, context
  jal x1, keccakf
  ecall

.data
.balign 32
.globl context
context:
  .zero 224
.globl rc
rc:
  .zero 768
