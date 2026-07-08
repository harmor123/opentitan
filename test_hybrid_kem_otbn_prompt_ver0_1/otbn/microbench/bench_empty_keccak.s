.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x10, context
  li x5, 1
  LOOP x5, 1
    jal x1, keccak_empty_leaf
  ecall

keccak_empty_leaf:
  ret

.data
.balign 32
context:
  .zero 224
