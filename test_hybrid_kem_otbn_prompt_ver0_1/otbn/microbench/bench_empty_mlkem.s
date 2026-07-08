.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x2, stack_end
  li x5, 1
  LOOP x5, 1
    jal x1, mlkem_empty_leaf
  ecall

mlkem_empty_leaf:
  ret

.data
.balign 32
.global stack
stack:
  .zero 4096
.global stack_end
stack_end:
