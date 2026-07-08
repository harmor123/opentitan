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

.balign 32
/* Local weak stack_end for standalone OTBN microbench. */
.section .data
.balign 32
.zero 4096
.weak stack_end
stack_end:

