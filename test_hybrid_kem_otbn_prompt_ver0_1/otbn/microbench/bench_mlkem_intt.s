.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x2, stack_end
  la x10, poly_in
  la x11, twiddles_intt
  jal x1, intt
  ecall

.data
.balign 32
.globl poly_in
poly_in:
  .zero 2048
.globl modulus
modulus:
  .word 0x00000d01, 0, 0, 0, 0, 0, 0, 0
.globl twiddles_intt
twiddles_intt:
  .zero 2048

.balign 32
/* Local weak stack_end for standalone OTBN microbench. */
.section .data
.balign 32
.zero 4096
.weak stack_end
stack_end:

