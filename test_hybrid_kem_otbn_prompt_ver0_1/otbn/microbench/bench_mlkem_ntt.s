.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x2, stack_end
  la x10, poly_in
  la x11, twiddles_ntt
  la x12, poly_out
  jal x1, ntt
  ecall

.data
.balign 32
.globl poly_in
poly_in:
  .zero 1024
.globl poly_out
poly_out:
  .zero 1024
.globl modulus
modulus:
  .word 0x00000d01, 0, 0, 0, 0, 0, 0, 0
.globl twiddles_ntt
twiddles_ntt:
  .zero 2048

.balign 32
/* Local weak stack_end for standalone OTBN microbench. */
.section .data
.balign 32
.zero 4096
.weak stack_end
stack_end:

