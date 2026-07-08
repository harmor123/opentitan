.section .text.start
.globl main
main:
  bn.xor w31, w31, w31
  la x2, stack_end
  la x11, poly_a
  la x13, poly_out
  la x28, twiddles_ntt
  la x29, poly_b
  jal x1, basemul
  ecall

.data
.balign 32
.globl poly_a
poly_a:
  .zero 1024
.globl poly_b
poly_b:
  .zero 1024
.globl poly_out
poly_out:
  .zero 1024
.globl qinv
qinv:
  .word 0x6ba8f301, 0, 0, 0, 0, 0, 0, 0
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

