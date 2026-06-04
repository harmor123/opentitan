/* ML-KEM Encap data — buffers only, Ibex writes inputs at runtime */

.data
.balign 32
.globl enc_ct
enc_ct:
  .zero 1088
.globl enc_ss
enc_ss:
  .zero 32

.balign 32
/* Ibex writes enc_coins at runtime */
.globl enc_coins
enc_coins:
  .zero 64

/* Ibex writes enc_ek at runtime */
.globl enc_ek
enc_ek:
  .zero 1184
