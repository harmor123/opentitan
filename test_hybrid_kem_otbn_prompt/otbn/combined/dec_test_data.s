/* ML-KEM Decap data — buffers only, Ibex writes inputs at runtime */

.data
.balign 32
.globl dec_ss
dec_ss:
  .zero 32

.balign 32
/* Ibex writes dec_ct at runtime */
.globl dec_ct
dec_ct:
  .zero 1088

/* Ibex writes dec_dk at runtime */
.globl dec_dk
dec_dk:
  .zero 2400
