/*
 * ML-KEM-768 combined entry point.
 * Ibex writes mode to dmem[mode], then execute.
 *
 * Modes:
 *   0 = ML-KEM-768 KeyGen (input at coins; output at ek, dk)
 *   1 = ML-KEM-768 Encap  (input at ek, coins; output at ct, ss)
 *   2 = ML-KEM-768 Decap  (input at dk, ct; output at ss)
 *
 * All modes: init MOD=KYBER_Q from DMEM labels before calling crypto function.
 */

.section .text.start

.globl main
main:
  /* Clear WDRs */
  bn.xor  w0, w0, w0
  bn.xor  w1, w1, w1
  bn.xor  w2, w2, w2
  bn.xor  w3, w3, w3
  bn.xor  w4, w4, w4
  bn.xor  w5, w5, w5
  bn.xor  w6, w6, w6
  bn.xor  w7, w7, w7
  bn.xor  w8, w8, w8
  bn.xor  w9, w9, w9
  bn.xor  w10, w10, w10
  bn.xor  w11, w11, w11
  bn.xor  w12, w12, w12
  bn.xor  w13, w13, w13
  bn.xor  w14, w14, w14
  bn.xor  w15, w15, w15
  bn.xor  w16, w16, w16
  bn.xor  w17, w17, w17
  bn.xor  w18, w18, w18
  bn.xor  w19, w19, w19
  bn.xor  w20, w20, w20
  bn.xor  w21, w21, w21
  bn.xor  w22, w22, w22
  bn.xor  w23, w23, w23
  bn.xor  w24, w24, w24
  bn.xor  w25, w25, w25
  bn.xor  w26, w26, w26
  bn.xor  w27, w27, w27
  bn.xor  w28, w28, w28
  bn.xor  w29, w29, w29
  bn.xor  w30, w30, w30
  bn.xor  w31, w31, w31

  /* Init stack pointer */
  la   x2, stack_end

  /* Load mode from dmem[mode] */
  la      x3, mode
  lw      x4, 0(x3)

  /* Switch on mode */
  li      x3, 0
  beq     x4, x3, run_keypair

  li      x3, 1
  beq     x4, x3, run_encap

  li      x3, 2
  beq     x4, x3, run_decap

  /* Invalid mode: loop */
  jal     x0, .

run_keypair:
  /* Init MOD = KYBER_Q */
  li      x5, 2
  la      x6, modulus
  bn.lid  x5++, 0(x6)
  la      x6, modulus_inv
  bn.lid  x5, 0(x6)
  bn.or   w2, w2, w3 << 32
  bn.wsrw 0x0, w2
  la      x10, kp_coins
  la      x11, kp_ek
  la      x12, kp_dk
  jal     x1, crypto_kem_keypair
  ecall

run_encap:
  /* Init MOD = KYBER_Q */
  li      x5, 2
  la      x6, modulus
  bn.lid  x5++, 0(x6)
  la      x6, modulus_inv
  bn.lid  x5, 0(x6)
  bn.or   w2, w2, w3 << 32
  bn.wsrw 0x0, w2
  la      x10, enc_coins
  la      x11, enc_ct
  la      x12, enc_ss
  la      x13, enc_ek
  jal     x1, crypto_kem_enc
  ecall

run_decap:
  /* Init MOD = KYBER_Q */
  li      x5, 2
  la      x6, modulus
  bn.lid  x5++, 0(x6)
  la      x6, modulus_inv
  bn.lid  x5, 0(x6)
  bn.or   w2, w2, w3 << 32
  bn.wsrw 0x0, w2
  la      x10, dec_dk
  la      x11, dec_ct
  la      x12, dec_ss
  jal     x1, crypto_kem_dec
  ecall

.data
.balign 32
.globl stack
stack:
  .zero 20000
.globl stack_end
stack_end:

.balign 32
.globl mode
mode:
  .zero 4
