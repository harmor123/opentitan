/* Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Name:        indcpa_keypair_plain
 *
 * Description: Generates public and private key for the CPA-secure
 *              public-key encryption scheme underlying Kyber
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                             (of length 1184 bytes)
 *              - uint8_t *sk: pointer to output private key
 *                             (of length 1152 bytes)
 *
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): pointer to seed (32 = 32)
 * @param[out] x11 (x11): dmem pointer to public key pk_addr
 * @param[out] x12 (x12): dmem pointer to secret key sk_addr
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */

indcpa_keypair_plain:

  /* Store parameters to stack */
  sw  x10, -16(fp)
  sw  x11, -32(fp)
  sw  x12, -24(fp)

  /*** hash_g: SHA3-512 ***/
  la   x10, context
  li   x11, 64 /* output len */
  jal  x1, sha3_init
  la   x10, context
  lw   x11, -16(fp)
  li   x12, 32 /* input len */
  jal  x1, sha3_update
  addi  x11, x0, 3
  sw    x11, -128(fp)
  la    x10, context
  addi  x11, fp, -128
  addi  x12, x0, 1
  jal   x1, sha3_update
  la   x10, context
  addi x11, fp, -128
  jal  x1, sha3_final

  /*** CBD skpv ***/
  li   x15, -2176
  li   x11, -3712
  add  x11, fp, x11
  li   x13, -64
  li   x12, 0
  LOOPI 3, 5
    add  x6, fp, x15
    addi x10, fp, -96
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_1
    addi x12, x12, 1 

  /*** NTT skpv ***/
  /* ntt(skpv) */
  li   x10, -3712
  add  x10, fp, x10
  add  x12, x0, x10
  .rept 3
    la  x11, twiddles_ntt_base
    jal x1, ntt_base_kyber
  .endr
  
  /*** Packing sk ***/
  li   x10, -3712
  add  x10, fp, x10
  lw   x13, -24(fp)
  jal  x1, pack_sk

  /*** Matrix generation ***/
  li   x11, -2176
  add  x11, fp, x11
  li   x12, 0
  .rept 3
    /* Gen 1st mat poly */
    addi x10, fp, -128
    jal  x1, poly_gen_matrix_plain
    addi x12, x12, 1

    /* Mutliply this generated poly with sk */
    addi x11, x11, -512 /* point back to A[0][0] */
    li   x29, -3712
    add  x29, fp, x29 /* point to sk[0] */
    add  x13, x11, x0   /* output at A[0][0] */
    la   x28, twiddles_ntt_base
    jal  x1, basemul_base_kyber

    .rept 3-1
      /* Gen next mat poly */
      addi x10, fp, -128
      jal  x1, poly_gen_matrix_plain
      addi x12, x12, 1

      /* Mutliply this generated poly with sk */
      addi x11, x11, -512 /* points back to A[0][1] */
      addi x13, x11, -512 /* points back to A[0][0] for accumulation */
      la   x28, twiddles_ntt_base
      jal  x1, basemul_acc_base_kyber
      addi x11, x11, -512 /* points back to A[0][1] */
    .endr 
    addi x12, x12, 253 
  .endr 
  
  /* toplant */
  li  x10, -2176
  add x10, fp, x10
  la  x12, const_toplant
  .rept 3
    jal x1, poly_reduce
  .endr 

  /*** CBD e ***/
  li   x15, -640
  li   x11, -3712
  add  x11, fp, x11
  li   x13, -64
  li   x12, 3
  LOOPI 3, 5
    add  x6, fp, x15
    addi x10, fp, -96
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_1
    addi x12, x12, 1 

  /*** NTT e ***/
  /* ntt(skpv) */
  li   x10, -3712
  add  x10, fp, x10
  add  x12, x0, x10
  .rept 3
    la  x11, twiddles_ntt_base
    jal x1, ntt_base_kyber
  .endr

  /* Polyvec add */
  li   x10, -2176
  add  x10, fp, x10
  li   x11, -3712 
  add  x11, fp, x11 
  add  x12, x0, x10 
  .rept 3
    jal x1, poly_add_base
  .endr
  
  /*** Packing pk ***/

  lw   x13, -32(fp)
  li   x10, -2176
  add  x10, fp, x10 
  addi x11, fp, -128
  jal  x1, pack_pk

  ret 

/*
 * Name:        crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of 1184 bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of 2400 bytes)
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): pointer to seed (2*32 = 64)
 * @param[out] x11 (x11): dmem pointer to kem_pk
 * @param[out] x12 (x12): dmem pointer to kem_sk 
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */

.globl crypto_kem_keypair
crypto_kem_keypair: 
  /* Set frame pointer */
  addi fp, sp, 0 

    li  x5, -3712

  add  sp, sp, x5  

  /*** indcpa_keypair ***/
  jal  x1, indcpa_keypair_plain
  li   x4, 0
  lw   x10, -32(fp)
  lw   x11, -24(fp)
  addi x11, x11, 1152
  LOOPI 37, 2
    bn.lid x4, 0(x10++)
    bn.sid x4, 0(x11++)

  /*** hash_h ***/
  la   x10, context
  li   x11, 32
  jal  x1, sha3_init
  la   x10, context
  lw   x11, -32(fp)
  li   x12, 1184
  jal  x1, sha3_update
  la   x10, context
  lw   x11, -24(fp)
  addi x11, x11, 1184
  addi x11, x11, 1152
  jal  x1, sha3_final

  /*** Random bytes ***/
  lw      x10, -16(fp)
  addi    x10, x10, 32 
  li      x5, 8
  bn.lid  x5, 0(x10)
  bn.sid  x5, 0(x11++) 

  /* Free space on stack */
  addi sp, fp, 0
  ret

/*
 * Name:        indcpa_enc_plain
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *c: pointer to output ciphertext
 *                            (of length 1088 bytes)
 *              - const uint8_t *m: pointer to input message
 *                                  (of length 32 bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                                   (of length 1184)
 *              - const uint8_t *coins: pointer to input random coins used as seed
 *                                      (of length 32) to deterministically
 *                                      generate all randomness 
 *
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): dmem pointer to input message 
 * @param[in]  x11 (x11): dmem pointer to input packed pk
 * @param[in]  x12 (x12): dmem pointer to input coins 
 * @param[out] x13 (x13): dmem pointer to output ciphertext
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */

indcpa_enc_plain:

  /* Store parameters to stack */
  sw x12, -28(fp)

  /*** poly_frommsg ***/
  la  x11, modulus_over_2
  li  x12, -2656
  add x12, fp, x12 
  jal x1, poly_frommsg_base

  /*** unpack_pk ***/
  lw  x10, -24(fp)
  la  x13, const_0x0fff
  jal x1, unpack_pk

  /*** save seed to dmem ***/
  li     x4, 0
  bn.lid x4, 0(x10)
  bn.sid x4, -96(fp)

  /*** CBD sp ***/
  lw  x10, -28(fp)
  add x14, x0, x10
  li  x11, -4192
  add x11, fp, x11
  li  x15, -608  
  li  x13, -64
  li  x12, 0
  LOOPI 3, 5
    add  x6, fp, x15
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_1
    add  x10, x0, x14
    addi x12, x12, 1  

  /*** NTT ***/
  li  x10, -4192 
  add x10, fp, x10
  add x12, x0, x10 
  .rept 3
    la  x11, twiddles_ntt_base
    jal x1, ntt_base_kyber
  .endr 

  /** v = sp * pkpv **/ 
  li   x29, -2144 
  add  x29, fp, x29
  li   x11, -4192 
  add  x11, fp, x11 
  li   x13, -608
  add  x13, fp, x13
  la   x28, twiddles_ntt_base
  jal  x1, basemul_base_kyber
  /** .rept 3-1 **/ 
  .rept 2
    addi x13, x13, -512
    la   x28, twiddles_ntt_base
    jal  x1, basemul_acc_base_kyber 
  .endr

  /*** reduce v ***/
  li  x10, -608
  add x10, fp, x10
  la  x12, const_1290167
  jal x1, poly_reduce

  /*** INTT v ***/
  li  x10, -608
  add x10, fp, x10 
  add x12, x0, x10 
  la  x11, twiddles_intt_base
  jal x1, intt_base_kyber

  /*** CBD epp ***/
  lw   x10, -28(fp)
  li   x11, -2144
  add  x11, fp, x11
  addi x12, x0, 2*3
  sw   x12, -64(fp)
  li   x13, -64
  li   x6, -1120
  add  x6, fp, x6
  jal  x1, poly_getnoise_eta_2

  /** v = v + k + epp **/
  li   x10, -2656
  add  x10, fp, x10
  li   x11, -608
  add  x11, fp, x11
  add  x12, x0, x11 
  jal  x1, poly_add_base
  addi x11, x11, -512
  addi x12, x12, -512
  jal  x1, poly_add_base

  /*** Matrix vector multiplication ***/
  li   x11, -2656
  add  x11, fp, x11
  li   x12, 0
  .rept 3
    /* Gen 1st mat poly */
    addi x10, fp, -96
    jal  x1, poly_gen_matrix_plain
    addi x12, x12, 0x0100

    /* Mutliply this generated poly with sk */
    addi x11, x11, -512 /* point back to A[0][0] */
    li   x29, -4192
    add  x29, fp, x29 /* point to sk[0] */
    add  x13, x11, x0   /* output at A[0][0] */
    la   x28, twiddles_ntt_base
    jal  x1, basemul_base_kyber
    /** .rept 3-1 **/ 
    .rept 2
      /* Gen next mat poly */
      addi x10, fp, -96
      jal  x1, poly_gen_matrix_plain
      addi x12, x12, 0x0100

      /* Mutliply this generated poly with sk */
      addi x11, x11, -512 /* points back to A[0][1] */
      addi x13, x11, -512 /* points back to A[0][0] for accumulation */
      la   x28, twiddles_ntt_base
      jal  x1, basemul_acc_base_kyber
      addi x11, x11, -512 /* points back to A[0][1] */
    .endr 
    addi x12, x12, -767 
  .endr

  /* reduce */
  li  x10, -2656
  add x10, fp, x10
  la  x12, const_1290167
  .rept 3
    jal x1, poly_reduce
  .endr

  /*** INTT ***/
  li  x10, -2656
  add x10, fp, x10 
  add x12, x0, x10 
  .rept 3
    la  x11, twiddles_intt_base
    jal x1, intt_base_kyber
  .endr 

  /*** CBD ep ***/
  lw  x10, -28(fp)
  li  x11, -4192
  add x11, fp, x11
  add x14, x0, x10
  li  x15, -1120
  li  x13, -64
  li  x12, 3
  LOOPI 3, 5
    add  x6, fp, x15
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_2
    add  x10, x0, x14
    addi x12, x12, 1

  /*** ADD ***/
  /** b = b + ep **/
  li  x10, -2656
  add x10, fp, x10
  li  x11, -4192
  add x11, fp, x11 
  add x12, x0, x10 
  .rept 3
    jal x1, poly_add_base 
  .endr 

  /*** pack_ciphertext ***/
  li   x10, -2656
  add  x10, fp, x10
  li   x11, -608
  add  x11, fp, x11
  lw   x12, -32(fp)
  la   x13, const_1290167
  la   x15, modulus_over_2
  jal  x1, pack_ciphertext
  ret 

/*
 * Name:        crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of 1088 bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of 32 bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of 1184 bytes)
 *
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): dmem pointer to input randombytes (32 = 32)
 * @param[out] x11 (x11): dmem pointer to output ct
 * @param[out] x12 (x12): dmem pointer to output key_b 
 * @param[in]  x13 (x13): dmem pointer to input pk 
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */

.globl crypto_kem_enc
crypto_kem_enc: 

  /* Set frame pointer */
  addi fp, sp, 0 

    li  x5, -4192

  add  sp, sp, x5

  /* Save parameters to stack */
  sw x11, -32(fp)
  sw x12, -20(fp) 
  sw x13, -24(fp)

  /*** Copy randombytes to buf ***/
  li     x4, 0
  bn.lid x4, 0(x10)
  li     x5, -1120
  add    x5, fp, x5 
  bn.sid x4, 0(x5++)
  add    x12, x0, x5 

  /*** hash_h(pk) ***/
  la   x10, context
  li   x11, 32
  jal  x1, sha3_init
  la   x10, context
  lw   x11, -24(fp)
  li   x12, 1184
  jal  x1, sha3_update
  la   x10, context
  li   x11, -1120
  add  x11, fp, x11 
  addi x11, x11, 32
  jal  x1, sha3_final

  /*** hash_g(randombytes||hash_h(pk)) ***/
  la   x10, context
  li   x11, 64
  jal  x1, sha3_init
  la   x10, context
  li   x11, -1120
  add  x11, fp, x11
  li   x12, 64
  jal  x1, sha3_update
  la   x10, context
  lw   x11, -20(fp)
  jal  x1, sha3_final

  /*** indcpa_enc ***/
  li  x10, -1120
  add x10, fp, x10 
  lw  x12, -20(fp)
  add x12, x12, 32
  jal x1, indcpa_enc_plain

  /* Free space on stack */
  addi sp, fp, 0

  ret

/*
 * Name:        indcpa_dec_plain
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *m: pointer to output decrypted message
 *                            (of length 32)
 *              - const uint8_t *c: pointer to input ciphertext
 *                                  (of length 1088)
 *              - const uint8_t *sk: pointer to input secret key
 *                                   (of length 1152) 
 *
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): dmem pointer to input ciphertext 
 * @param[in]  x11 (x11): dmem pointer to input packed sk
 * @param[out] x13 (x13): dmem pointer to output message
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */

indcpa_dec_plain:

  /* Store parameters to stack */
  sw x13, -32(fp)
  
  /*** unpack_ciphertext ***/
  li  x12, -3616
  add x12, fp, x12 
  la  x13, const_8
  la  x14, modulus
  la  x15, const_0x0fff
  jal x1, unpack_ciphertext

  /*** unpack_sk ***/
  jal x1, unpack_sk

  /*** NTT ***/
  li  x10, -3616
  add x10, fp, x10 
  add x12, x0, x10 
  .rept 3 
    la  x11, twiddles_ntt_base
    jal x1, ntt_base_kyber
  .endr 

  /*** Vector vector multiplication ***/
  addi x29, x10, -1536
  addi x11, x12, 512
  add  x13, x0, x29
  la   x28, twiddles_ntt_base
  jal  x1, basemul_base_kyber
  /** .rept 3-1 **/ 
  .rept 2
    addi x13, x13, -512
    la   x28, twiddles_ntt_base
    jal  x1, basemul_acc_base_kyber 
  .endr 

  /* reduce */
  li  x10, -3616
  add x10, fp, x10
  la  x12, const_1290167
  jal x1, poly_reduce

  /*** INTT ***/
  add x10, x10, -512
  la  x11, twiddles_intt_base
  add x12, x0, x10 
  jal x1, intt_base_kyber

  /*** SUB ***/
  li   x10, -2080
  add  x10, fp, x10 
  addi x11, x12, -512
  addi x12, x12, -512 
  jal  x1, poly_sub_base 

  /*** poly_tomsg ***/
  addi x10, x11, -512 
  la   x11, modulus_over_2
  lw   x12, -32(fp)
  la   x13, const_1290167
  jal  x1, poly_tomsg_base

  ret

/*
 * Name:        crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of 32 bytes)
 *              - const uint8_t *ct: pointer to input cipher text
 *                (an already allocated array of 1088 bytes)
 *              - const uint8_t *sk: pointer to input private key
 *                (an already allocated array of 2400 bytes)
 *
 * Flags: Clobbers FG0, has no meaning beyond the scope of this subroutine.
 *
 * @param[in]  x10 (x10): dmem pointer to input ct
 * @param[in]  x11 (x11): dmem pointer to input sk 
 * @param[out] x12 (x12): dmem pointer to output key_a
 *
 * clobbered registers: x10-x14, x5-x30, w8, w16
 */
.globl crypto_kem_dec
crypto_kem_dec:

  /* Set frame pointer */
  addi fp, sp, 0 

    li  x5, -4320

  add  sp, sp, x5

  /* Save parameters to stack */ 
  sw   x10, -20(fp)
  sw   x11, -16(fp) 
  addi x5, x11, 1152 
  sw   x5, -24(fp)
  addi x5, x5, 1184
  sw   x5, -12(fp)
  sw   x12, -8(fp)

  /*** indcpa_dec ***/ 
  li  x13, -4320
  add x13, fp, x13 
  jal x1, indcpa_dec_plain

  /*** Copy hash_h(pk) to buf+32 ***/
  li     x4, 0
  lw     x10, -12(fp)
  li     x13, -4320
  add    x13, fp, x13 
  addi   x13, x13, 32
  bn.lid x4, 0(x10)
  bn.sid x4, 0(x13++)

  /*** hash_g(buf) ***/
  la   x10, context
  li   x11, 64
  jal  x1, sha3_init
  la   x10, context
  li   x11, -4320
  add  x11, fp, x11
  li   x12, 64
  jal  x1, sha3_update
  la   x10, context
  li   x11, -4256
  add  x11, fp, x11 
  jal  x1, sha3_final

  /*** indcpa_enc ***/
  li   x10, -4320
  add  x10, fp, x10
  li   x12, -4256
  add  x12, fp, x12 
  addi x12, x12, 32 
  li   x13, -2656
  add  x13, fp, x13 
  sw   x13, -32(fp)
  jal  x1, indcpa_enc_plain

  /*** shake256(z||c,32) ***/
  la   x10, context
  li   x11, 32
  jal  x1, sha3_init

  la   x10, context
  lw   x11, -12(fp)
  addi x11, x11, 32 
  li   x12, 32
  jal x1, sha3_update

  la   x10, context
  lw   x11, -20(fp)
  li   x12, 1088
  jal  x1, sha3_update

  la   x10, context
  jal  x1, shake_xof

  la   x10, context
  li   x11, -4256
  add  x11, fp, x11
  addi x11, x11, 32
  addi x12, x0, 32
  jal  x1, shake_out
  
  /*** verify: ct == cmp ? ***/
  li      x5, 0
  li      x6, 1
  lw      x10, -20(fp)
  lw      x11, -32(fp)
  li      x7, 1
  bn.subi w2, w31, 1
  LOOPI 34, 8
    beq    x7, x0, _skip_verify
    bn.lid x5, 0(x10++)
    bn.lid x6, 0(x11++)
    bn.cmp w0, w1
    bn.sel w4, w31, w2, FG0.Z
    csrrw  x7, 0x7C0, x0 
    srl x7, x7, 3
_skip_verify:
    nop

  /*** cmov ***/
  li      x10, -4256
  add     x10, fp, x10 
  bn.lid  x5, 0(x10++) /* load true key */
  bn.lid  x6, 0(x10)   /* load false key */
  bn.xor  w3, w0, w1 
  bn.and  w3, w3, w4 
  bn.xor  w0, w0, w3 
  lw      x10, -8(fp) 
  bn.sid  x5, 0(x10) /* return key */

  ret
