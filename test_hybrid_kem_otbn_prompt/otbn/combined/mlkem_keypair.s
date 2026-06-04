indcpa_keypair:

  sw  x10, -16(fp)
  sw  x11, -32(fp)
  sw  x12, -24(fp)

  /*** hash_g: SHA3-512 ***/
  /* Initialize SHA3-512 (Mode 1) */
  addi  x10, x0, 1              
  jal   x1, kmac_init

  /* Send seed (32 bytes) */
  lw    x10, -16(fp)            /* Load seed pointer */
  addi  x11, x0, 32             /* Length 32 */
  jal   x1, keccak_send_message

  /* Send 0x03 byte */
  addi  x11, x0, 3
  sw    x11, -128(fp)           /* Store 0x03 in kp_stack frame temporary space */
  addi  x10, fp, -128
  addi  x11, x0, 1              /* Length 1 */
  jal   x1, keccak_send_message

  /* End Absorb, enter Squeeze */
  jal   x1, kmac_process

  /* Squeeze first 32 bytes to fp-128 */
  addi  x10, fp, -128
  jal   x1, kmac_squeeze_32B

  /* Continue squeezing next 32 bytes to fp-96 */
  addi  x10, fp, -96
  jal   x1, kmac_squeeze_32B

  /* Release KMAC hardware */
  jal   x1, kmac_done

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

  bn.wsrr   w16, 0x0 /* w16 = MOD = R | Q */
  bn.shv.8S w22, w16 << 1 /* w22 = 2*R | 2*Q */
  bn.wsrw   0x0, w22 /* MOD = 2*R | 2*Q */
  /*** NTT skpv ***/
  li   x10, -3712
  add  x10, fp, x10
  la   x11, twiddles_ntt
  add  x12, x0, x10
  .rept 3
    jal x1, ntt
  .endr
  bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

  /*** Packing sk ***/
  li   x10, -3712
  add  x10, fp, x10
  lw   x13, -24(fp)
  jal  x1, pack_sk

  bn.wsrw 0x0, w22 /* MOD = 2*R | 2*Q */
  /*** Matrix-vector multiplication ***/
  li   x11, -2176
  add  x11, fp, x11
  li   x12, 0
  .rept 3
    /* Gen 1st mat poly */
    addi x10, fp, -128
    jal  x1, poly_gen_matrix
    addi x12, x12, 1

    /* Mutliply this generated poly with sk */
    addi x11, x11, -512 /* point back to A[0][0] */
    li   x29, -3712
    add  x29, fp, x29 /* point to sk[0] */
    add  x13, x11, x0   /* output at A[0][0] */
    la   x28, twiddles_basemul
    jal  x1, basemul

    .rept 2
      /* Gen next mat poly */
      addi x10, fp, -128
      jal  x1, poly_gen_matrix
      addi x12, x12, 1

      /* Mutliply this generated poly with sk */
      addi x11, x11, -512 /* points back to A[0][1] */
      addi x13, x11, -512 /* points back to A[0][0] for accumulation */
      la   x28, twiddles_basemul
      jal  x1, basemul_acc
      addi x11, x11, -512 /* points back to A[0][1] */
    .endr 
    addi x12, x12, 253 
  .endr 
  bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

  /* After basemul, w16 is still R | Q */
  /*** poly_tomont ***/
  li  x10, -2176
  add x10, fp, x10
  la  x11, const_tomont
  LOOPI 3, 2
    jal x1, poly_tomont
    NOP

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

  /* After cbd, w16 is still R | Q */
  bn.shv.8S w0, w16 << 1 /* w0 = 2*R | 2*Q */
  bn.wsrw   0x0, w0 /* MOD = 2*R | 2*Q */
  /*** NTT e ***/
  li   x10, -3712
  add  x10, fp, x10
  la   x11, twiddles_ntt
  add  x12, x0, x10
  .rept 3
    jal x1, ntt
  .endr
  bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

  /* Polyvec add */
  li   x10, -2176
  add  x10, fp, x10
  li   x11, -3712 
  add  x11, fp, x11 
  add  x12, x0, x10 
  .rept 3
    jal x1, poly_add
  .endr
  
  /*** Packing ***/
  lw   x13, -32(fp)
  li   x10, -2176
  add  x10, fp, x10 
  addi x11, fp, -128
  jal  x1, pack_pk

  ret 


.globl crypto_kem_keypair
crypto_kem_keypair: 

  addi fp, sp, 0 

    li  x5, -3712

  add  sp, sp, x5 

  /*** indcpa_keypair ***/
  jal  x1, indcpa_keypair
  li   x4, 0
  lw   x10, -32(fp)
  lw   x11, -24(fp)
  addi x11, x11, 1152
  LOOPI 37, 2
    bn.lid x4, 0(x10++)
    bn.sid x4, 0(x11++)

  add   x12, x0, x11           # x12 = sk + 2336 (x11 after LOOPI)
  
  /*** hash_h ***/
  /* Initialize SHA3-256 (Mode 0) */
  addi  x10, x0, 0              
  jal   x1, kmac_init

  /* Send pk (1184 bytes) */
  lw    x10, -32(fp)            /* Load pk pointer */
  addi  x11, x0, 1184           /* Length 1184 */
  jal   x1, keccak_send_message

  /* End Absorb, Enter Squeeze */
  jal   x1, kmac_process

  /* Squeeze 32 bytes to sk + 2336 (x12 already saved this value) */
  add   x10, x0, x12            /* x10 = sk + 2336 */
  jal   x1, kmac_squeeze_32B

  /* Release KMAC hardware */
  jal   x1, kmac_done


  /*** Random bytes ***/
  lw      x10, -16(fp)
  addi    x10, x10, 32 
  li      x5, 8
  bn.lid  x5, 0(x10)

  /* x12 = sk + 2368 (sk+2336 + 32) */
  addi  x12, x12, 32         # x12 = sk + 2368
  bn.sid  x5, 0(x12++)       # 存储 z

  /* Free space on kp_stack */
  addi sp, fp, 0
  ret