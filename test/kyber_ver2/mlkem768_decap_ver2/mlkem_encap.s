/* mlkem_encap.s — exact port of mlkem_ver2_nold, KYBER_K=3. KMAC interface. */

.globl indcpa_enc
indcpa_enc:
  sw x12, -28(fp) /* coins */

  /*** poly_frommsg ***/
  la  x11, modulus_over_2
  li  x12, -2656
  add x12, fp, x12 /* K at fp-2656 */
  jal x1, poly_frommsg

  /*** unpack_pk ***/
  lw  x10, -24(fp) /* pk */
  la  x13, const_0x0fff
  jal x1, unpack_pk

  /*** save seed ***/
  li     x4, 0
  bn.lid x4, 0(x10)   /* x10 = seed ptr (unpack_pk advanced it past pk) */
  bn.sid x4, -96(x8)   /* seed at fp-96 */

  /*** CBD sp ***/
  lw  x10, -28(fp) /* coins */
  add x14, x0, x10  /* save coins ptr */
  li  x11, -4192
  add x11, fp, x11  /* sp at fp-4192 */
  li  x15, -608      /* V/tmp area */
  li  x13, -64       /* nonce */
  li  x12, 0
  LOOPI 3, 5
    add  x6, fp, x15 /* x6 = tmp buffer for SHAKE */
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_1
    add  x10, x0, x14
    addi x12, x12, 1

  bn.wsrr w16, 0x0

  /*** NTT sp ***/
  li  x10, -4192
  add x10, fp, x10
  la  x11, twiddles_ntt
  add x12, x0, x10
  .rept 3
    jal x1, ntt
  .endr

  /*** v = sp * pkpv ***/
  li   x29, -2144
  add  x29, fp, x29 /* pkpv */
  li   x11, -4192
  add  x11, fp, x11 /* sp */
  li   x13, -608
  add  x13, fp, x13 /* v */
  la   x28, twiddles_basemul
  jal  x1, basemul
  .rept 2
    addi x13, x13, -512
    la   x28, twiddles_basemul
    jal  x1, basemul_acc
  .endr

  /*** INTT v ***/
  li  x10, -608
  add x10, fp, x10
  add x12, x0, x10
  la  x11, twiddles_intt
  jal x1, intt

  /*** CBD epp ***/
  lw   x10, -28(fp)
  li   x11, -2144
  add  x11, fp, x11 /* epp */
  addi x12, x0, 6    /* nonce = 2*K */
  sw   x12, -64(fp)
  li   x13, -64
  li   x6, -1120
  add  x6, fp, x6    /* tmp */
  jal  x1, poly_getnoise_eta_2

  /*** v = v + k + epp ***/
  li   x10, -2656
  add  x10, fp, x10 /* k */
  li   x11, -608
  add  x11, fp, x11 /* v */
  add  x12, x0, x11
  jal  x1, poly_add
  addi x11, x11, -512
  addi x12, x12, -512
  jal  x1, poly_add

  /*** AT * sp ***/
  li   x11, -2656
  add  x11, fp, x11 /* AT */
  li   x12, 0
  .rept 3
    addi x10, fp, -96
    jal  x1, poly_gen_matrix
    addi x12, x12, 0x0100

    addi x11, x11, -512
    li   x29, -4192
    add  x29, fp, x29 /* sp */
    add  x13, x11, x0
    la   x28, twiddles_basemul
    jal  x1, basemul
    .rept 2
      addi x10, fp, -96
      jal  x1, poly_gen_matrix
      addi x12, x12, 0x0100

      addi x11, x11, -512
      addi x13, x11, -512
      la   x28, twiddles_basemul
      jal  x1, basemul_acc
      addi x11, x11, -512
    .endr
    addi x12, x12, -767
  .endr

  /*** INTT AT ***/
  li  x10, -2656
  add x10, fp, x10
  la  x11, twiddles_intt
  add x12, x0, x10
  .rept 3
    jal x1, intt
  .endr

  /*** CBD ep ***/
  lw  x10, -28(fp)
  li  x11, -4192
  add x11, fp, x11 /* ep */
  add x14, x0, x10
  li  x15, -1120     /* tmp */
  li  x13, -64
  li  x12, 3
  LOOPI 3, 5
    add  x6, fp, x15
    sw   x12, -64(fp)
    jal  x1, poly_getnoise_eta_2
    add  x10, x0, x14
    addi x12, x12, 1

  /*** b = b + ep ***/
  li  x10, -2656
  add x10, fp, x10 /* b */
  li  x11, -4192
  add x11, fp, x11 /* ep */
  add x12, x0, x10
  .rept 3
    jal x1, poly_add
  .endr

  /*** pack_ciphertext ***/
  li   x10, -2656
  add  x10, fp, x10 /* b */
  li   x11, -608
  add  x11, fp, x11 /* v */
  lw   x12, -32(fp)  /* ct */
  la   x13, const_1290167
  la   x15, modulus_over_2
  jal  x1, pack_ciphertext
  ret


.globl crypto_kem_enc
crypto_kem_enc:
  addi fp, sp, 0
  li   x5, -4192
  add  sp, sp, x5

  sw x11, -32(fp) /* ct */
  sw x12, -20(fp) /* key_b */
  sw x13, -24(fp) /* pk */

  /*** Copy randombytes to buf[0..31] ***/
  li     x4, 0
  bn.lid x4, 0(x10)
  li     x5, -1120
  add    x5, fp, x5  /* buf at fp-1120 */
  bn.sid x4, 0(x5++)
  add    x7, x0, x5  /* x7 = buf+32 */

  /*** hash_h: SHA3-256(pk) → buf+32 ***/
  addi  x10, x0, 0
  jal   x1, kmac_init
  lw    x10, -24(fp)
  addi  x11, x0, 1184
  jal   x1, keccak_send_message
  jal   x1, kmac_process
  add   x10, x0, x7  /* buf+32 */
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_done

  /*** hash_g: SHA3-512(buf[0..63]) → key_b[0..63] ***/
  addi  x10, x0, 1
  jal   x1, kmac_init
  li    x10, -1120
  add   x10, fp, x10 /* buf */
  addi  x11, x0, 64
  jal   x1, keccak_send_message
  jal   x1, kmac_process
  lw    x12, -20(fp) /* key_b */
  add   x10, x0, x12
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_run
  addi  x10, x12, 32
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_done

  /*** indcpa_enc(m, pk, r, ct) ***/
  li    x10, -1120
  add   x10, fp, x10 /* m = buf */
  lw    x11, -24(fp)  /* pk */
  lw    x13, -32(fp)  /* ct */
  lw    x12, -20(fp)  /* key_b */
  addi  x12, x12, 32  /* r = key_b + 32 */
  jal   x1, indcpa_enc

  addi sp, fp, 0
  ret
