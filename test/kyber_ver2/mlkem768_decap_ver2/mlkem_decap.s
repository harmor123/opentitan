/* mlkem_decap.s — exact port of mlkem_ver2_nold, KYBER_K=3. KMAC interface. */

.globl indcpa_dec
indcpa_dec:
  sw x13, -32(fp) /* save m ptr */

  /*** unpack_ciphertext ***/
  li  x12, -3616
  add x12, fp, x12 /* B */
  la  x13, const_8
  la  x14, modulus
  la  x15, const_0x0fff
  jal x1, unpack_ciphertext

  /*** unpack_sk ***/
  jal x1, unpack_sk

  bn.wsrr w16, 0x0

  /*** NTT B ***/
  li  x10, -3616
  add x10, fp, x10
  la  x11, twiddles_ntt
  add x12, x0, x10
  .rept 3
    jal x1, ntt
  .endr

  /*** B * skpv ***/
  addi x29, x10, -1536
  addi x11, x12, 512
  add  x13, x0, x29
  la   x28, twiddles_basemul
  jal  x1, basemul
  .rept 2
    addi x13, x13, -512
    la   x28, twiddles_basemul
    jal  x1, basemul_acc
  .endr

  /*** INTT ***/
  add  x10, x10, -1536
  la   x11, twiddles_intt
  add  x12, x0, x10
  jal  x1, intt

  /*** SUB: V - INTT_result ***/
  li   x10, -2080
  add  x10, fp, x10
  addi x11, x12, -512
  addi x12, x12, -512
  jal  x1, poly_sub

  /*** poly_tomsg ***/
  addi x10, x11, -512
  la   x11, modulus_over_2
  lw   x12, -32(fp)
  la   x13, const_1290167
  jal  x1, poly_tomsg

  ret


.globl crypto_kem_dec
crypto_kem_dec:
  addi fp, sp, 0
  li   x5, -4320
  add  sp, sp, x5

  sw   x10, -20(fp) /* ct */
  sw   x11, -16(fp) /* sk */
  addi x5, x11, 1152
  sw   x5, -24(fp)  /* pk = sk+1152 */
  addi x5, x5, 1184
  sw   x5, -12(fp)  /* h = pk+1184 */
  sw   x12, -8(fp)  /* key_a */

  /*** indcpa_dec ***/
  li   x13, -4320
  add  x13, fp, x13 /* buf */
  jal  x1, indcpa_dec

  /*** Copy H(pk) to buf+32 ***/
  li     x4, 0
  lw     x10, -12(fp)
  li     x13, -4288
  add    x13, fp, x13 /* buf+32 */
  bn.lid x4, 0(x10)
  bn.sid x4, 0(x13++)

  /*** hash_g: SHA3-512(buf,64) → kr ***/
  addi  x10, x0, 1
  jal   x1, kmac_init
  li    x10, -4320
  add   x10, fp, x10
  addi  x11, x0, 64
  jal   x1, keccak_send_message
  jal   x1, kmac_process
  li    x12, -4256
  add   x12, fp, x12 /* kr */
  add   x10, x0, x12
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_run
  addi  x10, x12, 32
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_done

  /*** indcpa_enc ***/
  li    x10, -4320
  add   x10, fp, x10  /* m = buf */
  lw    x11, -24(fp)   /* pk */
  li    x13, -2656
  add   x13, fp, x13   /* cmp */
  sw    x13, -32(fp)
  li    x12, -4256
  add   x12, fp, x12
  addi  x12, x12, 32   /* r = kr+32 */
  jal   x1, indcpa_enc

  /*** shake256: SHAKE-256(z||ct) → kr+32 ***/
  addi  x10, x0, 3
  jal   x1, kmac_init
  lw    x10, -12(fp)
  addi  x10, x10, 32   /* z = h+32 */
  addi  x11, x0, 32
  jal   x1, keccak_send_message
  lw    x10, -20(fp)   /* ct */
  addi  x11, x0, 1088
  jal   x1, keccak_send_message
  jal   x1, kmac_process
  li    x12, -4256
  add   x12, fp, x12
  addi  x12, x12, 32
  add   x10, x0, x12
  jal   x1, kmac_squeeze_32B
  jal   x1, kmac_done

  /*** verify: ct == cmp ? ***/
  li      x5, 0
  li      x6, 1
  lw      x10, -20(fp) /* ct */
  lw      x11, -32(fp) /* cmp */
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
  add     x10, fp, x10 /* kr */
  bn.lid  x5, 0(x10++)
  bn.lid  x6, 0(x10)
  bn.xor  w3, w0, w1
  bn.and  w3, w3, w4
  bn.xor  w0, w0, w3
  lw      x10, -8(fp) /* key_a */
  bn.sid  x5, 0(x10)

  addi sp, fp, 0
  ret
