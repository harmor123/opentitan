/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/* Public interface. */
.globl p256_shared_key

/* Exposed only for testing or SCA purposes. */
.globl mai_arithmetic_to_boolean_mod

.text

/**
 * Externally callable wrapper for P-256 scalar point multiplication.
 *
 * Returns x0, x1 such that x0 ^ x1 = x-coordinate of (d * P).
 *
 * This routine is specialized for ECDH shared key generation.
 * The A2B conversion is offloaded to MAI hardware.
 *
 * This routine assumes that the scalar d is provided in two arithmetic shares,
 * d0 and d1, where d = (d0 + d1) mod n.
 *
 * This routine runs in constant time.
 *
 * @param[in]      dmem[d0]:  first share of scalar d (320 bits)
 * @param[in]      dmem[d1]:  second share of scalar d (320 bits)
 * @param[in]      dmem[x]:   affine x-coordinate in dmem
 * @param[in]      dmem[y]:   affine y-coordinate in dmem
 * @param[out]     dmem[x]:   x0, first boolean share of x-coordinate
 * @param[out]     dmem[y]:   x1, second boolean share of x-coordinate
 *
 * Flags: When leaving this subroutine, the M, L and Z flags of FG0 depend on
 *        the computed affine y-coordinate.
 *
 * clobbered registers: x2, x3, x4, x5, x6, x10-x16, x21, x22, w0 to w25, w31
 * clobbered flag groups: FG0
 */
p256_shared_key:
  /* Init all-zero register. */
  bn.xor    w31, w31, w31

  /* Load first share of secret key d from dmem.
       w0,w1 = dmem[d0] */
  la        x16, d0
  li        x2, 0
  bn.lid    x2, 0(x16++)
  li        x2, 1
  bn.lid    x2, 0(x16)

  /* Load second share of secret key d from dmem.
       w2,w3 = dmem[d1] */
  la        x16, d1
  li        x2, 2
  bn.lid    x2, 0(x16++)
  li        x2, 3
  bn.lid    x2, 0(x16)

  /* Reblind the secret key before running the scalar multiplication. */
  jal       x1, p256_masked_scalar_reblind

  /* Call internal scalar multiplication routine.
     Returns point in projective coordinates.
     R = (x, y, z) = (w8, w9, w10) <= d*P = ([w0,w1] + [w2,w3])*P */
  la        x21, x
  la        x22, y
  jal       x1, scalar_mult_int

  /* store result (projective coordinates) in dmem
     dmem[x] <= x = w8
     dmem[y] <= y = w9
     dmem[z] <= z = w10 */
  li        x2, 8
  la        x21, x
  bn.sid    x2++, 0(x21)
  la        x22, y
  bn.sid    x2++, 0(x22)
  la        x21, z
  bn.sid    x2, 0(x21)

  /* Compute both sides of the Weierstrauss equation.
       w18 <= (x^3 + ax + b) mod p
       w19 <= (zy^2) mod p */
  jal      x1, p256_isoncurve_proj

  /* Compare the two sides of the equation to check if the result
     is a valid point as an FI countermeasure.
     FG0.Z <= (zy^2) mod p == (x^3 + axz^2 + bz^3) mod p */
  bn.cmp   w18, w19
  jal      x1, trigger_fault_if_fg0_z

  /* ---- Arithmetic masking + MAI A2B ----
     1. Generate random projective mask m
     2. Subtract from x: A_proj = (x - m) mod p
     3. Convert to affine: x_a = A_proj / z, get z^-1
     4. Convert mask to affine: m_aff = m * z^-1 mod p
     5. Call MAI A2B to convert (x_a, m_aff) to boolean shares
     6. Store boolean shares to dmem[x], dmem[y]
  */

  /* Fetch a fresh random number as mask.
       w2 <= URND() */
  bn.wsrr   w2, URND

  /* Subtract random mask from x coordinate of projective point.
       w8 = (w8 - w2) mod p */
  bn.subm    w8, w8, w2

  /* Convert masked result back to affine coordinates.
       R = (x_a, y_a) = (w11, w12),  w14 = z^-1 */
  jal       x1, proj_to_affine

  /* Multiply mask with z^-1 to convert it to affine space.
       w24 = m_x, w25 = z^-1 (still in w14 from proj_to_affine) */
  bn.mov    w25, w14
  bn.mov    w24, w2

  /* w19 = m_x * z^-1 mod p = affine mask */
  jal       x1, mul_modp

  /* ---- Offload A2B to MAI hardware ----
   * Store A = w11 (masked affine x) and r = w19 (affine mask) to DMEM.
   * MAI A2B computes: res_s0 XOR res_s1 = (A + r) mod p = x
   */
  la        x10, mai_A_buf
  li        x3, 11
  bn.sid    x3, 0(x10)

  la        x10, mai_r_buf
  li        x3, 19
  bn.sid    x3, 0(x10)

  /* Call MAI A2B: in0 = (A, r), in1 = (0, 0) */
  la        x11, mai_A_buf
  la        x12, zero_buf
  la        x13, mai_r_buf
  la        x14, zero_buf
  la        x15, mai_out0
  la        x16, mai_out1

  jal       x1, mai_p256_a2b

  /* Load boolean shares from DMEM and store to output */
  li        x4, 0
  bn.lid    x4, 0(x15)
  li        x4, 1
  bn.lid    x4, 0(x16)

  la        x21, x
  li        x3, 0
  bn.sid    x3, 0(x21)
  la        x22, y
  li        x3, 1
  bn.sid    x3, 0(x22)

  ret


/**
 * MAI-accelerated arithmetic-to-boolean conversion mod p.
 *
 * Thin wrapper: stores arithmetic shares (A, r) to DMEM, calls MAI A2B,
 * reads back boolean shares.
 *
 * @param[in]  w31: all-zero
 * @param[in]  w19: mask r
 * @param[in]  w11: arithmetically masked value A, such that x = (A + r) mod p
 * @param[out] w20: boolean share 0 (x = w20 ^ w19_new, where w19_new is fresh)
 *
 * clobbered registers: x3-x6, x10-x16, w0, w1
 * clobbered flag groups: FG0
 */
mai_arithmetic_to_boolean_mod:
  /* Store A and r to DMEM */
  la        x10, mai_A_buf
  li        x3, 11
  bn.sid    x3, 0(x10)

  la        x10, mai_r_buf
  li        x3, 19
  bn.sid    x3, 0(x10)

  la        x11, mai_A_buf
  la        x12, zero_buf
  la        x13, mai_r_buf
  la        x14, zero_buf
  la        x15, mai_out0
  la        x16, mai_out1

  jal       x1, mai_p256_a2b

  /* Load boolean share 0 into w20 (output convention) */
  li        x4, 0
  bn.lid    x4, 0(x15)

  /* The caller expects w20 to hold the first boolean share.
     w19 (the second share) is also available in mai_out1 if needed. */
  bn.mov    w20, w0

  ret


/* ================================================================
 * BSS buffers for MAI A2B
 * ================================================================ */
.section .bss

.balign 32
zero_buf:
  .zero 32

.balign 32
mai_A_buf:
  .zero 32

.balign 32
mai_r_buf:
  .zero 32

.balign 32
mai_out0:
  .zero 32

.balign 32
mai_out1:
  .zero 32
