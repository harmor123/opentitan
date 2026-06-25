/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

.globl p256_isoncurve_proj

.globl setup_modp


/**
 * Set up for coordinate field operations modulo the prime p.
 *
 * Loads the constants required by `mul_modp` and other coordinate-arithmetic
 * routines.
 *
 * Flags: Flags have no meaning beyond the scope of this subroutine.
 *
 * @param[in]  w31: all-zero
 * @param[out] MOD: p, modulus of P-256 underlying finite field
 * @param[out] w28: r256, constant, 2^256 mod p = 2^256 - p
 * @param[out] w29: r448, constant, 2^448 mod p
 *
 * clobbered registers: w28, w29
 * clobbered flag groups: FG0
 */
setup_modp:
  /* Load the modulus p from DMEM and store it in MOD.
     MOD <= w29 <= p = dmem[p256_p] */
  li        x2, 29
  la        x3, p256_p
  bn.lid    x2, 0(x3)
  bn.wsrw   MOD, w29

  /* Compute the constant r256 for reduction modulo p.
       w28 <= 2^256 - p = r256 */
  bn.sub   w28, w31, w29

  /* Load the constant r448 for reduction modulo p.
     w29 <= dmem[p256_r448] = r448 */
  li        x2, 29
  la        x3, p256_r448
  bn.lid    x2, 0(x3)
  ret

/**
 * Checks if a projective point is a valid curve point on curve P-256 (secp256r1)
 *
 * Returns rhs = x^3 + axz^2 + bz^3  mod p
 *     and lhs = zy^2  mod p
 *         with x,y,z being the projective coordinates of the curve point
 *              a, b and p being the domain parameters of P-256
 *
 * This routine checks if a point with given projective x- and y-coordinate is
 * a valid curve point on P-256.
 * The routine checks whether the coordinates are a solution of the modified
 * Weierstrass equation zy^2 = x^3 + axz^2 + bz^3  mod p.
 * The routine makes use of the property that the domain parameter 'a' can be
 * written as a=-3 for the P-256 curve, hence the routine is limited to P-256.
 * The routine does not return a boolean result but computes the left side
 * and the right sight of the Weierstrass equation and leaves the final
 * comparison to the caller.
 * The routine runs in constant time.
 *
 * Flags: Flags have no meaning beyond the scope of this subroutine.
 *
 * @param[in]      w31: all-zero
 * @param[in]  dmem[x]: projective x-coordinate of input point
 * @param[in]  dmem[y]: projective y-coordinate of input point
 * @param[in]  dmem[z]: projective y-coordinate of input point
 * @param[out]     w18: lhs, left side of equation = (x^3 + ax + b) mod p
 * @param[out]     w19: rhs, right side of equation = y^2 mod p
 *
 * clobbered registers: x2, x3, x19, x20, w0, w18 to w29
 * clobbered flag groups: FG0
 */
p256_isoncurve_proj:
  /* Set up for coordinate arithmetic.
       MOD <= p
       w28 <= r256
       w29 <= r448 */
  jal       x1, setup_modp

  /* load domain parameter b from dmem
     w27 <= b = dmem[p256_b] */
  li        x2, 27
  la        x3, p256_b
  bn.lid    x2, 0(x3)

  /* load projective z-coordinate of curve point from dmem
     w26 <= dmem[z] */
  la        x3, z
  li        x2, 26
  bn.lid    x2, 0(x3)

  /* w19 <= z^2 = w26*w26 */
  bn.modp256 w19, w26, w26

  /* for curve P-256, 'a' can be written as a = -3, therefore we subtract
     z^2 three times from 0.
     w18 = az^2 <= -3z^2  mod p */
  bn.subm   w18, w31, w19
  bn.subm   w18, w18, w19
  bn.subm   w18, w18, w19

  /* w19 <= bz^2 = w27*w19 */
  bn.modp256 w19, w27, w19

  /* w19 <= bz^3 = w26*w19 */
  bn.modp256 w19, w26, w19

  /* Move the modified b back into w27. */
  bn.mov    w27, w19

  /* load projective x-coordinate of curve point from dmem
     w26 <= dmem[x] */
  la        x3, x
  li        x2, 26
  bn.lid    x2, 0(x3)

  /* w19 <= axz^2 = w26*w18 */
  bn.modp256 w19, w26, w18

  /* Move the modified axz^2 into w18. */
  bn.mov    w18, w19

  /* w19 <= x^2 = w26*w26 */
  bn.modp256 w19, w26, w26

  /* w19 = x^3 <= w19 * w26 */
  bn.modp256 w19, w19, w26

  /* w18 <= x^3 + axz^2 mod p = w19 + w18 mod p */
  bn.addm   w18, w19, w18

  /* w18 <= x^3 + axz^2 + bz^3 mod p = w19 + w27 mod p = lhs */
  bn.addm   w18, w18, w27

  /* Load projective y-coordinate of curve point from dmem
     w24 <= dmem[y] */
  la        x3, y
  li        x2, 24
  bn.lid    x2, 0(x3)

  /* w19 <= w24*w24 mod p = y^2 mod p */
  bn.modp256 w19, w24, w24

  /* load projective z-coordinate of curve point from dmem
     w24 <= dmem[z] (overwrites w24) */
  la        x3, z
  li        x2, 24
  bn.lid    x2, 0(x3)

  /* w19 <= w24*w19 mod p = zy^2 mod p */
  bn.modp256 w19, w24, w19

  ret

.section .data

/* P-256 domain parameter b */
.globl p256_b
.balign 32
p256_b:
  .word 0x27d2604b
  .word 0x3bce3c3e
  .word 0xcc53b0f6
  .word 0x651d06b0
  .word 0x769886bc
  .word 0xb3ebbd55
  .word 0xaa3a93e7
  .word 0x5ac635d8

/* P-256 domain parameter p (modulus) */
.globl p256_p
.balign 32
p256_p:
  .word 0xffffffff
  .word 0xffffffff
  .word 0xffffffff
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000001
  .word 0xffffffff

/* Constant ((2^448) mod p) for reduction modulo p. */
.globl p256_r448
.balign 32
p256_r448:
  .word 0xffffffff
  .word 0xfffffffe
  .word 0xfffffffe
  .word 0xffffffff
  .word 0x00000000
  .word 0x00000002
  .word 0x00000003
  .word 0x00000000
