/*
 * Test wrapper for p256_ecdh — pure software baseline (ver0_base).
 *
 * Calls p256_shared_key from p256_shared_key.s.
 * Ibex writes d0(64B), d1(64B), x(32B), y(32B) before execution.
 * After execution: dmem[x] = x0 (boolean share), dmem[y] = x1 (boolean share).
 * Ibex XORs x0 ^ x1 to recover the plain x-coordinate (shared secret).
 */

.section .text.start

.globl main
main:

  jal      x1, p256_shared_key

  /* Load the two boolean shares */
  li        x3, 11
  la        x4, x
  bn.lid    x3++, 0(x4)
  la        x4, y
  bn.lid    x3, 0(x4)

  /* Unmask: x = x0 ^ x1 (for testing — Ibex does this in production) */
  bn.xor    w11, w11, w12

  ecall

.data

/* Secret key d in arithmetic shares. */
.globl d0
.balign 32
d0:
  .zero 64

.globl d1
.balign 32
d1:
  .zero 64

/* Curve point x-coordinate (input: point to multiply; output: x0 share) */
.globl x
.balign 32
x:
  .zero 32

/* Curve point y-coordinate (input: point y; output: x1 share) */
.globl y
.balign 32
y:
  .zero 32

/* Public key z-coordinate (unused, reserved) */
.globl z
.balign 32
z:
  .zero 32

/* Affine x-coordinate before A2B (unused in this wrapper) */
.globl x_a
.balign 32
x_a:
  .zero 32
