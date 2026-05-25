/*
 * Binary wrapper for HKDF-SHA3-256 — pure software baseline (ver0_base).
 *
 * Defines all DMEM labels required by hmac_sha3.s and hkdf_sha3_256.s.
 * Calls hkdf_extract then hkdf_expand.
 * Ibex writes input_salt / ikm_prebuilt / input_lengths before execution,
 * and reads output_okm after execution.
 */

.section .text.start

.globl main
main:
    la      x2, stack_end
    addi    x2, x2, -64
    jal     x1, hkdf_extract
    jal     x1, hkdf_expand
    ecall

.data

/* ---- Stack ---- */
.balign 32
.globl stack
stack:
    .zero 512
stack_end:

/* ---- HKDF public DMEM labels (Ibex writes/reads these) ---- */

.balign 32
.globl input_salt
input_salt:
    .zero 32

.balign 32
.globl ikm_prebuilt
ikm_prebuilt:
    .zero 384

.balign 32
.globl input_lengths
input_lengths:
    .zero 32

.balign 32
.globl output_okm
output_okm:
    .zero 256

/* ---- HMAC work buffers (required by hmac_sha3.s) ---- */

.balign 32
.globl hmac_ipad
hmac_ipad:
    .zero 160

.balign 32
.globl hmac_opad
hmac_opad:
    .zero 160

.balign 32
.globl hmac_inner
hmac_inner:
    .zero 32

.balign 32
.globl hmac_key_hashed
hmac_key_hashed:
    .zero 32

/* ---- SHA-3 context (required by sha3_shake.s) ---- */

.balign 32
.globl context
context:
    .zero 212

/* ---- Keccak-f round constants ---- */

.globl rc
.balign 32
rc:
    .balign 32
    .dword 0x0000000000000001
    .balign 32
    .dword 0x0000000000008082
    .balign 32
    .dword 0x800000000000808a
    .balign 32
    .dword 0x8000000080008000
    .balign 32
    .dword 0x000000000000808b
    .balign 32
    .dword 0x0000000080000001
    .balign 32
    .dword 0x8000000080008081
    .balign 32
    .dword 0x8000000000008009
    .balign 32
    .dword 0x000000000000008a
    .balign 32
    .dword 0x0000000000000088
    .balign 32
    .dword 0x0000000080008009
    .balign 32
    .dword 0x000000008000000a
    .balign 32
    .dword 0x000000008000808b
    .balign 32
    .dword 0x800000000000008b
    .balign 32
    .dword 0x8000000000008089
    .balign 32
    .dword 0x8000000000008003
    .balign 32
    .dword 0x8000000000008002
    .balign 32
    .dword 0x8000000000000080
    .balign 32
    .dword 0x000000000000800a
    .balign 32
    .dword 0x800000008000000a
    .balign 32
    .dword 0x8000000080008081
    .balign 32
    .dword 0x8000000000008080
    .balign 32
    .dword 0x0000000080000001
    .balign 32
    .dword 0x8000000080008008

/* ---- HMAC constants (required by hmac_sha3.s) ---- */

.balign 32
.globl const_0x36
const_0x36:
    .rept 40
    .word 0x36363636
    .endr

.balign 32
.globl const_0x5c
const_0x5c:
    .rept 40
    .word 0x5c5c5c5c
    .endr

/* ---- HKDF internal buffers (required by hkdf_sha3_256.s) ---- */

.balign 32
.globl ikm_buf
ikm_buf:
    .zero 1024

.balign 32
.globl t_buf
t_buf:
    .zero 32
