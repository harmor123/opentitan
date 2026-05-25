/*
 * Test wrapper for hkdf_sha3_256 — pure software baseline (ver0_base).
 *
 * DMEM-based interface. Calls hkdf_extract then hkdf_expand.
 * Test vector: salt, ss_e, ss_m, ctx, sid, role as hardcoded values.
 * Expected OKM (64B) verified against Python reference implementation.
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

/* ---- HKDF salt (32B) ---- */

.balign 32
.globl input_salt
input_salt:
    .word 0x03020100
    .word 0x07060504
    .word 0x0b0a0908
    .word 0x0f0e0d0c
    .word 0x13121110
    .word 0x17161514
    .word 0x1b1a1918
    .word 0x1f1e1d1c

/* ---- Pre-built IKM (fixed header 68B + ctx + sid + role) ---- */

.balign 32
.globl ikm_prebuilt
ikm_prebuilt:
    .word 0x176b2000    /* len_cls(0020) || ss_e[0:2](6b17) */
    .word 0x2ce1f2d1    /* ss_e[2:6] */
    .word 0xbcf84742    /* ss_e[6:10] */
    .word 0xa463e5e6    /* ss_e[10:14] */
    .word 0x0377f240    /* ss_e[14:18] */
    .word 0xeb2d817d    /* ss_e[18:22] */
    .word 0xa1f4a033    /* ss_e[22:26] */
    .word 0x98d84539    /* ss_e[26:30] */
    .word 0x200096c2    /* ss_e[30:32](c296) || len_pqc(0020) */
    .word 0xd4c3b2a1    /* ss_m[0:4] */
    .word 0x1807f6e5    /* ss_m[4:8] */
    .word 0x3a2908f9    /* ss_m[8:12] */
    .word 0x5c4b6d7e    /* ss_m[12:16] */
    .word 0x44332211    /* ss_m[16:20] */
    .word 0x88776655    /* ss_m[20:24] */
    .word 0xccbbaa99    /* ss_m[24:28] */
    .word 0x00ffeedd    /* ss_m[28:32] */
    .word 0x74736574    /* ctx "test" */
    .word 0x7874632d    /* ctx "-ctx" */
    .word 0x73736573    /* sid "sess" */
    .word 0x2d6e6f69    /* sid "ion-" */
    .word 0x69313030    /* sid "001i" (overlap with role) */
    .word 0x6974696e    /* role "niti" */
    .word 0x726f7461    /* role "ator" */

.balign 32
.globl input_lengths
input_lengths:
    .word 8     /* ctx_len  at +0 */
    .word 11    /* sid_len  at +4 */
    .word 9     /* role_len at +8 */
    .word 64    /* okm_len  at +12 */
    .zero 16    /* pad to 32B */

/* ---- HMAC work buffers ---- */

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

/* ---- Output ---- */

.balign 32
.globl output_okm
output_okm:
    .zero 256

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

/* SHA-3 context (required by sha3_shake.s) */
.balign 32
.globl context
context:
    .zero 212

/* Keccak-f round constants */
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
