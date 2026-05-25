/**
 * @file
 * @brief Hybrid KEM (ML-KEM-768 + P-256 ECDH) pure-software baseline (ver0_base).
 *
 * Implements hybrid key generation, encapsulation, and decapsulation
 * using OTBN as the cryptographic coprocessor. All cryptographic
 * operations (ML-KEM-768, P-256 ECDH, HKDF-SHA3-256) execute on OTBN
 * using pure software Keccak-f (no KMAC hardware, no BN vector extensions).
 * Ibex handles scheduling, data movement, and result verification.
 *
 * This is the ver0_base performance baseline for comparison with
 * hardware-accelerated versions (KMAC / BNMULV macro extensions).
 *
 * Key sizes:
 *   PK_Hyb = pk_m(1184B) || pk_e(64B)  = 1248 bytes
 *   SK_Hyb = sk_m(2400B) || sk_e(32B)  = 2432 bytes
 *   CT_Hyb = ek(64B) || ct_m(1088B)    = 1152 bytes
 */

#ifndef HYBRID_KEM_H_
#define HYBRID_KEM_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Size constants
 * ================================================================ */

#define HYBRID_KEM_PK_M_BYTES   1184
#define HYBRID_KEM_SK_M_BYTES   2400
#define HYBRID_KEM_CT_M_BYTES   1088
#define HYBRID_KEM_SS_M_BYTES   32
#define HYBRID_KEM_PK_E_BYTES   64
#define HYBRID_KEM_SK_E_BYTES   32
#define HYBRID_KEM_SS_E_BYTES   32

#define HYBRID_KEM_PK_HYB_BYTES (HYBRID_KEM_PK_M_BYTES + HYBRID_KEM_PK_E_BYTES)
#define HYBRID_KEM_SK_HYB_BYTES (HYBRID_KEM_SK_M_BYTES + HYBRID_KEM_SK_E_BYTES)
#define HYBRID_KEM_CT_HYB_BYTES (HYBRID_KEM_PK_E_BYTES + HYBRID_KEM_CT_M_BYTES)

#define HYBRID_KEM_SALT_BYTES   32
#define HYBRID_KEM_OKM_MAX      256

#define HYBRID_KEM_CTX_MAX      128
#define HYBRID_KEM_SID_MAX      128
#define HYBRID_KEM_ROLE_MAX     16

#define HYBRID_KEM_ROLE_INITIATOR  "initiator"
#define HYBRID_KEM_ROLE_RESPONDER  "responder"
#define HYBRID_KEM_ROLE_INITIATOR_LEN  10
#define HYBRID_KEM_ROLE_RESPONDER_LEN  10

/* ================================================================
 * Instruction count thresholds (set to 0 = skip until calibrated)
 * ================================================================ */
#define HYBRID_KEM_INSNS_MLKEM_KEYPAIR  0
#define HYBRID_KEM_INSNS_MLKEM_ENCAP    0
#define HYBRID_KEM_INSNS_MLKEM_DECAP    0
#define HYBRID_KEM_INSNS_P256_ECDH      0
#define HYBRID_KEM_INSNS_HKDF           0

/* ================================================================
 * Public API
 * ================================================================ */

/**
 * Initialize the hybrid KEM subsystem.
 *
 * Test mode: no-op. Production mode: initializes hardware entropy source.
 * Must be called once before any hybrid_* function.
 *
 * @return OK_STATUS() or entropy source initialization error.
 */
status_t hybrid_kem_init(void);

/**
 * Hybrid key generation (Bob, offline).
 *
 * OTBN sequence: mlkem768_keypair -> wipe -> p256_ecdh(keygen) -> wipe.
 *
 * @param otbn         OTBN DIF handle.
 * @param[out] pk_hyb  Hybrid public key (1248B = pk_m || pk_e).
 * @param[out] sk_hyb  Hybrid secret key (2432B = sk_m || sk_e).
 * @return OTBN status / hardware result.
 */
status_t hybrid_keygen(dif_otbn_t *otbn,
                       uint8_t *pk_hyb,
                       uint8_t *sk_hyb);

/**
 * Hybrid encapsulation (Alice).
 *
 * @param otbn         OTBN DIF handle.
 * @param pk_hyb       Bob's hybrid public key (1248B).
 * @param salt         HKDF salt (32B, NULL = all-zero).
 * @param ctx,ctx_len  Context binding string.
 * @param sid,sid_len  Session ID (replay defense).
 * @param[out] ct_hyb  Hybrid ciphertext (1152B = ek || ct_m).
 * @param[out] okm     Output key material.
 * @param okm_len      Desired OKM length (max HYBRID_KEM_OKM_MAX).
 * @return OTBN status.
 */
status_t hybrid_encaps(dif_otbn_t *otbn,
                       const uint8_t *pk_hyb,
                       const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *ct_hyb,
                       uint8_t *okm, size_t okm_len);

/**
 * Hybrid decapsulation (Bob). Constant-time.
 *
 * @param otbn         OTBN DIF handle.
 * @param sk_hyb       Bob's hybrid secret key (2432B).
 * @param ct_hyb       Received hybrid ciphertext (1152B).
 * @param salt         HKDF salt (32B, NULL = all-zero).
 * @param ctx,ctx_len  Context binding string.
 * @param sid,sid_len  Session ID.
 * @param[out] okm     Output key material.
 * @param okm_len      Desired OKM length.
 * @return OTBN status (always OK even on implicit reject).
 */
status_t hybrid_decaps(dif_otbn_t *otbn,
                       const uint8_t *sk_hyb,
                       const uint8_t *ct_hyb,
                       const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // HYBRID_KEM_H_
