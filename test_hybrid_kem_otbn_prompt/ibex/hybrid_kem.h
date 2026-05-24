/**
 * @file
 * @brief Hybrid KEM (ML-KEM-768 + P-256 ECDH) key agreement system.
 *
 * Implements hybrid key generation, encapsulation, and decapsulation
 * using OTBN as the cryptographic coprocessor. All cryptographic
 * operations (ML-KEM-768, P-256 ECDH, HKDF-SHA3-256) execute on OTBN.
 * Ibex handles scheduling, data movement, and result verification.
 *
 * ================================================================
 * 运行模式 (通过 BUILD copts 切换)
 * ================================================================
 *
 *   BUILD 中控制:
 *     copts = ["-DHYBRID_KEM_TEST_MODE"],   // 功能测试模式
 *     copts = [],                            // 生产安全模式
 *
 *   定义 HYBRID_KEM_TEST_MODE → 功能测试模式:
 *     - 使用硬编码测试向量 (NIST KAT / RFC 5869)
 *     - P-256 d1 算术份额 = 0 (简化验证)
 *     - LOAD_CHECKSUM + 指令计数验证启用 (需实测阈值)
 *     - 确定性输出, 可与 Python 参考实现比对
 *
 *   不定义 HYBRID_KEM_TEST_MODE → 生产安全模式:
 *     - 从硬件 TRNG (dif_entropy_src) 获取全部随机数
 *     - P-256 标量拆分为真算术份额 d = d0 + d1 mod n
 *     - 每轮 ML-KEM coins 刷新
 *     - LOAD_CHECKSUM + 指令计数验证启用
 *
 *   禁止在此头文件中手动 #define HYBRID_KEM_TEST_MODE.
 *   所有模式切换必须通过 BUILD copts 统一管理.
 *
 * Key sizes:
 *   PK_Hyb = pk_m(1184B) || pk_e(64B)  = 1248 bytes
 *   SK_Hyb = sk_m(2400B) || sk_e(32B)  = 2432 bytes
 *   CT_Hyb = ek(64B) || ct_m(1088B)    = 1152 bytes
 *
 * DMEM addressing: all OTBN DMEM addresses are obtained through the
 * build pipeline (otbn_build.py objcopy symbol prefixing).  C code
 * uses OTBN_DECLARE_SYMBOL_ADDR / OTBN_ADDR_T_INIT exclusively.
 * There are NO hardcoded numeric DMEM offsets in this interface.
 */

#ifndef HYBRID_KEM_H_
#define HYBRID_KEM_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/dif/dif_otbn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 运行模式切换 — 通过 BUILD copts 控制, 禁止在此手动 #define
 * ================================================================
 *
 * 功能测试: copts = ["-DHYBRID_KEM_TEST_MODE"],
 * 生产安全: copts = [],
 */

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
 * 构建时验证 — 从 OTBN ELF 提取的指令计数阈值
 *
 * 这些值必须从 OTBN 仿真器实测获取。设为 0 跳过验证。
 * 生产模式部署前必须填入实际值。
 * ================================================================ */
#define HYBRID_KEM_INSNS_MLKEM_KEYPAIR  0   /* TODO: 实测 */
#define HYBRID_KEM_INSNS_MLKEM_ENCAP    0   /* TODO: 实测 */
#define HYBRID_KEM_INSNS_MLKEM_DECAP    0   /* TODO: 实测 */
#define HYBRID_KEM_INSNS_P256_ECDH      0   /* TODO: 实测 */
#define HYBRID_KEM_INSNS_HKDF           0   /* TODO: 实测 */

/* ================================================================
 * Public API
 * ================================================================ */

/**
 * 初始化混合 KEM 子系统。
 *
 * 生产模式下从硬件熵源初始化；测试模式下为无操作。
 * 必须在调用任何 hybrid_* 函数之前调用一次。
 *
 * @return OK_STATUS() 或熵源初始化错误。
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
 * Hybrid decapsulation (Bob).  Constant-time.
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
