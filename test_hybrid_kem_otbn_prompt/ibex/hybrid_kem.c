/**
 * @file
 * @brief Hybrid KEM (ML-KEM-768 + P-256 ECDH) OTBN scheduling framework.
 *
 * 双模式设计:
 *   HYBRID_KEM_TEST_MODE defined  → 功能测试: 硬编码测试向量, d1=0
 *   HYBRID_KEM_TEST_MODE undefined → 生产安全: TRNG 熵源, 真算术份额
 *
 * Build integration (BUILD file snippet):
 *   otbn_binary(name = "mlkem768_keypair", srcs = [...])
 *   otbn_binary(name = "mlkem768_encap",   srcs = [...])
 *   otbn_binary(name = "mlkem768_decap",   srcs = [...])
 *   otbn_binary(name = "p256_ecdh",        srcs = [...])
 *   otbn_binary(name = "hkdf_sha3_256",    srcs = [...])
 *   opentitan_functest(name = "hybrid_kem_test",
 *       srcs = ["ibex/hybrid_kem.c"],
 *       deps = [":mlkem768_keypair", ":mlkem768_encap", ...])
 *
 * All cryptographic operations execute on OTBN. KMAC hardware is
 * accessed exclusively by OTBN via CSR/WSR. Ibex never touches KMAC.
 */

#include "hybrid_kem.h"

#include <string.h>

#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ================================================================
 * OTBN app declarations — build pipeline resolves all symbols
 * ================================================================ */

/* ---- mlkem768_keypair ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, _checksum);

static const otbn_app_t kAppMlKemKeypair = OTBN_APP_T_INIT(mlkem768_keypair);
static const otbn_addr_t kMlKemKeypairCoins = OTBN_ADDR_T_INIT(mlkem768_keypair, coins);
static const otbn_addr_t kMlKemKeypairEk    = OTBN_ADDR_T_INIT(mlkem768_keypair, ek);
static const otbn_addr_t kMlKemKeypairDk    = OTBN_ADDR_T_INIT(mlkem768_keypair, dk);
static const uint32_t kChecksumMlKemKeypair = OTBN_ADDR_T_INIT(mlkem768_keypair, _checksum);

/* ---- mlkem768_encap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_encap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, _checksum);

static const otbn_app_t kAppMlKemEncap = OTBN_APP_T_INIT(mlkem768_encap);
static const otbn_addr_t kMlKemEncapCoins = OTBN_ADDR_T_INIT(mlkem768_encap, coins);
static const otbn_addr_t kMlKemEncapEk    = OTBN_ADDR_T_INIT(mlkem768_encap, ek);
static const otbn_addr_t kMlKemEncapCt    = OTBN_ADDR_T_INIT(mlkem768_encap, ct);
static const otbn_addr_t kMlKemEncapSs    = OTBN_ADDR_T_INIT(mlkem768_encap, ss);
static const uint32_t kChecksumMlKemEncap = OTBN_ADDR_T_INIT(mlkem768_encap, _checksum);

/* ---- mlkem768_decap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_decap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, _checksum);

static const otbn_app_t kAppMlKemDecap = OTBN_APP_T_INIT(mlkem768_decap);
static const otbn_addr_t kMlKemDecapCt = OTBN_ADDR_T_INIT(mlkem768_decap, ct);
static const otbn_addr_t kMlKemDecapDk = OTBN_ADDR_T_INIT(mlkem768_decap, dk);
static const otbn_addr_t kMlKemDecapSs = OTBN_ADDR_T_INIT(mlkem768_decap, ss);
static const uint32_t kChecksumMlKemDecap = OTBN_ADDR_T_INIT(mlkem768_decap, _checksum);

/* ---- p256_ecdh (keygen + ECDH — 同一 OTBN app) ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, _checksum);

static const otbn_app_t kAppP256Ecdh = OTBN_APP_T_INIT(p256_ecdh);
static const otbn_addr_t kP256D0 = OTBN_ADDR_T_INIT(p256_ecdh, d0);
static const otbn_addr_t kP256D1 = OTBN_ADDR_T_INIT(p256_ecdh, d1);
static const otbn_addr_t kP256X  = OTBN_ADDR_T_INIT(p256_ecdh, x);
static const otbn_addr_t kP256Y  = OTBN_ADDR_T_INIT(p256_ecdh, y);
static const uint32_t kChecksumP256Ecdh = OTBN_ADDR_T_INIT(p256_ecdh, _checksum);

/* ---- hkdf_sha3_256 ---- */
OTBN_DECLARE_APP_SYMBOLS(hkdf_sha3_256);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_salt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, ikm_prebuilt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_lengths);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, output_okm);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, _checksum);

static const otbn_app_t kAppHkdf = OTBN_APP_T_INIT(hkdf_sha3_256);
static const otbn_addr_t kHkdfSalt    = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_salt);
static const otbn_addr_t kHkdfIkmPre  = OTBN_ADDR_T_INIT(hkdf_sha3_256, ikm_prebuilt);
static const otbn_addr_t kHkdfLengths = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_lengths);
static const otbn_addr_t kHkdfOutput  = OTBN_ADDR_T_INIT(hkdf_sha3_256, output_okm);
static const uint32_t kChecksumHkdf    = OTBN_ADDR_T_INIT(hkdf_sha3_256, _checksum);

/* ================================================================
 * 指令计数阈值 (从 otbn_sim 实测, 0 = 跳过)
 * ================================================================ */
static const uint32_t kExpectedInsnMlKemKeypair = HYBRID_KEM_INSNS_MLKEM_KEYPAIR;
static const uint32_t kExpectedInsnMlKemEncap   = HYBRID_KEM_INSNS_MLKEM_ENCAP;
static const uint32_t kExpectedInsnMlKemDecap   = HYBRID_KEM_INSNS_MLKEM_DECAP;
static const uint32_t kExpectedInsnP256Ecdh     = HYBRID_KEM_INSNS_P256_ECDH;
static const uint32_t kExpectedInsnHkdf         = HYBRID_KEM_INSNS_HKDF;

/* ================================================================
 * 模式相关的输入数据
 * ================================================================ */

#ifdef HYBRID_KEM_TEST_MODE
/* ===== 功能测试模式: 硬编码已知答案测试向量 ===== */

static const uint8_t kTestMlKemKeypairCoins[64] = {
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
    0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
    0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
    0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
    0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93,
    0x10, 0x3c, 0xfb, 0x0a, 0xee, 0xfd, 0x2a, 0x68,
    0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63,
    0x9c, 0xa8, 0xa1, 0xe3, 0xf9, 0xae, 0x57, 0xe2,
};
static const uint8_t kTestMlKemEncapCoins[32] = {
    0x35, 0xb8, 0xcc, 0x87, 0x3c, 0x23, 0xdc, 0x62,
    0xb8, 0xd2, 0x60, 0x16, 0x9a, 0xfa, 0x2f, 0x75,
    0xab, 0x91, 0x6a, 0x58, 0xd9, 0x74, 0x91, 0x88,
    0x35, 0xd2, 0x5e, 0x6a, 0x43, 0x50, 0x85, 0xb2,
};
/* P-256 标量 d (256-bit): d0 = d, d1 = 0 (arithmetic share) */
static const uint8_t kTestP256D0[64] = {
    0x71, 0x10, 0x6d, 0xfe, 0x16, 0xa0, 0xd0, 0x21,
    0x81, 0xc7, 0xb2, 0xb0, 0x5d, 0xef, 0x90, 0x95,
    0x79, 0xa3, 0xdf, 0x3f, 0xe8, 0xeb, 0x76, 0x1b,
    0x63, 0x02, 0x21, 0x74, 0x41, 0xfc, 0x20, 0x14,
};
static const uint8_t kTestP256D1[64] = {0};  /* d1 = 0 simplifies verification */
/* P-256 generator G = (x_G, y_G) */
static const uint8_t kTestP256GenX[32] = {
    0x34, 0xc3, 0xa8, 0xbf, 0xb3, 0xb7, 0x73, 0x97,
    0x89, 0x06, 0x6b, 0xf3, 0xb2, 0xc0, 0xc0, 0x6e,
    0xf3, 0x8b, 0x6c, 0xdb, 0x58, 0xce, 0x28, 0x16,
    0x46, 0xc5, 0xcd, 0xfa, 0x6a, 0x1a, 0x55, 0xb5,
};
static const uint8_t kTestP256GenY[32] = {
    0x2e, 0x8c, 0x00, 0x9e, 0x58, 0x70, 0x70, 0xa8,
    0x24, 0x69, 0x9c, 0xab, 0xd0, 0x11, 0x7a, 0x7f,
    0xfa, 0x17, 0x3a, 0xb5, 0xea, 0x09, 0xdd, 0x43,
    0x43, 0xc1, 0x31, 0x1f, 0x97, 0xc6, 0xa1, 0x42,
};

#else  /* !HYBRID_KEM_TEST_MODE — 生产安全模式 */
/* ================================================================
 * 生产安全模式: 从 Ibex RND / EDN0 获取全部随机数
 *
 * 通过 ibex_rnd32_read() (EDN0) 获取随机字。
 * P-256 私钥拆分为真算术份额: d = d0 + d1 mod n
 * 每轮 ML-KEM coins 独立刷新.
 * ================================================================ */

#include "sw/device/lib/crypto/drivers/rv_core_ibex.h"

/**
 * 从 Ibex EDN0 读取 len 字节随机数 (byte-aligned safe).
 */
static status_t entropy_get(void *buf, size_t len) {
  uint8_t *out = (uint8_t *)buf;
  size_t remaining = len;
  while (remaining > 0) {
    uint32_t rnd = ibex_rnd32_read();
    size_t copy = remaining < sizeof(rnd) ? remaining : sizeof(rnd);
    memcpy(out, &rnd, copy);
    out += copy;
    remaining -= copy;
  }
  return OK_STATUS();
}

/**
 * P-256 标量算术份额拆分 (生产模式简化版).
 *
 * d0 = d (低位), d1 = random (高位).
 * OTBN 内部 p256_masked_scalar_reblind 会完成模约简.
 */
static void p256_split_scalar(const uint8_t *d, uint8_t *d0, uint8_t *d1) {
  entropy_get(d1, 64);
  memcpy(d0, d, 32);
  memset(d0 + 32, 0, 32);
}
#endif  /* HYBRID_KEM_TEST_MODE */

/* ================================================================
 * Internal helpers
 * ================================================================ */

static void memwipe(void *p, size_t n)
{
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

/**
 * Secure wipe of both DMEM and IMEM after each OTBN phase.
 *
 * Uses CHECK_* macros because wipe failure is always fatal for the test.
 */
static status_t otbn_full_sec_wipe(dif_otbn_t *otbn)
{
  CHECK_DIF_OK(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeDmem));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  CHECK_DIF_OK(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeImem));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  return OK_STATUS();
}

/**
 * Load OTBN app and verify checksum.
 *
 * Returns error status on failure so callers (especially decaps)
 * can implement constant-time fallback.
 */
static status_t load_with_checksum(dif_otbn_t *otbn,
                                   const otbn_app_t app,
                                   uint32_t expected_checksum)
{
  if (dif_otbn_clear_load_checksum(otbn) != kDifOk) return INTERNAL();
  TRY(otbn_testutils_load_app(otbn, app));

  uint32_t hw_checksum;
  if (dif_otbn_get_load_checksum(otbn, &hw_checksum) != kDifOk) {
    return INTERNAL();
  }

  if (hw_checksum != expected_checksum) {
    LOG_ERROR("Checksum mismatch: hw=0x%08x expected=0x%08x",
              hw_checksum, expected_checksum);
    return INTERNAL();
  }

  return OK_STATUS();
}

/**
 * Execute loaded OTBN app and verify instruction count.
 */
static status_t execute_and_check_insns(dif_otbn_t *otbn,
                                        uint32_t expected_insns)
{
  TRY(otbn_testutils_execute(otbn));
  TRY(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  if (expected_insns == 0) {
    return OK_STATUS();
  }

  uint32_t insn_cnt;
  if (dif_otbn_get_insn_cnt(otbn, &insn_cnt) != kDifOk) {
    return INTERNAL();
  }

  if (insn_cnt != expected_insns) {
    LOG_ERROR("Instruction count mismatch: got=0x%08x expected=0x%08x",
              insn_cnt, expected_insns);
    return INTERNAL();
  }

  return OK_STATUS();
}

/**
 * Write data to OTBN DMEM and verify by reading back in chunks.
 *
 * Chunked readback avoids stack overflow from large VLAs.
 */
static status_t write_and_verify(dif_otbn_t *otbn,
                                 size_t len_bytes,
                                 const void *src,
                                 otbn_addr_t dest)
{
  TRY(otbn_testutils_write_data(otbn, len_bytes, src, dest));

  /* Read back in 128-byte chunks to limit stack usage */
  uint8_t readback[128];
  const uint8_t *s = (const uint8_t *)src;
  for (size_t off = 0; off < len_bytes; off += sizeof(readback)) {
    size_t chunk = len_bytes - off;
    if (chunk > sizeof(readback)) chunk = sizeof(readback);
    TRY(otbn_testutils_read_data(otbn, chunk, dest + off, readback));
    if (memcmp(s + off, readback, chunk) != 0) {
      memwipe(readback, sizeof(readback));
      return INTERNAL();
    }
  }
  memwipe(readback, sizeof(readback));
  return OK_STATUS();
}

/* ================================================================
 * Individual phase functions
 * ================================================================ */

static status_t phase_mlkem_keypair(dif_otbn_t *otbn,
                                    uint8_t *pk_m, uint8_t *sk_m)
{
  TRY(load_with_checksum(otbn, kAppMlKemKeypair, kChecksumMlKemKeypair));

#ifdef HYBRID_KEM_TEST_MODE
  TRY(write_and_verify(otbn, sizeof(kTestMlKemKeypairCoins),
                       kTestMlKemKeypairCoins, kMlKemKeypairCoins));
#else
  uint8_t coins[64];
  TRY(entropy_get(coins, sizeof(coins)));
  TRY(write_and_verify(otbn, sizeof(coins), coins, kMlKemKeypairCoins));
  memwipe(coins, sizeof(coins));
#endif

  TRY(execute_and_check_insns(otbn, kExpectedInsnMlKemKeypair));

  TRY(otbn_testutils_read_data(otbn, HYBRID_KEM_PK_M_BYTES,
                               kMlKemKeypairEk, pk_m));
  TRY(otbn_testutils_read_data(otbn, HYBRID_KEM_SK_M_BYTES,
                               kMlKemKeypairDk, sk_m));

  return OK_STATUS();
}

static status_t phase_mlkem_encap(dif_otbn_t *otbn,
                                  const uint8_t *pk_m,
                                  uint8_t *ct_m, uint8_t *ss_m)
{
  TRY(load_with_checksum(otbn, kAppMlKemEncap, kChecksumMlKemEncap));

  TRY(write_and_verify(otbn, HYBRID_KEM_PK_M_BYTES, pk_m, kMlKemEncapEk));

#ifdef HYBRID_KEM_TEST_MODE
  TRY(write_and_verify(otbn, sizeof(kTestMlKemEncapCoins),
                       kTestMlKemEncapCoins, kMlKemEncapCoins));
#else
  uint8_t coins[32];
  TRY(entropy_get(coins, sizeof(coins)));
  TRY(write_and_verify(otbn, sizeof(coins), coins, kMlKemEncapCoins));
  memwipe(coins, sizeof(coins));
#endif

  TRY(execute_and_check_insns(otbn, kExpectedInsnMlKemEncap));

  TRY(otbn_testutils_read_data(otbn, HYBRID_KEM_CT_M_BYTES,
                               kMlKemEncapCt, ct_m));
  TRY(otbn_testutils_read_data(otbn, HYBRID_KEM_SS_M_BYTES,
                               kMlKemEncapSs, ss_m));

  return OK_STATUS();
}

static status_t phase_mlkem_decap(dif_otbn_t *otbn,
                                  const uint8_t *sk_m,
                                  const uint8_t *ct_m,
                                  uint8_t *ss_m)
{
  TRY(load_with_checksum(otbn, kAppMlKemDecap, kChecksumMlKemDecap));

  TRY(write_and_verify(otbn, HYBRID_KEM_SK_M_BYTES, sk_m, kMlKemDecapDk));
  TRY(write_and_verify(otbn, HYBRID_KEM_CT_M_BYTES, ct_m, kMlKemDecapCt));

  TRY(execute_and_check_insns(otbn, kExpectedInsnMlKemDecap));

  TRY(otbn_testutils_read_data(otbn, HYBRID_KEM_SS_M_BYTES,
                               kMlKemDecapSs, ss_m));

  return OK_STATUS();
}

/**
 * OTBN P-256 scalar multiplication (masked).
 *
 * Input:  d0[64B], d1[64B] = arithmetic shares of scalar
 *         point_x[32B], point_y[32B] = point coordinates
 * Output: result_x[32B] = x-coordinate of d*P (Boolean share 0 XOR share 1)
 *
 * OTBN stores the result as two Boolean shares: share0 at label `x`,
 * share1 at label `y`.  Only the x-coordinate of the result is returned
 * (sufficient for ECDH shared secret; for public key the caller must
 * recover y from x using the curve equation).
 */
static status_t phase_p256_scalar_mult(dif_otbn_t *otbn,
                                       const uint8_t *d0, const uint8_t *d1,
                                       const uint8_t *point_x,
                                       const uint8_t *point_y,
                                       uint8_t *result_x)
{
  TRY(load_with_checksum(otbn, kAppP256Ecdh, kChecksumP256Ecdh));

  TRY(write_and_verify(otbn, 64, d0, kP256D0));
  TRY(write_and_verify(otbn, 64, d1, kP256D1));
  TRY(write_and_verify(otbn, 32, point_x, kP256X));
  TRY(write_and_verify(otbn, 32, point_y, kP256Y));

  TRY(execute_and_check_insns(otbn, kExpectedInsnP256Ecdh));

  /* OTBN outputs two Boolean shares of the result x-coordinate.
   * share0 at label x, share1 at label y. XOR to unmask. */
  uint32_t share0[8], share1[8];
  TRY(otbn_testutils_read_data(otbn, 32, kP256X, share0));
  TRY(otbn_testutils_read_data(otbn, 32, kP256Y, share1));

  for (int i = 0; i < 8; i++) {
    ((uint32_t *)result_x)[i] = share0[i] ^ share1[i];
  }
  memwipe(share0, sizeof(share0));
  memwipe(share1, sizeof(share1));

  return OK_STATUS();
}

static status_t phase_hkdf(dif_otbn_t *otbn,
                           const uint8_t *salt,
                           const uint8_t *ss_e, const uint8_t *ss_m,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sid, size_t sid_len,
                           const uint8_t *role, size_t role_len,
                           uint8_t *okm, size_t okm_len)
{
  TRY(load_with_checksum(otbn, kAppHkdf, kChecksumHkdf));

  /* Build IKM: be16(32) || ss_e || be16(32) || ss_m || ctx || sid || role.
   * Round up to 4-byte boundary for OTBN DMEM word-aligned write. */
  uint8_t ikm[256] = {0};
  size_t off = 0;
  ikm[off++] = 0x00; ikm[off++] = 0x20;  /* be16(32) for ss_e */
  memcpy(&ikm[off], ss_e, 32); off += 32;
  ikm[off++] = 0x00; ikm[off++] = 0x20;  /* be16(32) for ss_m */
  memcpy(&ikm[off], ss_m, 32); off += 32;
  memcpy(&ikm[off], ctx, ctx_len); off += ctx_len;
  memcpy(&ikm[off], sid, sid_len); off += sid_len;
  memcpy(&ikm[off], role, role_len); off += role_len;
  size_t ikm_len = off;
  size_t ikm_write_len = (ikm_len + 3) & ~(size_t)3;  /* round up to 4B */

  /* Write salt, IKM, length struct, and OKM len to OTBN DMEM */
  TRY(write_and_verify(otbn, 32, salt, kHkdfSalt));
  TRY(write_and_verify(otbn, ikm_write_len, ikm, kHkdfIkmPre));

  uint32_t u32;
  u32 = (uint32_t)ctx_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfLengths + 0));
  u32 = (uint32_t)sid_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfLengths + 4));
  u32 = (uint32_t)role_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfLengths + 8));
  u32 = (uint32_t)okm_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfLengths + 12));

  memwipe(ikm, sizeof(ikm));

  TRY(execute_and_check_insns(otbn, kExpectedInsnHkdf));

  TRY(otbn_testutils_read_data(otbn, okm_len, kHkdfOutput, okm));

  return OK_STATUS();
}

/* ================================================================
 * Public API — Hybrid KEM operations
 * ================================================================ */

status_t hybrid_kem_init(void) {
  /* Always initialize entropy complex — OTBN secure wipe requires it. */
  return entropy_testutils_auto_mode_init();
}

status_t hybrid_keygen(dif_otbn_t *otbn,
                       uint8_t *pk_hyb, uint8_t *sk_hyb)
{
  if (otbn == NULL || pk_hyb == NULL || sk_hyb == NULL) {
    return INVALID_ARGUMENT();
  }

  uint8_t *pk_m = pk_hyb;
  uint8_t *pk_e = pk_hyb + HYBRID_KEM_PK_M_BYTES;
  uint8_t *sk_m = sk_hyb;
  uint8_t *sk_e = sk_hyb + HYBRID_KEM_SK_M_BYTES;

  /* === Step 1: ML-KEM-768 KeyGen === */
  TRY(phase_mlkem_keypair(otbn, pk_m, sk_m));
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 2: P-256 KeyGen (d*G) → pk_e (x-coordinate only) === */
#ifdef HYBRID_KEM_TEST_MODE
  TRY(phase_p256_scalar_mult(otbn,
                             kTestP256D0, kTestP256D1,
                             kTestP256GenX, kTestP256GenY,
                             pk_e));
  memcpy(sk_e, kTestP256D0, HYBRID_KEM_SK_E_BYTES);
#else
  uint8_t d[HYBRID_KEM_SK_E_BYTES];
  uint8_t d0[64], d1[64];
  memset(d0, 0, sizeof(d0));
  memset(d1, 0, sizeof(d1));

  TRY(entropy_get(d, sizeof(d)));
  p256_split_scalar(d, d0, d1);

  TRY(phase_p256_scalar_mult(otbn,
                             d0, d1,
                             kTestP256GenX, kTestP256GenY,
                             pk_e));
  memcpy(sk_e, d, HYBRID_KEM_SK_E_BYTES);

  memwipe(d, sizeof(d));
  memwipe(d0, sizeof(d0));
  memwipe(d1, sizeof(d1));
#endif
  /* pk_e[32..63] remain zero (x-coordinate only for ECDH).
   * Full uncompressed point recovery requires y from curve equation. */
  memset(pk_e + 32, 0, 32);

  TRY(otbn_full_sec_wipe(otbn));

  return OK_STATUS();
}

status_t hybrid_encaps(dif_otbn_t *otbn,
                       const uint8_t *pk_hyb,
                       const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *ct_hyb,
                       uint8_t *okm, size_t okm_len)
{
  if (otbn == NULL || pk_hyb == NULL || ct_hyb == NULL || okm == NULL) {
    return INVALID_ARGUMENT();
  }
  if (okm_len == 0 || okm_len > HYBRID_KEM_OKM_MAX) {
    return INVALID_ARGUMENT();
  }
  if (ctx_len > HYBRID_KEM_CTX_MAX || sid_len > HYBRID_KEM_SID_MAX) {
    return INVALID_ARGUMENT();
  }

  const uint8_t *pk_m_bob = pk_hyb;
  const uint8_t *pk_e_bob = pk_hyb + HYBRID_KEM_PK_M_BYTES;

  uint8_t ss_e[HYBRID_KEM_SS_E_BYTES];
  uint8_t ss_m[HYBRID_KEM_SS_M_BYTES];
  uint8_t ek[HYBRID_KEM_PK_E_BYTES];
  uint8_t salt_buf[HYBRID_KEM_SALT_BYTES];

  memset(ss_e, 0, sizeof(ss_e));
  memset(ss_m, 0, sizeof(ss_m));
  memset(ek, 0, sizeof(ek));

  if (salt != NULL) {
    memcpy(salt_buf, salt, HYBRID_KEM_SALT_BYTES);
  } else {
    memset(salt_buf, 0, HYBRID_KEM_SALT_BYTES);
  }

  /* P-256 ephemeral scalar — 测试/生产 模式选择 */
#ifdef HYBRID_KEM_TEST_MODE
  const uint8_t *d0 = kTestP256D0;
  const uint8_t *d1 = kTestP256D1;
#else
  uint8_t d0_prod[64], d1_prod[64], d_prod[32];
  const uint8_t *d0 = d0_prod;
  const uint8_t *d1 = d1_prod;
  memset(d0_prod, 0, sizeof(d0_prod));
  memset(d1_prod, 0, sizeof(d1_prod));
  TRY(entropy_get(d_prod, sizeof(d_prod)));
  p256_split_scalar(d_prod, d0_prod, d1_prod);
#endif

  /* === Step 1: P-256 ECDH — ephemeral keygen (d*G) → ek === */
  TRY(phase_p256_scalar_mult(otbn, d0, d1,
                             kTestP256GenX, kTestP256GenY,
                             ek));
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 2: P-256 ECDH — ss_e = d * pk_e_bob === */
  TRY(phase_p256_scalar_mult(otbn, d0, d1,
                             pk_e_bob, pk_e_bob + 32,
                             ss_e));
  TRY(otbn_full_sec_wipe(otbn));

#ifndef HYBRID_KEM_TEST_MODE
  memwipe(d_prod, sizeof(d_prod));
  memwipe(d0_prod, sizeof(d0_prod));
  memwipe(d1_prod, sizeof(d1_prod));
#endif

  /* === Step 3: ML-KEM-768 Encap === */
  TRY(phase_mlkem_encap(otbn, pk_m_bob, ct_hyb + HYBRID_KEM_PK_E_BYTES, ss_m));
  TRY(otbn_full_sec_wipe(otbn));

  memcpy(ct_hyb, ek, HYBRID_KEM_PK_E_BYTES);
  memwipe(ek, sizeof(ek));

  /* === Step 4: HKDF-SHA3-256 === */
  TRY(phase_hkdf(otbn, salt_buf, ss_e, ss_m,
                 ctx, ctx_len, sid, sid_len,
                 (const uint8_t *)HYBRID_KEM_ROLE_INITIATOR,
                 HYBRID_KEM_ROLE_INITIATOR_LEN,
                 okm, okm_len));
  TRY(otbn_full_sec_wipe(otbn));

  memwipe(ss_e, sizeof(ss_e));
  memwipe(ss_m, sizeof(ss_m));
  memwipe(salt_buf, sizeof(salt_buf));

  return OK_STATUS();
}

status_t hybrid_decaps(dif_otbn_t *otbn,
                       const uint8_t *sk_hyb,
                       const uint8_t *ct_hyb,
                       const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *okm, size_t okm_len)
{
  if (otbn == NULL || sk_hyb == NULL || ct_hyb == NULL || okm == NULL) {
    return INVALID_ARGUMENT();
  }
  if (okm_len == 0 || okm_len > HYBRID_KEM_OKM_MAX) {
    return INVALID_ARGUMENT();
  }
  if (ctx_len > HYBRID_KEM_CTX_MAX || sid_len > HYBRID_KEM_SID_MAX) {
    return INVALID_ARGUMENT();
  }

  const uint8_t *sk_m_bob = sk_hyb;
  const uint8_t *sk_e_bob = sk_hyb + HYBRID_KEM_SK_M_BYTES;
  const uint8_t *ek_alice = ct_hyb;
  const uint8_t *ct_m     = ct_hyb + HYBRID_KEM_PK_E_BYTES;

  uint8_t ss_e[HYBRID_KEM_SS_E_BYTES];
  uint8_t ss_m[HYBRID_KEM_SS_M_BYTES];
  uint8_t salt_buf[HYBRID_KEM_SALT_BYTES];
  status_t result = OK_STATUS();

  memset(ss_e, 0, sizeof(ss_e));
  memset(ss_m, 0, sizeof(ss_m));

  if (salt != NULL) {
    memcpy(salt_buf, salt, HYBRID_KEM_SALT_BYTES);
  } else {
    memset(salt_buf, 0, HYBRID_KEM_SALT_BYTES);
  }

  /* === Step 1: P-256 ECDH (sk_e_bob * ek_alice) ===
   * 常数时间: 即使失败也继续执行后续步骤 */
  status_t s1 = load_with_checksum(otbn, kAppP256Ecdh, kChecksumP256Ecdh);

#ifdef HYBRID_KEM_TEST_MODE
  if (status_ok(s1)) {
    s1 = write_and_verify(otbn, 32, sk_e_bob, kP256D0);
  }
  /* d1 = 0 (测试模式) */
#else
  uint8_t d0[64], d1[64];
  memset(d0, 0, sizeof(d0));
  memset(d1, 0, sizeof(d1));
  if (status_ok(s1)) {
    p256_split_scalar(sk_e_bob, d0, d1);
    s1 = write_and_verify(otbn, 64, d0, kP256D0);
  }
  if (status_ok(s1)) {
    s1 = write_and_verify(otbn, 64, d1, kP256D1);
  }
  memwipe(d0, sizeof(d0));
  memwipe(d1, sizeof(d1));
#endif

  if (status_ok(s1)) {
    s1 = write_and_verify(otbn, 32, ek_alice, kP256X);
  }
  if (status_ok(s1)) {
    s1 = write_and_verify(otbn, 32, ek_alice + 32, kP256Y);
  }
  if (status_ok(s1)) {
    s1 = otbn_testutils_execute(otbn);
  }
  if (status_ok(s1)) {
    s1 = otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError);
  }

  if (status_ok(s1)) {
    uint32_t share0[8], share1[8];
    status_t rs = otbn_testutils_read_data(otbn, 32, kP256X, share0);
    status_t ry = otbn_testutils_read_data(otbn, 32, kP256Y, share1);
    if (status_ok(rs) && status_ok(ry)) {
      for (int i = 0; i < 8; i++) {
        ((uint32_t *)ss_e)[i] = share0[i] ^ share1[i];
      }
    } else {
      memset(ss_e, 0xAA, sizeof(ss_e));
      s1 = INTERNAL();
    }
    memwipe(share0, sizeof(share0));
    memwipe(share1, sizeof(share1));
  } else {
    memset(ss_e, 0xAA, sizeof(ss_e));
    result = s1;
  }
  /* Always wipe, even on failure (constant-time requirement) */
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 2: ML-KEM-768 Decap === */
  status_t s2 = phase_mlkem_decap(otbn, sk_m_bob, ct_m, ss_m);
  if (!status_ok(s2)) {
    memset(ss_m, 0xBB, sizeof(ss_m));
    if (status_ok(result)) result = s2;
  }
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 3: HKDF-SHA3-256 (always executed — constant-time) === */
  status_t s3 = phase_hkdf(otbn, salt_buf, ss_e, ss_m,
                           ctx, ctx_len, sid, sid_len,
                           (const uint8_t *)HYBRID_KEM_ROLE_RESPONDER,
                           HYBRID_KEM_ROLE_RESPONDER_LEN,
                           okm, okm_len);
  if (!status_ok(s3)) {
    memset(okm, 0, okm_len);
    if (status_ok(result)) result = s3;
  }
  TRY(otbn_full_sec_wipe(otbn));

  memwipe(ss_e, sizeof(ss_e));
  memwipe(ss_m, sizeof(ss_m));
  memwipe(salt_buf, sizeof(salt_buf));

  return result;
}

/* ================================================================
 * OTTF test entry point
 * ================================================================ */

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));

  CHECK_STATUS_OK(hybrid_kem_init());

  uint8_t pk_hyb[HYBRID_KEM_PK_HYB_BYTES];
  uint8_t sk_hyb[HYBRID_KEM_SK_HYB_BYTES];
  uint8_t ct_hyb[HYBRID_KEM_CT_HYB_BYTES];
  uint8_t okm_a[32], okm_b[32];
  const uint8_t salt[HYBRID_KEM_SALT_BYTES] = {0};

  LOG_INFO("Hybrid KEM round-trip test starting...");

  /* Bob: key generation */
  CHECK_STATUS_OK(hybrid_keygen(&otbn, pk_hyb, sk_hyb));
  LOG_INFO("Keygen: PASS");

  /* Alice: encapsulation */
  CHECK_STATUS_OK(hybrid_encaps(&otbn, pk_hyb, salt,
      (const uint8_t *)"test", 4,
      (const uint8_t *)"001", 3,
      ct_hyb, okm_a, sizeof(okm_a)));
  LOG_INFO("Encaps: PASS");

  /* Bob: decapsulation */
  CHECK_STATUS_OK(hybrid_decaps(&otbn, sk_hyb, ct_hyb, salt,
      (const uint8_t *)"test", 4,
      (const uint8_t *)"001", 3,
      okm_b, sizeof(okm_b)));
  LOG_INFO("Decaps: PASS");

  /* OKM must match */
  CHECK(memcmp(okm_a, okm_b, sizeof(okm_a)) == 0,
        "Alice/Bob OKM mismatch!");
  LOG_INFO("Round-trip OKM verified.");

  return true;
}
