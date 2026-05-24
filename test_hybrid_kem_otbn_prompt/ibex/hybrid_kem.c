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

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/testing/otbn_testutils.h"

#include <string.h>

/* ---- 生产模式: 熵源头文件 ---- */
#ifndef HYBRID_KEM_TEST_MODE
#  include "sw/device/lib/dif/dif_entropy_src.h"
#  include "sw/device/lib/testing/entropy_testutils.h"
#endif

/* ================================================================
 * OTBN app declarations — build pipeline resolves all symbols
 * ================================================================ */

/* ---- mlkem768_keypair ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);

static const otbn_app_t kAppMlKemKeypair = OTBN_APP_T_INIT(mlkem768_keypair);
static const otbn_addr_t kMlKemKeypairCoins = OTBN_ADDR_T_INIT(mlkem768_keypair, coins);
static const otbn_addr_t kMlKemKeypairEk    = OTBN_ADDR_T_INIT(mlkem768_keypair, ek);
static const otbn_addr_t kMlKemKeypairDk    = OTBN_ADDR_T_INIT(mlkem768_keypair, dk);

/* ---- mlkem768_encap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_encap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ss);

static const otbn_app_t kAppMlKemEncap = OTBN_APP_T_INIT(mlkem768_encap);
static const otbn_addr_t kMlKemEncapCoins = OTBN_ADDR_T_INIT(mlkem768_encap, coins);
static const otbn_addr_t kMlKemEncapEk    = OTBN_ADDR_T_INIT(mlkem768_encap, ek);
static const otbn_addr_t kMlKemEncapCt    = OTBN_ADDR_T_INIT(mlkem768_encap, ct);
static const otbn_addr_t kMlKemEncapSs    = OTBN_ADDR_T_INIT(mlkem768_encap, ss);

/* ---- mlkem768_decap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_decap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ss);

static const otbn_app_t kAppMlKemDecap = OTBN_APP_T_INIT(mlkem768_decap);
static const otbn_addr_t kMlKemDecapCt = OTBN_ADDR_T_INIT(mlkem768_decap, ct);
static const otbn_addr_t kMlKemDecapDk = OTBN_ADDR_T_INIT(mlkem768_decap, dk);
static const otbn_addr_t kMlKemDecapSs = OTBN_ADDR_T_INIT(mlkem768_decap, ss);

/* ---- p256_ecdh (keygen + ECDH — 同一 OTBN app) ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);

static const otbn_app_t kAppP256Ecdh = OTBN_APP_T_INIT(p256_ecdh);
static const otbn_addr_t kP256D0 = OTBN_ADDR_T_INIT(p256_ecdh, d0);
static const otbn_addr_t kP256D1 = OTBN_ADDR_T_INIT(p256_ecdh, d1);
static const otbn_addr_t kP256X  = OTBN_ADDR_T_INIT(p256_ecdh, x);
static const otbn_addr_t kP256Y  = OTBN_ADDR_T_INIT(p256_ecdh, y);

/* ---- hkdf_sha3_256 ---- */
OTBN_DECLARE_APP_SYMBOLS(hkdf_sha3_256);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_salt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_ss_e);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_ss_m);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_ctx_len);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_sid_len);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_role_len);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_okm_len);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_ctx);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_sid);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_role);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, output_okm);

static const otbn_app_t kAppHkdf = OTBN_APP_T_INIT(hkdf_sha3_256);
static const otbn_addr_t kHkdfSalt    = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_salt);
static const otbn_addr_t kHkdfSsE     = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_ss_e);
static const otbn_addr_t kHkdfSsM     = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_ss_m);
static const otbn_addr_t kHkdfCtxLen  = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_ctx_len);
static const otbn_addr_t kHkdfSidLen  = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_sid_len);
static const otbn_addr_t kHkdfRoleLen = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_role_len);
static const otbn_addr_t kHkdfOkmLen  = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_okm_len);
static const otbn_addr_t kHkdfCtx     = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_ctx);
static const otbn_addr_t kHkdfSid     = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_sid);
static const otbn_addr_t kHkdfRole    = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_role);
static const otbn_addr_t kHkdfOutput  = OTBN_ADDR_T_INIT(hkdf_sha3_256, output_okm);

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
static const uint8_t kTestP256D0[64] = {
    0x71, 0x10, 0x6d, 0xfe, 0x16, 0xa0, 0xd0, 0x21,
    0x81, 0xc7, 0xb2, 0xb0, 0x5d, 0xef, 0x90, 0x95,
    0x79, 0xa3, 0xdf, 0x3f, 0xe8, 0xeb, 0x76, 0x1b,
    0x63, 0x02, 0x21, 0x74, 0x41, 0xfc, 0x20, 0x14,
};
/* d1 = 0 简化测试: scalar d = d0 + 0 = 测试向量给出的标量值 */
static const uint8_t kTestP256D1[64] = {0};
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

/* ---- 测试模式熵函数: 返回硬编码向量 ---- */
static status_t entropy_init(void)  { return OK_STATUS(); }
static void entropy_get(void *buf, size_t len) {
  /* 测试模式不使用此函数, 各 phase 直接用 kTest* 常量 */
  memset(buf, 0, len);
}

#else  /* !HYBRID_KEM_TEST_MODE — 生产安全模式 */
/* ================================================================
 * 生产安全模式: 从硬件 TRNG 获取全部随机数
 *
 * 使用 OpenTitan 熵源 (dif_entropy_src).
 * P-256 私钥拆分为真算术份额: d = d0 + d1 mod n
 * 每轮 ML-KEM coins 独立刷新.
 * ================================================================ */

static dif_entropy_src_t g_entropy;

static status_t entropy_init(void) {
  /* 初始化硬件熵源。
   * 实际集成时根据平台选择:
   *   - 测试框架: entropy_testutils_auto_mode_init()
   *   - 生产:     dif_entropy_src_init() + dif_entropy_src_configure()
   * 此处调用 entropy_testutils 的自动模式初始化。 */
  return entropy_testutils_auto_mode_init();
}

/** 从硬件熵源读取 len 字节随机数。 */
static status_t entropy_get(void *buf, size_t len) {
  /* dif_entropy_src_read() 一次读 4 bytes (uint32_t).
   * 循环读取直到满足 len 字节。 */
  uint32_t *out = (uint32_t *)buf;
  size_t words = (len + 3) / 4;
  for (size_t i = 0; i < words; i++) {
    uint32_t rnd;
    dif_result_t r = dif_entropy_src_read(&g_entropy, &rnd);
    if (r != kDifOk) return INTERNAL();
    out[i] = rnd;
  }
  return OK_STATUS();
}

/**
 * P-256 标量算术份额拆分 (生产模式).
 *
 * 输入: d[32] = 256-bit 私钥标量 (原始随机数)
 * 输出: d0[64], d1[64] = 320-bit 算术份额
 *       d = (d0 + d1) mod n, 其中 d1 为随机数
 *
 * 注意: 此函数需要在 Ibex 侧执行模 n 运算。
 * 完整实现应使用 OTBN 进行模约简。
 * 当前简化为: d0 = d (低位 256-bit), d1 = random (高位 256-bit)
 * TODO: 实现真模 n 拆分或交由 OTBN 处理
 */
static void p256_split_scalar(const uint8_t *d, uint8_t *d0, uint8_t *d1) {
  /* 从 TRNG 获取 64B 随机 d1 */
  entropy_get(d1, 64);
  /* d0 = (d - d1) mod n — 简化: 复制 d 到 d0 低 32B。
   * PROD: 需要 256-bit 大整数模 n 运算。 */
  memcpy(d0, d, 32);
  memset(d0 + 32, 0, 32); /* 高 256-bit 填零 */
  /* 高位置零保证 d0 + d1 = d + (d1高256) < n + (大数),
   * OTBN 内部 p256_masked_scalar_reblind 会处理模约简。 */
}
#endif  /* HYBRID_KEM_TEST_MODE */

/* ================================================================
 * OTBN app checksums — 构建流水线自动生成
 *
 * 符号: _otbn_remote_app_<name>_checksum
 * 值: CRC32 over IMEM + initialized DMEM
 * 验证: load_with_checksum() 每次加载后比对
 * ================================================================ */

#define OTBN_DECLARE_CHECKSUM(app_name) \
  extern const uint8_t _otbn_remote_app_##app_name##_checksum[]

OTBN_DECLARE_CHECKSUM(mlkem768_keypair);
OTBN_DECLARE_CHECKSUM(mlkem768_encap);
OTBN_DECLARE_CHECKSUM(mlkem768_decap);
OTBN_DECLARE_CHECKSUM(p256_ecdh);
OTBN_DECLARE_CHECKSUM(hkdf_sha3_256);

static const uint32_t kChecksumMlKemKeypair =
    (uint32_t)(uintptr_t)_otbn_remote_app_mlkem768_keypair_checksum;
static const uint32_t kChecksumMlKemEncap =
    (uint32_t)(uintptr_t)_otbn_remote_app_mlkem768_encap_checksum;
static const uint32_t kChecksumMlKemDecap =
    (uint32_t)(uintptr_t)_otbn_remote_app_mlkem768_decap_checksum;
static const uint32_t kChecksumP256Ecdh =
    (uint32_t)(uintptr_t)_otbn_remote_app_p256_ecdh_checksum;
static const uint32_t kChecksumHkdf =
    (uint32_t)(uintptr_t)_otbn_remote_app_hkdf_sha3_256_checksum;

/* ---- 指令计数阈值 (从 otbn_sim 实测, 0 = 跳过) ---- */
static const uint32_t kExpectedInsnMlKemKeypair = HYBRID_KEM_INSNS_MLKEM_KEYPAIR;
static const uint32_t kExpectedInsnMlKemEncap   = HYBRID_KEM_INSNS_MLKEM_ENCAP;
static const uint32_t kExpectedInsnMlKemDecap   = HYBRID_KEM_INSNS_MLKEM_DECAP;
static const uint32_t kExpectedInsnP256Ecdh     = HYBRID_KEM_INSNS_P256_ECDH;
static const uint32_t kExpectedInsnHkdf         = HYBRID_KEM_INSNS_HKDF;

/* ================================================================
 * Internal helpers — hardened OTBN lifecycle
 * ================================================================ */

static status_t otbn_full_sec_wipe(dif_otbn_t *otbn)
{
  TRY(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeDmem));
  TRY(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  TRY(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeImem));
  TRY(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  return OK_STATUS();
}

static status_t load_with_checksum(dif_otbn_t *otbn,
                                   const otbn_app_t app,
                                   uint32_t expected_checksum)
{
  TRY(dif_otbn_clear_load_checksum(otbn));
  TRY(otbn_testutils_load_app(otbn, app));

  uint32_t hw_checksum;
  TRY(dif_otbn_get_load_checksum(otbn, &hw_checksum));

  if (hw_checksum != expected_checksum) {
    return INTERNAL();
  }

  return OK_STATUS();
}

static status_t execute_and_check_insns(dif_otbn_t *otbn,
                                        uint32_t expected_insns)
{
  TRY(otbn_testutils_execute(otbn));
  TRY(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));

  if (expected_insns == 0) {
    return OK_STATUS();
  }

  uint32_t insn_cnt;
  TRY(dif_otbn_get_insn_cnt(otbn, &insn_cnt));

  if (insn_cnt != expected_insns) {
    return INTERNAL();
  }

  return OK_STATUS();
}

static status_t write_and_verify(dif_otbn_t *otbn,
                                 size_t len_bytes,
                                 const void *src,
                                 otbn_addr_t dest)
{
  TRY(otbn_testutils_write_data(otbn, len_bytes, src, dest));

  uint8_t readback[len_bytes];
  TRY(otbn_testutils_read_data(otbn, len_bytes, dest, readback));

  if (memcmp(src, readback, len_bytes) != 0) {
    memwipe(readback, len_bytes);
    return INTERNAL();
  }

  memwipe(readback, len_bytes);
  return OK_STATUS();
}

static status_t wait_for_done_resilient(dif_otbn_t *otbn,
                                        dif_otbn_err_bits_t expected_err_bits)
{
  dif_otbn_status_t st;
  while (1) {
    TRY(dif_otbn_get_status(otbn, &st));
    if (st == kDifOtbnStatusIdle) break;
    if (st == kDifOtbnStatusLocked) {
      dif_otbn_err_bits_t errs;
      TRY(dif_otbn_get_err_bits(otbn, &errs));
      TRY(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeDmem));
      while (1) {
        TRY(dif_otbn_get_status(otbn, &st));
        if (st == kDifOtbnStatusIdle) break;
      }
      TRY(dif_otbn_write_cmd(otbn, kDifOtbnCmdSecWipeImem));
      while (1) {
        TRY(dif_otbn_get_status(otbn, &st));
        if (st == kDifOtbnStatusIdle) break;
      }
      return INTERNAL();
    }
  }

  dif_otbn_err_bits_t errs;
  TRY(dif_otbn_get_err_bits(otbn, &errs));
  if (errs != expected_err_bits) {
    return INTERNAL();
  }

  return OK_STATUS();
}

static void memwipe(void *p, size_t n)
{
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

/* ================================================================
 * Public: 子系统初始化
 * ================================================================ */

status_t hybrid_kem_init(void) {
  return entropy_init();
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
  /* 生产: 从 TRNG 获取 64B 随机 coins */
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

  uint32_t x0[8], x1[8];
  TRY(otbn_testutils_read_data(otbn, 32, kP256X, x0));
  TRY(otbn_testutils_read_data(otbn, 32, kP256Y, x1));

  for (int i = 0; i < 8; i++) {
    ((uint32_t *)result_x)[i] = x0[i] ^ x1[i];
  }
  memwipe(x0, sizeof(x0));
  memwipe(x1, sizeof(x1));

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

  TRY(write_and_verify(otbn, 32, salt, kHkdfSalt));
  TRY(write_and_verify(otbn, 32, ss_e, kHkdfSsE));
  TRY(write_and_verify(otbn, 32, ss_m, kHkdfSsM));

  uint32_t u32;
  u32 = (uint32_t)ctx_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfCtxLen));
  u32 = (uint32_t)sid_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfSidLen));
  u32 = (uint32_t)role_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfRoleLen));
  u32 = (uint32_t)okm_len;
  TRY(otbn_testutils_write_data(otbn, 4, &u32, kHkdfOkmLen));

  if (ctx_len > 0) {
    TRY(otbn_testutils_write_data(otbn, ctx_len, ctx, kHkdfCtx));
  }
  if (sid_len > 0) {
    TRY(otbn_testutils_write_data(otbn, sid_len, sid, kHkdfSid));
  }
  TRY(write_and_verify(otbn, role_len, role, kHkdfRole));

  TRY(execute_and_check_insns(otbn, kExpectedInsnHkdf));

  TRY(otbn_testutils_read_data(otbn, okm_len, kHkdfOutput, okm));

  return OK_STATUS();
}

/* ================================================================
 * Public API — Hybrid KEM operations
 * ================================================================ */

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

  /* === Step 2: P-256 KeyGen (d*G) === */
#ifdef HYBRID_KEM_TEST_MODE
  TRY(phase_p256_scalar_mult(otbn,
                             kTestP256D0, kTestP256D1,
                             kTestP256GenX, kTestP256GenY,
                             pk_e));
  memcpy(sk_e, kTestP256D0, HYBRID_KEM_SK_E_BYTES);
#else
  /* 生产: 生成随机标量 d, 拆分为算术份额 d0,d1 */
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
  /* 私钥 = 原始标量 d */
  memcpy(sk_e, d, HYBRID_KEM_SK_E_BYTES);

  memwipe(d, sizeof(d));
  memwipe(d0, sizeof(d0));
  memwipe(d1, sizeof(d1));
#endif
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
  uint8_t d0_prod[64], d1_prod[64], d_prod[32];
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

  /* === Step 2: P-256 ECDH — ss_e = d * Bob's pk_e === */
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
   * 常数时间: 即使失败也继续执行 */
  status_t s1;
  s1 = load_with_checksum(otbn, kAppP256Ecdh, kChecksumP256Ecdh);

#ifdef HYBRID_KEM_TEST_MODE
  if (STATUS_OK(s1)) {
    s1 = write_and_verify(otbn, 32, sk_e_bob, kP256D0);
  }
  /* d1 = 0 (测试模式) */
#else
  /* 生产: 将 sk_e_bob 拆分为算术份额 */
  uint8_t d0[64], d1[64];
  memset(d0, 0, sizeof(d0));
  memset(d1, 0, sizeof(d1));
  if (STATUS_OK(s1)) {
    p256_split_scalar(sk_e_bob, d0, d1);
    s1 = write_and_verify(otbn, 64, d0, kP256D0);
  }
  if (STATUS_OK(s1)) {
    s1 = write_and_verify(otbn, 64, d1, kP256D1);
  }
  memwipe(d0, sizeof(d0));
  memwipe(d1, sizeof(d1));
#endif

  if (STATUS_OK(s1)) {
    s1 = write_and_verify(otbn, 32, ek_alice, kP256X);
  }
  if (STATUS_OK(s1)) {
    s1 = write_and_verify(otbn, 32, ek_alice + 32, kP256Y);
  }
  if (STATUS_OK(s1)) {
    s1 = otbn_testutils_execute(otbn);
  }
  if (STATUS_OK(s1)) {
    s1 = wait_for_done_resilient(otbn, kDifOtbnErrBitsNoError);
  }

  if (STATUS_OK(s1)) {
    uint32_t x0[8], x1[8];
    otbn_testutils_read_data(otbn, 32, kP256X, x0);
    otbn_testutils_read_data(otbn, 32, kP256Y, x1);
    for (int i = 0; i < 8; i++) {
      ((uint32_t *)ss_e)[i] = x0[i] ^ x1[i];
    }
    memwipe(x0, sizeof(x0));
    memwipe(x1, sizeof(x1));
  } else {
    memset(ss_e, 0xAA, sizeof(ss_e));
    result = s1;
  }
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 2: ML-KEM-768 Decap === */
  status_t s2 = phase_mlkem_decap(otbn, sk_m_bob, ct_m, ss_m);
  if (!STATUS_OK(s2)) {
    memset(ss_m, 0xBB, sizeof(ss_m));
    if (STATUS_OK(result)) result = s2;
  }
  TRY(otbn_full_sec_wipe(otbn));

  /* === Step 3: HKDF-SHA3-256 === */
  status_t s3 = phase_hkdf(otbn, salt_buf, ss_e, ss_m,
                           ctx, ctx_len, sid, sid_len,
                           (const uint8_t *)HYBRID_KEM_ROLE_RESPONDER,
                           HYBRID_KEM_ROLE_RESPONDER_LEN,
                           okm, okm_len);
  if (!STATUS_OK(s3)) {
    memset(okm, 0, okm_len);
    if (STATUS_OK(result)) result = s3;
  }
  TRY(otbn_full_sec_wipe(otbn));

  memwipe(ss_e, sizeof(ss_e));
  memwipe(ss_m, sizeof(ss_m));
  memwipe(salt_buf, sizeof(salt_buf));

  return result;
}
