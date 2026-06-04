/**
 * @file hybrid_kem_keygen.c
 * @brief Phase 1 — Hybrid KEM KeyGen (all inline, chip sim compatible).
 *
 * Step 1: P-256 ECDH → pk_e
 * Step 2: ML-KEM-768 keypair → pk_m, sk_m
 *
 * All OTBN operations inlined into test_main — no helper functions.
 * Verified: helper functions + multi-OTBN-binary triggers Alert 48
 * in Verilator chip sim (see p256_plus_mlkem experiments).
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ---- p256_ecdh ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, _checksum);
static const otbn_app_t kAppP256 = OTBN_APP_T_INIT(p256_ecdh);
static const otbn_addr_t kD0 = OTBN_ADDR_T_INIT(p256_ecdh, d0);
static const otbn_addr_t kD1 = OTBN_ADDR_T_INIT(p256_ecdh, d1);
static const otbn_addr_t kX  = OTBN_ADDR_T_INIT(p256_ecdh, x);
static const otbn_addr_t kY  = OTBN_ADDR_T_INIT(p256_ecdh, y);
static const uint32_t kP256Checksum = OTBN_ADDR_T_INIT(p256_ecdh, _checksum);

/* ---- mlkem768_keypair ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);
static const otbn_app_t kAppMlkem = OTBN_APP_T_INIT(mlkem768_keypair);

/* ---- Test vectors ---- */
static const uint8_t kP256D0[64] = {
    0x71,0x10,0x6d,0xfe,0x16,0xa0,0xd0,0x21,0x81,0xc7,0xb2,
    0xb0,0x5d,0xef,0x90,0x95,0x79,0xa3,0xdf,0x3f,0xe8,0xeb,
    0x76,0x1b,0x63,0x02,0x21,0x74,0x41,0xfc,0x20,0x14,
};
static const uint8_t kP256D1[64] = {0};
static const uint8_t kP256Gx[32] = {
    0x34,0xc3,0xa8,0xbf,0xb3,0xb7,0x73,0x97,0x89,0x06,0x6b,
    0xf3,0xb2,0xc0,0xc0,0x6e,0xf3,0x8b,0x6c,0xdb,0x58,0xce,
    0x28,0x16,0x46,0xc5,0xcd,0xfa,0x6a,0x1a,0x55,0xb5,
};
static const uint8_t kP256Gy[32] = {
    0x2e,0x8c,0x00,0x9e,0x58,0x70,0x70,0xa8,0x24,0x69,0x9c,
    0xab,0xd0,0x11,0x7a,0x7f,0xfa,0x17,0x3a,0xb5,0xea,0x09,
    0xdd,0x43,0x43,0xc1,0x31,0x1f,0x97,0xc6,0xa1,0x42,
};
static const uint8_t kKpCoins[64] = {
    0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,0x61,0x60,0x45,
    0x50,0x76,0x05,0x85,0x3e,0xd7,0x3b,0x80,0x93,0xf6,0xef,
    0xbc,0x88,0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26,0x3c,
    0xb1,0xee,0xa9,0x88,0x00,0x4b,0x93,0x10,0x3c,0xfb,0x0a,
    0xee,0xfd,0x2a,0x68,0x6e,0x01,0xfa,0x4a,0x58,0xe8,0xa3,
    0x63,0x9c,0xa8,0xa1,0xe3,0xf9,0xae,0x57,0xe2,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  /* ============================================================
   * Step 1: P-256 ECDH KeyGen → pk_e (all inline)
   * ============================================================ */
  LOG_INFO("Step 1: P-256 ECDH KeyGen...");

  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppP256));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kP256Checksum, "P-256 checksum mismatch hw=0x%08x exp=0x%08x",
        hw_cs, kP256Checksum);
  LOG_INFO("  P-256 checksum OK");

  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kP256D0, kD0));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kP256D1, kD1));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kP256Gx, kX));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kP256Gy, kY));

  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));

  uint32_t s0[8], s1[8];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kX, s0));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kY, s1));
  static uint8_t pk_e[64];
  for (int i = 0; i < 8; i++) ((uint32_t *)pk_e)[i] = s0[i] ^ s1[i];
  for (int i = 8; i < 16; i++) ((uint32_t *)pk_e)[i] = 0;
  LOG_INFO("  pk_e[ 0.. 3]=%02x%02x%02x%02x  pk_e[60..63]=%02x%02x%02x%02x",
           pk_e[0], pk_e[1], pk_e[2], pk_e[3],
           pk_e[60], pk_e[61], pk_e[62], pk_e[63]);

  /* ============================================================
   * Step 2: ML-KEM-768 KeyGen → pk_m, sk_m (all inline)
   * ============================================================ */
  LOG_INFO("Step 2: ML-KEM-768 KeyGen...");

  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppMlkem));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kKpCoins), kKpCoins,
      OTBN_ADDR_T_INIT(mlkem768_keypair, coins)));

  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));

  static uint8_t pk_m[1184], sk_m[2400];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(pk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, ek), pk_m));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(sk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, dk), sk_m));
  LOG_INFO("  pk_m[   0..   3]=%02x%02x%02x%02x  pk_m[1180..1183]=%02x%02x%02x%02x",
           pk_m[0], pk_m[1], pk_m[2], pk_m[3],
           pk_m[1180], pk_m[1181], pk_m[1182], pk_m[1183]);
  LOG_INFO("  sk_m[   0..   3]=%02x%02x%02x%02x  sk_m[2396..2399]=%02x%02x%02x%02x",
           sk_m[0], sk_m[1], sk_m[2], sk_m[3],
           sk_m[2396], sk_m[2397], sk_m[2398], sk_m[2399]);

  LOG_INFO("=== Phase 1 complete: PK_Hyb = pk_m(1184B) || pk_e(64B) = 1248B ===");
  return true;
}
