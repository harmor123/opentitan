/**
 * @file p256_plus_mlkem.c
 * @brief Minimal test: EXACT copy of p256_only + one mlkem dep, not executed.
 *
 * If this FAILS → multi-binary linking is the sole root cause.
 * If this OKES → code structure differences matter.
 */

#include "hw/top/dt/otbn.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();
static_assert(kDtOtbnCount >= 1,
              "This test requires at least one OTBN instance");
static dt_otbn_t kTestOtbn = (dt_otbn_t)0;

/* ---- p256_ecdh ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, _checksum);

static const otbn_app_t kApp = OTBN_APP_T_INIT(p256_ecdh);
static const otbn_addr_t kD0 = OTBN_ADDR_T_INIT(p256_ecdh, d0);
static const otbn_addr_t kD1 = OTBN_ADDR_T_INIT(p256_ecdh, d1);
static const otbn_addr_t kX = OTBN_ADDR_T_INIT(p256_ecdh, x);
static const otbn_addr_t kY = OTBN_ADDR_T_INIT(p256_ecdh, y);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(p256_ecdh, _checksum);

#include <string.h>

static const uint8_t kTestD0[64] = {
    0x71,0x10,0x6d,0xfe,0x16,0xa0,0xd0,0x21,0x81,0xc7,0xb2,
    0xb0,0x5d,0xef,0x90,0x95,0x79,0xa3,0xdf,0x3f,0xe8,0xeb,
    0x76,0x1b,0x63,0x02,0x21,0x74,0x41,0xfc,0x20,0x14,
};
static const uint8_t kTestD1[64] = {0};
static const uint8_t kTestGenX[32] = {
    0x34,0xc3,0xa8,0xbf,0xb3,0xb7,0x73,0x97,0x89,0x06,0x6b,
    0xf3,0xb2,0xc0,0xc0,0x6e,0xf3,0x8b,0x6c,0xdb,0x58,0xce,
    0x28,0x16,0x46,0xc5,0xcd,0xfa,0x6a,0x1a,0x55,0xb5,
};
static const uint8_t kTestGenY[32] = {
    0x2e,0x8c,0x00,0x9e,0x58,0x70,0x70,0xa8,0x24,0x69,0x9c,
    0xab,0xd0,0x11,0x7a,0x7f,0xfa,0x17,0x3a,0xb5,0xea,0x09,
    0xdd,0x43,0x43,0xc1,0x31,0x1f,0x97,0xc6,0xa1,0x42,
};

/* ---- mlkem768_keypair — ONLY declared, NEVER used ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);
static const otbn_app_t kAppMlkem = OTBN_APP_T_INIT(mlkem768_keypair);

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kTestOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Step 1: load p256_ecdh...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch! hw=0x%08x exp=0x%08x", hw_cs, kChecksum);
  LOG_INFO("Load OK");

  LOG_INFO("Step 2: write d0[64], d1[64], x[32], y[32]...");
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestD0), kTestD0, kD0));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestD1), kTestD1, kD1));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestGenX), kTestGenX, kX));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestGenY), kTestGenY, kY));
  LOG_INFO("Write OK");

  LOG_INFO("Step 3: EXECUTE...");
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));
  LOG_INFO("Execute OK");

  uint32_t share0[8], share1[8];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kX, share0));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kY, share1));

  uint8_t pk_e[64];
  for (int i = 0; i < 8; i++) ((uint32_t *)pk_e)[i] = share0[i] ^ share1[i];
  for (int i = 8; i < 16; i++) ((uint32_t *)pk_e)[i] = 0;

  LOG_INFO("=== P-256 KeyGen output: pk_e[64] ===");
  LOG_INFO("  pk_e[ 0.. 7]=%02x%02x%02x%02x%02x%02x%02x%02x",
           pk_e[0],pk_e[1],pk_e[2],pk_e[3],pk_e[4],pk_e[5],pk_e[6],pk_e[7]);
  LOG_INFO("  pk_e[24..31]=%02x%02x%02x%02x%02x%02x%02x%02x",
           pk_e[24],pk_e[25],pk_e[26],pk_e[27],pk_e[28],pk_e[29],pk_e[30],pk_e[31]);

  /* ============================================================
   * Step 2: ML-KEM-768 KeyGen (inline) — extra test_main size
   * ============================================================ */
  LOG_INFO("Step 2: ML-KEM-768 KeyGen...");

  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppMlkem));
  static const uint8_t kCoins[64] = {
      0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,0x61,0x60,0x45,
      0x50,0x76,0x05,0x85,0x3e,0xd7,0x3b,0x80,0x93,0xf6,0xef,
      0xbc,0x88,0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26,0x3c,
      0xb1,0xee,0xa9,0x88,0x00,0x4b,0x93,0x10,0x3c,0xfb,0x0a,
      0xee,0xfd,0x2a,0x68,0x6e,0x01,0xfa,0x4a,0x58,0xe8,0xa3,
      0x63,0x9c,0xa8,0xa1,0xe3,0xf9,0xae,0x57,0xe2,
  };
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kCoins), kCoins,
      OTBN_ADDR_T_INIT(mlkem768_keypair, coins)));

  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));

  static uint8_t pk_m[1184], sk_m[2400];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(pk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, ek), pk_m));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(sk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, dk), sk_m));
  LOG_INFO("=== ML-KEM KeyGen output ===");
  LOG_INFO("  pk_m[   0..   7]=%02x%02x%02x%02x%02x%02x%02x%02x",
           pk_m[0],pk_m[1],pk_m[2],pk_m[3],pk_m[4],pk_m[5],pk_m[6],pk_m[7]);
  LOG_INFO("  pk_m[1176..1183]=%02x%02x%02x%02x%02x%02x%02x%02x",
           pk_m[1176],pk_m[1177],pk_m[1178],pk_m[1179],pk_m[1180],pk_m[1181],pk_m[1182],pk_m[1183]);
  LOG_INFO("  sk_m[   0..   7]=%02x%02x%02x%02x%02x%02x%02x%02x",
           sk_m[0],sk_m[1],sk_m[2],sk_m[3],sk_m[4],sk_m[5],sk_m[6],sk_m[7]);
  LOG_INFO("  sk_m[2392..2399]=%02x%02x%02x%02x%02x%02x%02x%02x",
           sk_m[2392],sk_m[2393],sk_m[2394],sk_m[2395],sk_m[2396],sk_m[2397],sk_m[2398],sk_m[2399]);

  return true;
}
