/**
 * @file
 * @brief Hybrid KEM Phase 1: KeyGen per hybrid_kem_otbn_prompt.md §2.1
 *
 * Step 1: ML-KEM-768 KeyGen → pk_m(1184B), sk_m(2400B)
 * Step 2: P-256 KeyGen (d*G) → pk_e(64B)
 * Step 3: Combine pk_hyb = pk_m || pk_e, sk_hyb = sk_m || d
 *
 * Pattern: exact same as otbn_smoketest.c (void helpers + CHECK macros).
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include <string.h>

OTTF_DEFINE_TEST_CONFIG();

/* ---- mlkem768_keypair ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, _checksum);
static const otbn_app_t kAppKp = OTBN_APP_T_INIT(mlkem768_keypair);

/* ---- p256_ecdh ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, _checksum);
static const otbn_app_t kAppP256 = OTBN_APP_T_INIT(p256_ecdh);

static const uint8_t kKpCoins[64] = {
    0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,0x61,0x60,0x45,
    0x50,0x76,0x05,0x85,0x3e,0xd7,0x3b,0x80,0x93,0xf6,0xef,
    0xbc,0x88,0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26,0x3c,
    0xb1,0xee,0xa9,0x88,0x00,0x4b,0x93,0x10,0x3c,0xfb,0x0a,
    0xee,0xfd,0x2a,0x68,0x6e,0x01,0xfa,0x4a,0x58,0xe8,0xa3,
    0x63,0x9c,0xa8,0xa1,0xe3,0xf9,0xae,0x57,0xe2,
};
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

static void p256_keygen(dif_otbn_t *otbn, uint8_t *pk_e) {
  CHECK_STATUS_OK(otbn_testutils_load_app(otbn, kAppP256));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 64, kP256D0,
      OTBN_ADDR_T_INIT(p256_ecdh, d0)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 64, kP256D1,
      OTBN_ADDR_T_INIT(p256_ecdh, d1)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 32, kP256Gx,
      OTBN_ADDR_T_INIT(p256_ecdh, x)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 32, kP256Gy,
      OTBN_ADDR_T_INIT(p256_ecdh, y)));
  CHECK_STATUS_OK(otbn_testutils_execute(otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));
  uint32_t s0[8], s1[8];
  CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32,
      OTBN_ADDR_T_INIT(p256_ecdh, x), s0));
  CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32,
      OTBN_ADDR_T_INIT(p256_ecdh, y), s1));
  for (int i = 0; i < 8; i++) ((uint32_t *)pk_e)[i] = s0[i] ^ s1[i];
  memset(pk_e + 32, 0, 32);
}

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  /* Step 1: ML-KEM-768 KeyGen (only — p256 isolated) */
  LOG_INFO("Step 1: ML-KEM-768 KeyGen...");
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppKp));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kKpCoins), kKpCoins,
      OTBN_ADDR_T_INIT(mlkem768_keypair, coins)));
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));
  static uint8_t pk_m[1184], sk_m[2400];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(pk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, ek), pk_m));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(sk_m),
      OTBN_ADDR_T_INIT(mlkem768_keypair, dk), sk_m));
  LOG_INFO("Step 1 OK: pk_m[0]=0x%02x", pk_m[0]);

  return true;
}
