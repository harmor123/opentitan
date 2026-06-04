/**
 * @file
 * @brief Test: P-256 ECDH scalar multiplication (d*G).
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

static const otbn_app_t kApp = OTBN_APP_T_INIT(p256_ecdh);
static const otbn_addr_t kD0 = OTBN_ADDR_T_INIT(p256_ecdh, d0);
static const otbn_addr_t kD1 = OTBN_ADDR_T_INIT(p256_ecdh, d1);
static const otbn_addr_t kX = OTBN_ADDR_T_INIT(p256_ecdh, x);
static const otbn_addr_t kY = OTBN_ADDR_T_INIT(p256_ecdh, y);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(p256_ecdh, _checksum);

static const uint8_t kTestD0[64] = {
    0x71, 0x10, 0x6d, 0xfe, 0x16, 0xa0, 0xd0, 0x21, 0x81, 0xc7, 0xb2,
    0xb0, 0x5d, 0xef, 0x90, 0x95, 0x79, 0xa3, 0xdf, 0x3f, 0xe8, 0xeb,
    0x76, 0x1b, 0x63, 0x02, 0x21, 0x74, 0x41, 0xfc, 0x20, 0x14,
};
static const uint8_t kTestD1[64] = {0};
static const uint8_t kTestGenX[32] = {
    0x34, 0xc3, 0xa8, 0xbf, 0xb3, 0xb7, 0x73, 0x97, 0x89, 0x06, 0x6b,
    0xf3, 0xb2, 0xc0, 0xc0, 0x6e, 0xf3, 0x8b, 0x6c, 0xdb, 0x58, 0xce,
    0x28, 0x16, 0x46, 0xc5, 0xcd, 0xfa, 0x6a, 0x1a, 0x55, 0xb5,
};
static const uint8_t kTestGenY[32] = {
    0x2e, 0x8c, 0x00, 0x9e, 0x58, 0x70, 0x70, 0xa8, 0x24, 0x69, 0x9c,
    0xab, 0xd0, 0x11, 0x7a, 0x7f, 0xfa, 0x17, 0x3a, 0xb5, 0xea, 0x09,
    0xdd, 0x43, 0x43, 0xc1, 0x31, 0x1f, 0x97, 0xc6, 0xa1, 0x42,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
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

  uint8_t result_x[32];
  for (int i = 0; i < 8; i++) {
    ((uint32_t *)result_x)[i] = share0[i] ^ share1[i];
  }
  LOG_INFO("P-256 ECDH OK: result_x[0]=0x%02x", result_x[0]);

  return true;
}
