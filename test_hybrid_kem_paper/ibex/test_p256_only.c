/**
 * @file test_p256_only.c
 * @brief Standalone P-256 ECDH chip sim test with self-contained binary.
 *
 * Follows official otbn_ecdsa_op_irq_test.c pattern:
 *   load → write data → execute → wait_for_done
 */
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

OTBN_DECLARE_APP_SYMBOLS(p256_ecdh_shared_key);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh_shared_key, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh_shared_key, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh_shared_key, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh_shared_key, y);
static const otbn_app_t kApp = OTBN_APP_T_INIT(p256_ecdh_shared_key);

static const uint8_t kD0[64] = {
    0x71,0x10,0x6d,0xfe,0x16,0xa0,0xd0,0x21,0x81,0xc7,0xb2,0xb0,0x5d,0xef,0x90,0x95,
    0x79,0xa3,0xdf,0x3f,0xe8,0xeb,0x76,0x1b,0x63,0x02,0x21,0x74,0x41,0xfc,0x20,0x14,
};
static const uint8_t kD1[64] = {0};
static const uint8_t kGx[32] = {
    0x34,0xc3,0xa8,0xbf,0xb3,0xb7,0x73,0x97,0x89,0x06,0x6b,0xf3,0xb2,0xc0,0xc0,0x6e,
    0xf3,0x8b,0x6c,0xdb,0x58,0xce,0x28,0x16,0x46,0xc5,0xcd,0xfa,0x6a,0x1a,0x55,0xb5,
};
static const uint8_t kGy[32] = {
    0x2e,0x8c,0x00,0x9e,0x58,0x70,0x70,0xa8,0x24,0x69,0x9c,0xab,0xd0,0x11,0x7a,0x7f,
    0xfa,0x17,0x3a,0xb5,0xea,0x09,0xdd,0x43,0x43,0xc1,0x31,0x1f,0x97,0xc6,0xa1,0x42,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Load p256_ecdh_shared_key...");
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  LOG_INFO("Write inputs...");
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kD0,
      OTBN_ADDR_T_INIT(p256_ecdh_shared_key, d0)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kD1,
      OTBN_ADDR_T_INIT(p256_ecdh_shared_key, d1)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kGx,
      OTBN_ADDR_T_INIT(p256_ecdh_shared_key, x)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kGy,
      OTBN_ADDR_T_INIT(p256_ecdh_shared_key, y)));

  LOG_INFO("Execute...");
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));

  LOG_INFO("P-256 Exec OK");

  return true;
}
