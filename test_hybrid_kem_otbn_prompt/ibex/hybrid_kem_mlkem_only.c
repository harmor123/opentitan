/**
 * @file
 * @brief Test: load + execute mlkem768_keypair ONLY (isolates
 * phase_mlkem_keypair).
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ---- mlkem768_keypair ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_keypair);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, _checksum);

static const otbn_app_t kApp = OTBN_APP_T_INIT(mlkem768_keypair);
static const otbn_addr_t kCoins = OTBN_ADDR_T_INIT(mlkem768_keypair, coins);
static const otbn_addr_t kEk = OTBN_ADDR_T_INIT(mlkem768_keypair, ek);
static const otbn_addr_t kDk = OTBN_ADDR_T_INIT(mlkem768_keypair, dk);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(mlkem768_keypair, _checksum);

static const uint8_t kTestCoins[64] = {
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45,
    0x50, 0x76, 0x05, 0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef,
    0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26, 0x3c,
    0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93, 0x10, 0x3c, 0xfb, 0x0a,
    0xee, 0xfd, 0x2a, 0x68, 0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3,
    0x63, 0x9c, 0xa8, 0xa1, 0xe3, 0xf9, 0xae, 0x57, 0xe2,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  /* ===== Load ===== */
  LOG_INFO("Step 1: load mlkem768_keypair...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch! hw=0x%08x exp=0x%08x", hw_cs,
        kChecksum);
  LOG_INFO("Load PASS");

  /* ===== Write coins ===== */
  LOG_INFO("Step 2: write coins[64]...");
  CHECK_STATUS_OK(
      otbn_testutils_write_data(&otbn, sizeof(kTestCoins), kTestCoins, kCoins));
  LOG_INFO("Write PASS");

  /* ===== Execute ===== */
  LOG_INFO("Step 3: EXECUTE...");
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));

  dif_otbn_status_t st;
  do {
    CHECK_DIF_OK(dif_otbn_get_status(&otbn, &st));
  } while (st == kDifOtbnStatusBusyExecute ||
           st == kDifOtbnStatusBusySecWipeDmem ||
           st == kDifOtbnStatusBusySecWipeImem);

  if (st == kDifOtbnStatusLocked) {
    dif_otbn_err_bits_t errs;
    CHECK_DIF_OK(dif_otbn_get_err_bits(&otbn, &errs));
    LOG_ERROR("OTBN LOCKED! err_bits=0x%08x", errs);
    return false;
  }
  CHECK(st == kDifOtbnStatusIdle, "OTBN not idle");
  LOG_INFO("Execute PASS");

  /* ===== Read outputs ===== */
  uint8_t pk[1184], sk[2400];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(pk), kEk, pk));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(sk), kDk, sk));
  LOG_INFO("ML-KEM keypair OK: pk[0]=0x%02x sk[0]=0x%02x", pk[0], sk[0]);

  return true;
}
