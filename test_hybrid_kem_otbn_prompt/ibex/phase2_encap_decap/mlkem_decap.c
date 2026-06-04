/**
 * @file
 * @brief Test: ML-KEM-768 Decap only.
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ---- mlkem768_decap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_decap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, _checksum);

static const otbn_app_t kApp = OTBN_APP_T_INIT(mlkem768_decap);
static const otbn_addr_t kCt = OTBN_ADDR_T_INIT(mlkem768_decap, ct);
static const otbn_addr_t kDk = OTBN_ADDR_T_INIT(mlkem768_decap, dk);
static const otbn_addr_t kSs = OTBN_ADDR_T_INIT(mlkem768_decap, ss);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(mlkem768_decap, _checksum);

/* Dummy test data for standalone verification */
static const uint8_t kTestDk[2400] = {0};
static const uint8_t kTestCt[1088] = {0};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Step 1: load mlkem768_decap...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch! hw=0x%08x exp=0x%08x", hw_cs, kChecksum);
  LOG_INFO("Load OK");

  LOG_INFO("Step 2: write dk[2400], ct[1088]...");
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestDk), kTestDk, kDk));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestCt), kTestCt, kCt));
  LOG_INFO("Write OK");

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
  LOG_INFO("Execute OK");

  uint8_t ss[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ss), kSs, ss));
  LOG_INFO("ML-KEM Decap OK: ss[0]=0x%02x", ss[0]);

  return true;
}
