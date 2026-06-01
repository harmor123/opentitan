/**
 * @file
 * @brief Test: ML-KEM-768 Encap only.
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ---- mlkem768_encap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_encap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, _checksum);

static const otbn_app_t kApp = OTBN_APP_T_INIT(mlkem768_encap);
static const otbn_addr_t kCoins = OTBN_ADDR_T_INIT(mlkem768_encap, coins);
static const otbn_addr_t kEk    = OTBN_ADDR_T_INIT(mlkem768_encap, ek);
static const otbn_addr_t kCt    = OTBN_ADDR_T_INIT(mlkem768_encap, ct);
static const otbn_addr_t kSs    = OTBN_ADDR_T_INIT(mlkem768_encap, ss);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(mlkem768_encap, _checksum);

/* Hardcoded test public key (from keypair test output) — dummy for standalone */
static const uint8_t kTestEk[1184] = {0};
static const uint8_t kTestCoins[32] = {
    0x35, 0xb8, 0xcc, 0x87, 0x3c, 0x23, 0xdc, 0x62, 0xb8, 0xd2, 0x60,
    0x16, 0x9a, 0xfa, 0x2f, 0x75, 0xab, 0x91, 0x6a, 0x58, 0xd9, 0x74,
    0x91, 0x88, 0x35, 0xd2, 0x5e, 0x6a, 0x43, 0x50, 0x85, 0xb2,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Step 1: load mlkem768_encap...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch! hw=0x%08x exp=0x%08x", hw_cs, kChecksum);
  LOG_INFO("Load PASS");

  LOG_INFO("Step 2: write ek[1184], coins[32]...");
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestEk), kTestEk, kEk));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kTestCoins), kTestCoins, kCoins));
  LOG_INFO("Write PASS");

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

  uint8_t ct[1088], ss[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ct), kCt, ct));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ss), kSs, ss));
  LOG_INFO("ML-KEM Encap OK: ct[0]=0x%02x ss[0]=0x%02x", ct[0], ss[0]);

  return true;
}
