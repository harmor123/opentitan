/**
 * @file
 * @brief Test: HKDF-SHA3-256 only.
 */

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

/* ---- hkdf_sha3_256 ---- */
OTBN_DECLARE_APP_SYMBOLS(hkdf_sha3_256);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_salt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, ikm_prebuilt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_lengths);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, output_okm);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, _checksum);

static const otbn_app_t kApp = OTBN_APP_T_INIT(hkdf_sha3_256);
static const otbn_addr_t kSalt   = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_salt);
static const otbn_addr_t kIkm    = OTBN_ADDR_T_INIT(hkdf_sha3_256, ikm_prebuilt);
static const otbn_addr_t kLengths = OTBN_ADDR_T_INIT(hkdf_sha3_256, input_lengths);
static const otbn_addr_t kOutput = OTBN_ADDR_T_INIT(hkdf_sha3_256, output_okm);
static const uint32_t kChecksum = OTBN_ADDR_T_INIT(hkdf_sha3_256, _checksum);

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Step 1: load hkdf_sha3_256...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch! hw=0x%08x exp=0x%08x", hw_cs, kChecksum);
  LOG_INFO("Load OK");

  LOG_INFO("Step 2: write salt[32], ikm, lengths...");
  uint8_t salt[32] = {0};
  uint8_t ikm[256] = {0};
  /* IKM: be16(32)+32B_zero + be16(32)+32B_zero = 68B, pad to 4B */
  ikm[0] = 0x00; ikm[1] = 0x20;  /* be16(32) for ss_e */
  ikm[34] = 0x00; ikm[35] = 0x20; /* be16(32) for ss_m */
  uint32_t lens[4] = {0, 0, 9, 32}; /* ctx=0, sid=0, role_len=9, okm_len=32 */
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(salt), salt, kSalt));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 72, ikm, kIkm));  /* 68B rounded to 72 */
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(lens), lens, kLengths));
  /* Write role string at lengths+16 */
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 12, "initiator\0\0", kLengths + 16));
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

  uint8_t okm[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(okm), kOutput, okm));
  LOG_INFO("HKDF-SHA3-256 OK: okm[0]=0x%02x", okm[0]);

  return true;
}
