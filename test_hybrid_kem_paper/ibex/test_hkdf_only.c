/**
 * @file test_hkdf_only.c
 * @brief Standalone HKDF-SHA3-256 chip sim test.
 */
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include <string.h>

OTTF_DEFINE_TEST_CONFIG();

OTBN_DECLARE_APP_SYMBOLS(hkdf_sha3_256);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_salt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, ikm_prebuilt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_lengths);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, output_okm);
static const otbn_app_t kApp = OTBN_APP_T_INIT(hkdf_sha3_256);

static const uint8_t kKatPkE[32] = {
    0x5f, 0x33, 0xd7, 0x46, 0xa3, 0x26, 0x64, 0x0a, 0x73, 0x9a, 0x94, 0x90, 0xec, 0x15, 0xc1, 0x03,
    0x72, 0x86, 0x9f, 0x3d, 0xe6, 0x75, 0xb2, 0xe8, 0x57, 0x42, 0x27, 0x1d, 0x18, 0xc9, 0xeb, 0x82,
};

static const uint8_t kKatSsM[32] = {
    0x37, 0x50, 0xac, 0x4a, 0x8e, 0x65, 0x63, 0x27, 0xc3, 0xd1, 0x81, 0xfa, 0xb0, 0x02, 0x55, 0x4b,
    0xf6, 0xd2, 0xbe, 0x04, 0x75, 0xdd, 0x28, 0xd5, 0xf3, 0x1b, 0xef, 0x9f, 0x83, 0x5f, 0x86, 0xac,
};

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Load hkdf_sha3_256...");
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));

  uint8_t salt[32] = {0};
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, salt,
      OTBN_ADDR_T_INIT(hkdf_sha3_256, input_salt)));

  /* Build IKM: len_cls(2B)||ss_e(32B)||len_pqc(2B)||ss_m(32B)||initiator */
  uint8_t ikm[256] = {0};
  size_t off = 0;
  ikm[off++] = 0x00; ikm[off++] = 0x20;
  memcpy(ikm + off, kKatPkE, 32); off += 32;
  ikm[off++] = 0x00; ikm[off++] = 0x20;
  memcpy(ikm + off, kKatSsM, 32); off += 32;
  memcpy(ikm + off, "initiator", 9); off += 9;
  size_t ikm_len = (off + 3) & ~(size_t)3;

  uint32_t lens[4] = {0, 0, 9, 32};
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, ikm_len, ikm,
      OTBN_ADDR_T_INIT(hkdf_sha3_256, ikm_prebuilt)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(lens), lens,
      OTBN_ADDR_T_INIT(hkdf_sha3_256, input_lengths)));

  LOG_INFO("Execute...");
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));

  static uint8_t okm[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(okm),
      OTBN_ADDR_T_INIT(hkdf_sha3_256, output_okm), okm));

static const uint8_t kExpectedOkmInitiator[32] = {
    0xea, 0x3b, 0x25, 0x51, 0xa5, 0x48, 0xe9, 0xeb, 0xbd, 0xac, 0x90, 0xc1, 0x59, 0x6a, 0x92, 0x58,
    0xc0, 0x3b, 0x45, 0x39, 0x01, 0x34, 0xe3, 0x39, 0xba, 0x71, 0x81, 0x7f, 0x93, 0x96, 0xd0, 0x1e,
};

  CHECK_ARRAYS_EQ(okm, kExpectedOkmInitiator, sizeof(kExpectedOkmInitiator));

  LOG_INFO("=== HKDF OK ===");
  LOG_INFO("okm[ 0.. 7]=%02x%02x%02x%02x%02x%02x%02x%02x",
           okm[0],okm[1],okm[2],okm[3],okm[4],okm[5],okm[6],okm[7]);
  LOG_INFO("okm[24..31]=%02x%02x%02x%02x%02x%02x%02x%02x",
           okm[24],okm[25],okm[26],okm[27],okm[28],okm[29],okm[30],okm[31]);

  return true;
}
