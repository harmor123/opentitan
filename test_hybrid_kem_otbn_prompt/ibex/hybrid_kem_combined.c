/**
 * @file Hybrid KEM — single combined OTBN binary, P-256 only test.
 *
 * Follows otbn_smoketest.c pattern: void helpers, CHECK macros, static buffers.
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

OTBN_DECLARE_APP_SYMBOLS(hybrid_kem_all);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, d0);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, d1);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, x);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, y);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, mode);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, _checksum);
OTBN_DECLARE_SYMBOL_ADDR(hybrid_kem_all, p256_p);

static const otbn_app_t kApp           = OTBN_APP_T_INIT(hybrid_kem_all);
static const otbn_addr_t kP256P        = OTBN_ADDR_T_INIT(hybrid_kem_all, p256_p);
static const uint32_t   kChecksum      = OTBN_ADDR_T_INIT(hybrid_kem_all, _checksum);
static const otbn_addr_t kModeAddr     = OTBN_ADDR_T_INIT(hybrid_kem_all, mode);
static const otbn_addr_t kP256D0Addr   = OTBN_ADDR_T_INIT(hybrid_kem_all, d0);
static const otbn_addr_t kP256D1Addr   = OTBN_ADDR_T_INIT(hybrid_kem_all, d1);
static const otbn_addr_t kP256XAddr    = OTBN_ADDR_T_INIT(hybrid_kem_all, x);
static const otbn_addr_t kP256YAddr    = OTBN_ADDR_T_INIT(hybrid_kem_all, y);

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
static const uint32_t kModeP256 = 0;

static void otbn_run(dif_otbn_t *otbn, uint32_t mode, const otbn_addr_t p256_p_addr) {
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 4, &mode, kModeAddr));
  /* Check if mode write corrupted p256_p */
  if (mode == 0) {
    uint32_t pv[8];
    CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32, p256_p_addr, pv));
    LOG_INFO("After mode write: p256_p[0]=0x%08x [7]=0x%08x", pv[0], pv[7]);
  }
  CHECK_STATUS_OK(otbn_testutils_execute(otbn));
  dif_otbn_status_t st;
  do {
    CHECK_DIF_OK(dif_otbn_get_status(otbn, &st));
  } while (st != kDifOtbnStatusIdle && st != kDifOtbnStatusLocked);
  dif_otbn_err_bits_t errs;
  CHECK_DIF_OK(dif_otbn_get_err_bits(otbn, &errs));
  LOG_INFO("Mode %lu done: status=0x%x err_bits=0x%08x", mode, st, errs);
  if (st == kDifOtbnStatusLocked) {
    LOG_ERROR("OTBN LOCKED! err_bits=0x%08x", errs);
    CHECK(false);
  }
  CHECK(errs == kDifOtbnErrBitsNoError, "Unexpected err_bits=0x%08x for mode %lu", errs, mode);
}

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  LOG_INFO("Loading hybrid_kem_all...");
  CHECK_DIF_OK(dif_otbn_clear_load_checksum(&otbn));
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kApp));
  uint32_t hw_cs;
  CHECK_DIF_OK(dif_otbn_get_load_checksum(&otbn, &hw_cs));
  CHECK(hw_cs == kChecksum, "Checksum mismatch hw=0x%08x exp=0x%08x", hw_cs, kChecksum);
  LOG_INFO("Load OK");

  /* Check p256_p integrity after load but before execution */
  {
    uint32_t pval[8];
    CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kP256P, pval));
    LOG_INFO("p256_p[0]=0x%08x [7]=0x%08x (expect ffffffff ... ffffffff)", pval[0], pval[7]);
  }

  LOG_INFO("=== P-256 KeyGen (mode 0) ===");
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kP256D0, kP256D0Addr));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 64, kP256D1, kP256D1Addr));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kP256Gx, kP256XAddr));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, 32, kP256Gy, kP256YAddr));
  otbn_run(&otbn, kModeP256, kP256P);
  uint32_t s0[8], s1[8];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kP256XAddr, s0));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, 32, kP256YAddr, s1));
  LOG_INFO("s0[0]=0x%08x s1[0]=0x%08x", s0[0], s1[0]);

  return true;
}
