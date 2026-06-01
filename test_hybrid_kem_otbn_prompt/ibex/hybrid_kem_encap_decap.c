/**
 * @file
 * @brief Hybrid KEM Phase 2: Encaps + Decaps per hybrid_kem_otbn_prompt.md §2.2
 *
 * Encaps (Alice):
 *   Step 1: P-256 ephemeral keygen (d_eph*G) → ek
 *   Step 2: P-256 ECDH (d_eph * pk_e_Bob) → ss_e
 *   Step 3: ML-KEM-768 Encap(pk_m_Bob) → ct_m, ss_m
 *   Step 4: HKDF-SHA3-256(role="initiator") → okm
 *
 * Decaps (Bob):
 *   Step 5: P-256 ECDH (sk_e_Bob * ek_Alice) → ss_e
 *   Step 6: ML-KEM-768 Decap(sk_m_Bob, ct_m) → ss_m
 *   Step 7: HKDF-SHA3-256(role="responder") → okm_dec
 *   Verify: okm == okm_dec
 *
 * Note: Hardcoded test vectors from keygen output for standalone testing.
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

/* ---- mlkem768_encap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_encap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, coins);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ek);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_encap, _checksum);
static const otbn_app_t kAppEnc = OTBN_APP_T_INIT(mlkem768_encap);

/* ---- mlkem768_decap ---- */
OTBN_DECLARE_APP_SYMBOLS(mlkem768_decap);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ct);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, dk);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, ss);
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_decap, _checksum);
static const otbn_app_t kAppDec = OTBN_APP_T_INIT(mlkem768_decap);

/* ---- p256_ecdh ---- */
OTBN_DECLARE_APP_SYMBOLS(p256_ecdh);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdh, _checksum);
static const otbn_app_t kAppP256 = OTBN_APP_T_INIT(p256_ecdh);

/* ---- hkdf_sha3_256 ---- */
OTBN_DECLARE_APP_SYMBOLS(hkdf_sha3_256);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_salt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, ikm_prebuilt);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, input_lengths);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, output_okm);
OTBN_DECLARE_SYMBOL_ADDR(hkdf_sha3_256, _checksum);
static const otbn_app_t kAppHkdf = OTBN_APP_T_INIT(hkdf_sha3_256);

/* Dummy keygen outputs — replace with real values from Phase 1 */
static const uint8_t kPkM[1184] = {0};
static const uint8_t kSkM[2400] = {0};
static const uint8_t kSkE[32] = {0};
static const uint8_t kPkE[64] = {0};

static const uint8_t kEncCoins[32] = {
    0x35,0xb8,0xcc,0x87,0x3c,0x23,0xdc,0x62,0xb8,0xd2,0x60,
    0x16,0x9a,0xfa,0x2f,0x75,0xab,0x91,0x6a,0x58,0xd9,0x74,
    0x91,0x88,0x35,0xd2,0x5e,0x6a,0x43,0x50,0x85,0xb2,
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

static void p256_ecdh(dif_otbn_t *otbn, const uint8_t *d0, const uint8_t *d1,
                      const uint8_t *px, const uint8_t *py, uint8_t *rx) {
  CHECK_STATUS_OK(otbn_testutils_load_app(otbn, kAppP256));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 64, d0, OTBN_ADDR_T_INIT(p256_ecdh, d0)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 64, d1, OTBN_ADDR_T_INIT(p256_ecdh, d1)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 32, px, OTBN_ADDR_T_INIT(p256_ecdh, x)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 32, py, OTBN_ADDR_T_INIT(p256_ecdh, y)));
  CHECK_STATUS_OK(otbn_testutils_execute(otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));
  uint32_t s0[8], s1[8];
  CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32, OTBN_ADDR_T_INIT(p256_ecdh, x), s0));
  CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32, OTBN_ADDR_T_INIT(p256_ecdh, y), s1));
  for (int i = 0; i < 8; i++) ((uint32_t *)rx)[i] = s0[i] ^ s1[i];
  memset(rx + 32, 0, 32);
}

static void hkdf_derive(dif_otbn_t *otbn, const uint8_t *ss_e, const uint8_t *ss_m,
                        const char *role, size_t role_len, uint8_t *okm) {
  static uint8_t ikm[256];
  memset(ikm, 0, sizeof(ikm));
  size_t off = 0;
  ikm[off++] = 0x00; ikm[off++] = 0x20; memcpy(&ikm[off], ss_e, 32); off += 32;
  ikm[off++] = 0x00; ikm[off++] = 0x20; memcpy(&ikm[off], ss_m, 32); off += 32;
  memcpy(&ikm[off], role, role_len); off += role_len;
  size_t ikm_len = (off + 3) & ~(size_t)3;
  uint32_t lens[4] = {0, 0, (uint32_t)role_len, 32};
  uint8_t salt[32] = {0};
  CHECK_STATUS_OK(otbn_testutils_load_app(otbn, kAppHkdf));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, 32, salt, OTBN_ADDR_T_INIT(hkdf_sha3_256, input_salt)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, ikm_len, ikm, OTBN_ADDR_T_INIT(hkdf_sha3_256, ikm_prebuilt)));
  CHECK_STATUS_OK(otbn_testutils_write_data(otbn, sizeof(lens), lens, OTBN_ADDR_T_INIT(hkdf_sha3_256, input_lengths)));
  CHECK_STATUS_OK(otbn_testutils_execute(otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(otbn, kDifOtbnErrBitsNoError));
  CHECK_STATUS_OK(otbn_testutils_read_data(otbn, 32, OTBN_ADDR_T_INIT(hkdf_sha3_256, output_okm), okm));
}

bool test_main(void) {
  dif_otbn_t otbn;
  CHECK_DIF_OK(dif_otbn_init_from_dt(kDtOtbn, &otbn));
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  /* ================================================================
   * ENCAPS
   * ================================================================ */
  LOG_INFO("=== ENCAPS ===");

  /* Step 1: P-256 ephemeral keygen (d_eph * G) → ek */
  LOG_INFO("Step 1: P-256 ephemeral keygen...");
  static uint8_t ek[64];
  p256_ecdh(&otbn, kP256D0, kP256D1, kP256Gx, kP256Gy, ek);
  LOG_INFO("Step 1 OK");

  /* Step 2: P-256 ECDH (d_eph * pk_e_Bob) → ss_e */
  LOG_INFO("Step 2: P-256 ECDH...");
  static uint8_t ss_e[32];
  p256_ecdh(&otbn, kP256D0, kP256D1, kPkE, kPkE + 32, ss_e);
  LOG_INFO("Step 2 OK");

  /* Step 3: ML-KEM-768 Encap */
  LOG_INFO("Step 3: ML-KEM Encap...");
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppEnc));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kPkM), kPkM, OTBN_ADDR_T_INIT(mlkem768_encap, ek)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kEncCoins), kEncCoins, OTBN_ADDR_T_INIT(mlkem768_encap, coins)));
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));
  static uint8_t ct_m[1088], ss_m[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ct_m), OTBN_ADDR_T_INIT(mlkem768_encap, ct), ct_m));
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ss_m), OTBN_ADDR_T_INIT(mlkem768_encap, ss), ss_m));
  LOG_INFO("Step 3 OK");

  /* Step 4: HKDF (role=initiator) */
  LOG_INFO("Step 4: HKDF initiator...");
  static uint8_t okm_enc[32];
  hkdf_derive(&otbn, ss_e, ss_m, "initiator", 9, okm_enc);
  LOG_INFO("Step 4 OK: okm_enc[0]=0x%02x", okm_enc[0]);

  /* ================================================================
   * DECAPS
   * ================================================================ */
  LOG_INFO("=== DECAPS ===");

  /* Step 5: P-256 ECDH (sk_e_Bob * ek_Alice) → ss_e */
  LOG_INFO("Step 5: P-256 ECDH...");
  static uint8_t ss_e_dec[32];
  p256_ecdh(&otbn, kSkE, kP256D1, ek, ek + 32, ss_e_dec);
  LOG_INFO("Step 5 OK");

  /* Step 6: ML-KEM-768 Decap */
  LOG_INFO("Step 6: ML-KEM Decap...");
  CHECK_STATUS_OK(otbn_testutils_load_app(&otbn, kAppDec));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(kSkM), kSkM, OTBN_ADDR_T_INIT(mlkem768_decap, dk)));
  CHECK_STATUS_OK(otbn_testutils_write_data(&otbn, sizeof(ct_m), ct_m, OTBN_ADDR_T_INIT(mlkem768_decap, ct)));
  CHECK_STATUS_OK(otbn_testutils_execute(&otbn));
  CHECK_STATUS_OK(otbn_testutils_wait_for_done(&otbn, kDifOtbnErrBitsNoError));
  static uint8_t ss_m_dec[32];
  CHECK_STATUS_OK(otbn_testutils_read_data(&otbn, sizeof(ss_m_dec), OTBN_ADDR_T_INIT(mlkem768_decap, ss), ss_m_dec));
  LOG_INFO("Step 6 OK");

  /* Step 7: HKDF (role=responder) + verify */
  LOG_INFO("Step 7: HKDF responder...");
  static uint8_t okm_dec[32];
  hkdf_derive(&otbn, ss_e_dec, ss_m_dec, "responder", 10, okm_dec);
  LOG_INFO("Step 7 OK: okm_dec[0]=0x%02x", okm_dec[0]);

  CHECK(memcmp(okm_enc, okm_dec, 32) == 0, "Round-trip FAIL");
  return true;
}
