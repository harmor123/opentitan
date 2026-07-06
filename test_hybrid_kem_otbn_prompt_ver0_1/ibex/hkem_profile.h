/**
 * @file hkem_profile.h
 * @brief Lightweight Hybrid KEM profiling helpers for Ibex-side tests.
 *
 * This profiling is static instrumentation for Hybrid KEM phase and OTBN
 * application-boundary timing. The local repository may not be runnable; these
 * changes are intended to be copied to the remote server for execution.
 * Profiling can be disabled by setting HYBRID_KEM_ENABLE_PROFILING to 0.
 *
 * App/phase labels emitted by these helpers include:
 *   HKEM_PHASE_BOB_SETUP_TOTAL
 *   HKEM_PHASE_ALICE_ENCAP_TOTAL
 *   HKEM_PHASE_BOB_DECAP_TOTAL
 *   HKEM_BOB_SETUP_P256_APP
 *   HKEM_BOB_SETUP_MLKEM_APP
 *   HKEM_ALICE_ENCAP_P256_KEYGEN_APP
 *   HKEM_ALICE_ENCAP_P256_ECDH_APP
 *   HKEM_ALICE_ENCAP_MLKEM_ENCAP_APP
 *   HKEM_ALICE_ENCAP_KDF_APP
 *   HKEM_BOB_DECAP_P256_ECDH_APP
 *   HKEM_BOB_DECAP_MLKEM_DECAP_APP
 *   HKEM_BOB_DECAP_KDF_APP
 */
#ifndef TEST_HYBRID_KEM_OTBN_PROMPT_VER0_1_IBEX_HKEM_PROFILE_H_
#define TEST_HYBRID_KEM_OTBN_PROMPT_VER0_1_IBEX_HKEM_PROFILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/profile.h"
#include "sw/device/lib/testing/test_framework/check.h"

#ifndef HYBRID_KEM_ENABLE_PROFILING
#define HYBRID_KEM_ENABLE_PROFILING 1
#endif

typedef struct hkem_profile_entry {
  const char *step;
  uint32_t cycles;
  bool is_test;
} hkem_profile_entry_t;

static inline bool hkem_profile_streq(const char *a, const char *b) {
  while (*a != '\0' && *b != '\0') {
    if (*a != *b) {
      return false;
    }
    ++a;
    ++b;
  }
  return *a == *b;
}

static inline void hkem_profile_reset(uint64_t *protocol_cycles,
                                      uint32_t *test_cycles,
                                      size_t *entry_count) {
  *protocol_cycles = 0;
  *test_cycles = 0;
  *entry_count = 0;
}

static inline void hkem_profile_add_entry(hkem_profile_entry_t *entries,
                                          size_t capacity,
                                          size_t *entry_count,
                                          bool is_test,
                                          const char *step,
                                          uint32_t cycles) {
#if HYBRID_KEM_ENABLE_PROFILING
  CHECK(*entry_count < capacity);
  entries[(*entry_count)++] =
      (hkem_profile_entry_t){.step = step, .cycles = cycles, .is_test = is_test};
#else
  (void)entries;
  (void)capacity;
  (void)entry_count;
  (void)is_test;
  (void)step;
  (void)cycles;
#endif
}

static inline uint32_t hkem_profile_get_step(
    const hkem_profile_entry_t *entries,
    size_t entry_count,
    const char *step) {
  for (size_t i = 0; i < entry_count; ++i) {
    if (hkem_profile_streq(entries[i].step, step)) {
      return entries[i].cycles;
    }
  }
  return 0;
}

static inline void hkem_profile_dump_raw(const char *phase_name,
                                         const hkem_profile_entry_t *entries,
                                         size_t entry_count) {
#if HYBRID_KEM_ENABLE_PROFILING
  for (size_t i = 0; i < entry_count; ++i) {
    if (entries[i].is_test) {
      LOG_INFO("HKE_PROFILE_APP_TEST,%s,%s,%u", phase_name, entries[i].step,
               entries[i].cycles);
    } else {
      LOG_INFO("HKE_PROFILE_APP,%s,%s,%u", phase_name, entries[i].step,
               entries[i].cycles);
    }
  }
#else
  (void)phase_name;
  (void)entries;
  (void)entry_count;
#endif
}

static inline void hkem_profile_summary(const char *kind,
                                        const char *phase_name,
                                        const char *label,
                                        uint32_t calls,
                                        uint32_t total_cycles) {
#if HYBRID_KEM_ENABLE_PROFILING
  uint32_t avg_cycles = calls == 0 ? 0 : total_cycles / calls;
  LOG_INFO(
      "%s,%s,label=%s,calls=%u,total_cycles=%u,avg_cycles=%u",
      kind, phase_name, label, calls, total_cycles, avg_cycles);
#else
  (void)kind;
  (void)phase_name;
  (void)label;
  (void)calls;
  (void)total_cycles;
#endif
}

#define HKEM_PROFILE_PHASE(phase_name, label, calls, total_cycles) \
  hkem_profile_summary("HKE_PROFILE_PHASE", phase_name, label, calls, \
                       total_cycles)

#define HKEM_PROFILE_APP_SUMMARY(phase_name, label, calls, total_cycles) \
  hkem_profile_summary("HKE_PROFILE_APP", phase_name, label, calls, \
                       total_cycles)

#if HYBRID_KEM_ENABLE_PROFILING
#define HKEM_PROFILE(step, body)                                  \
  do {                                                            \
    uint64_t hkem_t_start = profile_start();                      \
    do {                                                          \
      body                                                        \
    } while (false);                                              \
    uint32_t hkem_elapsed = profile_end(hkem_t_start);            \
    hkem_protocol_cycles += hkem_elapsed;                         \
    hkem_profile_add_entry(hkem_profile_entries,                  \
                           ARRAYSIZE(hkem_profile_entries),       \
                           &hkem_profile_count, false, step,      \
                           hkem_elapsed);                         \
  } while (false)

#define HKEM_PROFILE_TEST(step, body)                             \
  do {                                                            \
    uint64_t hkem_t_start = profile_start();                      \
    do {                                                          \
      body                                                        \
    } while (false);                                              \
    uint32_t hkem_elapsed = profile_end(hkem_t_start);            \
    hkem_test_cycles += hkem_elapsed;                             \
    hkem_profile_add_entry(hkem_profile_entries,                  \
                           ARRAYSIZE(hkem_profile_entries),       \
                           &hkem_profile_count, true, step,       \
                           hkem_elapsed);                         \
  } while (false)
#else
#define HKEM_PROFILE(step, body)                                  \
  do {                                                            \
    (void)(step);                                                  \
    do {                                                          \
      body                                                        \
    } while (false);                                              \
  } while (false)

#define HKEM_PROFILE_TEST(step, body) HKEM_PROFILE(step, body)
#endif

#endif  // TEST_HYBRID_KEM_OTBN_PROMPT_VER0_1_IBEX_HKEM_PROFILE_H_
