/**
 * @file
 * @brief OTBN utility macros for the Hybrid KEM ver0_base baseline.
 *
 * Provides helper macros for loading OTBN apps, executing them,
 * reading mcycle counters, and managing DMEM data transfers.
 * All cryptographic operations use pure software Keccak-f
 * (no KMAC hardware, no BN vector extensions).
 */

#ifndef OTBN_UTILS_H_
#define OTBN_UTILS_H_

#include <stdint.h>

/**
 * Read the Ibex mcycle CSR for cycle counting.
 * Returns the current 64-bit cycle count.
 */
static inline uint64_t read_mcycle(void) {
  uint32_t lo, hi;
  asm volatile (
    "csrr %[lo], mcycle;"
    "csrr %[hi], mcycleh;"
    : [lo] "=r"(lo), [hi] "=r"(hi)
  );
  return ((uint64_t)hi << 32) | lo;
}

/**
 * Macro: measure elapsed cycles for a code block.
 *
 * Usage:
 *   uint64_t elapsed;
 *   MCYCLE_BENCH(elapsed) {
 *     // code to measure
 *   }
 *   // elapsed now holds the cycle count
 */
#define MCYCLE_BENCH(elapsed_var)                                          \
  for (uint64_t _mcycle_start_ = read_mcycle(), _mcycle_done_ = 0;        \
       _mcycle_done_ == 0;                                                 \
       elapsed_var = read_mcycle() - _mcycle_start_, _mcycle_done_ = 1)

#endif  // OTBN_UTILS_H_
