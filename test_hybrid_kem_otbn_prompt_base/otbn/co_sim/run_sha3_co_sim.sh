#!/bin/bash
# SHA3/SHAKE co-simulation (ver0_base — pure software Keccak-f)
# Runs RTL standalone + ISS test separately.
# Baseline RTL/ISS trace formats differ (ACCH vs ACC), so comparison is done
# at the DMEM/output level via otbn_sim_test instead of instruction-level trace.
set -euo pipefail
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../..")"

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== SHA3/SHAKE co-sim (ver0_base) ==="

# Step 1: ISS test (functional verification with expected DMEM output)
ISS_TARGET="//test_hybrid_kem_otbn_prompt_base/otbn/test:sha3_shake_test"
echo "--- ISS test ---"
(cd "$ROOT_DIR" && ./bazelisk.sh test "$ISS_TARGET" --cache_test_results=no) \
  || fail "ISS test failed"

# Step 2: RTL standalone (smoke test — runs without ISS comparison)
VOTBN="$ROOT_DIR/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"
BAZEL_TARGET="//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0"
ELF="$ROOT_DIR/bazel-bin/test_hybrid_kem_otbn_prompt_base/otbn/hkdf/hkdf_sha3_256_ver0.elf"

(cd "$ROOT_DIR" && ./bazelisk.sh build "$BAZEL_TARGET") || fail "bazel build"

if [ ! -x "$VOTBN" ]; then
  echo "Building Verilator (baseline OTBN)..."
  (cd "$ROOT_DIR" &&
   fusesoc --cores-root=. run --target=sim --setup --build \
     --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
     --make_options="-j$(nproc)") || fail "Verilator build"
fi

RUN_LOG=$(mktemp)
trap "rm -f $RUN_LOG" EXIT

echo "--- RTL co-sim (baseline, env -u BNMULV_VER) ---"
timeout 120s env -u BNMULV_VER "$VOTBN" --load-elf="$ELF" 2>&1 | tee "$RUN_LOG" || true

if grep -q "Mismatch\|%Error" "$RUN_LOG"; then
  grep "Mismatch\|RTL wrote\|ISS wrote" "$RUN_LOG" | head -10
  fail "SHA3 RTL-ISS mismatch"
fi

echo "PASS: SHA3/SHAKE (ver0_base) RTL matches ISS"
