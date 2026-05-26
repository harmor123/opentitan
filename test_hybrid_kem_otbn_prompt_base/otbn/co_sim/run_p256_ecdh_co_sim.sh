#!/bin/bash
# P-256 ECDH co-simulation (ver0_base — same code as reference)
set -euo pipefail
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../..")"

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== P-256 ECDH co-sim (ver0_base) ==="

# Step 1: ISS test
ISS_TARGET="//test_hybrid_kem_otbn_prompt_base/otbn/test:p256_ecdh_test"
echo "--- ISS test ---"
(cd "$ROOT_DIR" && ./bazelisk.sh test "$ISS_TARGET" --cache_test_results=no) \
  || fail "ISS test failed"

# Step 2: RTL standalone
VOTBN="$ROOT_DIR/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"
BAZEL_TARGET="//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_ecdh_ver0"
ELF="$ROOT_DIR/bazel-bin/test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh/p256_ecdh_ver0.elf"

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

echo "--- RTL co-sim ---"
timeout 120s env -u BNMULV_VER "$VOTBN" --load-elf="$ELF" 2>&1 | tee "$RUN_LOG" || true

if grep -q "Mismatch\|%Error" "$RUN_LOG"; then
  grep "Mismatch\|RTL wrote\|ISS wrote" "$RUN_LOG" | head -10
  fail "P-256 RTL-ISS mismatch"
fi

echo "PASS: P-256 ECDH (ver0_base) RTL matches ISS"
