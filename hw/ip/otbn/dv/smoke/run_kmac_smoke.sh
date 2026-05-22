#!/bin/bash
# Run KMAC/SHA3 smoke test — RTL register interface verification
set -o pipefail
set -e
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../../../..")"
OTBN_UTIL=$ROOT_DIR/hw/ip/otbn/util
SMOKE_BIN_DIR=$ROOT_DIR/build/otbn/kmac_smoke_test

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== Running kmac_smoke_test ==="

# Assemble and link
mkdir -p $SMOKE_BIN_DIR
export BNMULV_VER=0
$OTBN_UTIL/otbn_as.py -o $SMOKE_BIN_DIR/kmac_smoke_test.o $SCRIPT_DIR/kmac_smoke_test.s || \
  fail "Assemble"
$OTBN_UTIL/otbn_ld.py -o $SMOKE_BIN_DIR/kmac_smoke_test.elf $SMOKE_BIN_DIR/kmac_smoke_test.o || \
  fail "Link"

RUN_LOG=$(mktemp)
trap "rm -rf $RUN_LOG" EXIT

VOTBN="$ROOT_DIR/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"
if [ ! -x "$VOTBN" ]; then
  echo "Building Verilator simulation..."
  (cd $ROOT_DIR &&
   fusesoc --cores-root=. run --target=sim --setup --build \
     --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
     --make_options="-j$(nproc)" || fail "HW Sim build failed")
fi

timeout 30s "$VOTBN" --load-elf=$SMOKE_BIN_DIR/kmac_smoke_test.elf -t | tee $RUN_LOG

# Check for trace mismatch
if grep -q "Mismatch\|%Error" $RUN_LOG; then
  grep "Mismatch\|RTL wrote\|ISS wrote" $RUN_LOG | head -5
  fail "KMAC RTL-ISS trace mismatch"
fi

echo "PASS: kmac_smoke_test (KMAC register interface RTL-ISS match)"
