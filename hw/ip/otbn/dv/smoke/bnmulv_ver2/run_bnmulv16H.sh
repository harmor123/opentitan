#!/bin/bash
# Run bnmulv16H smoke test with RTL-ISS trace comparison
set -o pipefail
set -e

SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../../../..")"
UTIL_DIR="$ROOT_DIR/util"
OTBN_UTIL=$ROOT_DIR/ip/otbn/util
SMOKE_BIN_DIR=$ROOT_DIR/build/otbn/bnmulv16H_smoke_test

source "$UTIL_DIR/build_consts.sh" 2>/dev/null || true

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== Running bnmulv16H_smoke_test ==="

# Rebuild Verilator simulation every time (like baseline run_smoke.sh)
echo "Building Verilator simulation..."
(cd $ROOT_DIR &&
 fusesoc --cores-root=. run --target=sim --setup --build \
   --flag=bnmulv_ver2 \
   --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
   --make_options="-j$(nproc)" || fail "HW Sim build failed")

VOTBN="$ROOT_DIR/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"

# Assemble and link
mkdir -p $SMOKE_BIN_DIR
export BNMULV_VER=2
$OTBN_UTIL/otbn_as.py -o $SMOKE_BIN_DIR/bnmulv16H_smoke_test.o $SCRIPT_DIR/bnmulv16H_smoke_test.s || \
  fail "Assemble"
$OTBN_UTIL/otbn_ld.py -o $SMOKE_BIN_DIR/bnmulv16H_smoke_test.elf $SMOKE_BIN_DIR/bnmulv16H_smoke_test.o || \
  fail "Link"

RUN_LOG=$(mktemp)
trap "rm -rf $RUN_LOG" EXIT

timeout 10s "$VOTBN" --load-elf=$SMOKE_BIN_DIR/bnmulv16H_smoke_test.elf -t | tee $RUN_LOG

grep -A 72 "Call Stack:" $RUN_LOG | diff -U3 $SCRIPT_DIR/bnmulv16H_smoke_expected.txt - || \
  fail "Output mismatch"

echo "PASS: bnmulv16H_smoke_test"
