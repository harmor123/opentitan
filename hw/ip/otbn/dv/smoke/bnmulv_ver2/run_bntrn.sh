#!/bin/bash
# Run bntrn smoke test (addv.16H, addv.8S, subv.16H) with RTL-ISS trace comparison
set -o pipefail
set -e
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../../../..")"
UTIL_DIR="$ROOT_DIR/util"
OTBN_UTIL=$ROOT_DIR/ip/otbn/util
SMOKE_BIN_DIR=$ROOT_DIR/build/otbn/bntrn_smoke_test

source "$UTIL_DIR/build_consts.sh" 2>/dev/null || true

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== Running bntrn_smoke_test ==="

echo "Building Verilator simulation..."
(cd $ROOT_DIR &&
 fusesoc --cores-root=. run --target=sim --setup --build \
   --flag=bnmulv_ver2 \
   --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
   --make_options="-j$(nproc)" || fail "HW Sim build failed")

VOTBN="$ROOT_DIR/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"

mkdir -p $SMOKE_BIN_DIR
export BNMULV_VER=2
$OTBN_UTIL/otbn_as.py -o $SMOKE_BIN_DIR/bntrn_smoke_test.o $SCRIPT_DIR/bntrn_smoke_test.s || \
  fail "Assemble"
$OTBN_UTIL/otbn_ld.py -o $SMOKE_BIN_DIR/bntrn_smoke_test.elf $SMOKE_BIN_DIR/bntrn_smoke_test.o || \
  fail "Link"

RUN_LOG=$(mktemp)
trap "rm -rf $RUN_LOG" EXIT

timeout 10s "$VOTBN" --load-elf=$SMOKE_BIN_DIR/bntrn_smoke_test.elf -t | tee $RUN_LOG

if [ -f $SCRIPT_DIR/bntrn_smoke_expected.txt ]; then
  grep -A 72 "Call Stack:" $RUN_LOG | diff -U3 $SCRIPT_DIR/bntrn_smoke_expected.txt - || \
    fail "Output mismatch"
else
  echo "WARNING: No expected output file. Generating from this run."
  grep -A 72 "Call Stack:" $RUN_LOG > $SCRIPT_DIR/bntrn_smoke_expected.txt
fi

echo "PASS: bntrn_smoke_test"
