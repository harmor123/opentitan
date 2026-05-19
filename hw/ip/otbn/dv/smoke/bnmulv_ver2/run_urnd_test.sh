#!/bin/bash
# Run URND/RND PRNG test with RTL-ISS trace comparison
set -o pipefail
set -e

SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(readlink -e "$SCRIPT_DIR/../../../../..")"
OTBN_UTIL=$ROOT_DIR/ip/otbn/util
SMOKE_BIN_DIR=$ROOT_DIR/build/otbn/urnd_smoke_test

fail() { echo >&2 "FAIL: $*"; exit 1; }

echo "=== Running urnd_smoke_test ==="

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
$OTBN_UTIL/otbn_as.py -o $SMOKE_BIN_DIR/urnd_smoke_test.o $SCRIPT_DIR/urnd_smoke_test.s || \
  fail "Assemble"
$OTBN_UTIL/otbn_ld.py -o $SMOKE_BIN_DIR/urnd_smoke_test.elf $SMOKE_BIN_DIR/urnd_smoke_test.o || \
  fail "Link"

RUN_LOG=$(mktemp)
trap "rm -rf $RUN_LOG" EXIT

timeout 10s "$VOTBN" --load-elf=$SMOKE_BIN_DIR/urnd_smoke_test.elf -t | tee $RUN_LOG

# Check for trace mismatch
if grep -q "Mismatch\|%Error" $RUN_LOG; then
  grep "Mismatch\|RTL wrote\|ISS wrote" $RUN_LOG | head -5
  echo "PRNG MISMATCH DETECTED — ISS and RTL URND/RND values differ"
  echo "Root cause: edn_urnd_step() seeds PRNG per 32-bit word instead of full 256-bit"
  exit 1
fi

echo "PASS: urnd_smoke_test (PRNG values match)"
