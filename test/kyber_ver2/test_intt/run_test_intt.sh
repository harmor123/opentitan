#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

OT_ROOT=""
CUR="$SCRIPT_DIR"
while [[ "$CUR" != "/" ]]; do
    if [[ -d "$CUR/hw/ip/otbn" ]]; then
        OT_ROOT="$CUR"
        break
    fi
    CUR="$(dirname "$CUR")"
done

if [[ -z "$OT_ROOT" ]]; then
    echo "Error: Could not find OpenTitan root"
    exit 1
fi
echo "OpenTitan root: $OT_ROOT"

SOURCE_DIR="$OT_ROOT/test/kyber_ver2/test_intt"
export BNMULV_VER=2

OTBN_AS="$OT_ROOT/hw/ip/otbn/util/otbn_as.py"
OTBN_LD="$OT_ROOT/hw/ip/otbn/util/otbn_ld.py"
OTBN_SIM="$OT_ROOT/hw/ip/otbn/dv/otbnsim/standalone.py"
OTBN_SIM_TEST="$OT_ROOT/hw/ip/otbn/util/otbn_sim_test.py"

TMPDIR="$SCRIPT_DIR/tmp-intt-test"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# Assemble
echo "=== Assembling ==="
"$OTBN_AS" -o "$TMPDIR/test_intt.o"      "$SOURCE_DIR/test_intt.s"
"$OTBN_AS" -o "$TMPDIR/ntt.o"            "$OT_ROOT/test/kyber_ver2/mlkem768_encap_ver2/ntt.s"
"$OTBN_AS" -o "$TMPDIR/intt.o"           "$OT_ROOT/test/kyber_ver2/mlkem768_encap_ver2/intt.s"

# Link
echo "=== Linking ==="
"$OTBN_LD" -o "$TMPDIR/test_intt.elf" \
    "$TMPDIR/test_intt.o" \
    "$TMPDIR/ntt.o" \
    "$TMPDIR/intt.o"

export PYTHONPATH="$OT_ROOT:$PYTHONPATH"

# Run simulation
echo "=== Running simulation ==="
"$OTBN_SIM" --verbose --dump-dmem "$TMPDIR/dmem.bin" "$TMPDIR/test_intt.elf" > "$TMPDIR/sim_standalone.log" 2>&1
echo "Simulation done. Log: $TMPDIR/sim_standalone.log"

# Run comparison
echo "=== Comparing against expected ==="
"$OTBN_SIM_TEST" --verbose "$OTBN_SIM" \
    --expected_dmem "$SOURCE_DIR/test_intt.dexp" \
    "$TMPDIR/test_intt.elf" > "$TMPDIR/sim_test.log" 2>&1
echo "Test done. Log: $TMPDIR/sim_test.log"
