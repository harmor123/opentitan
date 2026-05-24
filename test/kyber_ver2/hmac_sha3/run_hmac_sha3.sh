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

SOURCE_DIR="$OT_ROOT/test/kyber_ver2/hmac_sha3"

OTBN_AS="$OT_ROOT/hw/ip/otbn/util/otbn_as.py"
OTBN_LD="$OT_ROOT/hw/ip/otbn/util/otbn_ld.py"
OTBN_SIM="$OT_ROOT/hw/ip/otbn/dv/otbnsim/standalone.py"
OTBN_SIM_TEST="$OT_ROOT/hw/ip/otbn/util/otbn_sim_test.py"

TMPDIR="$SCRIPT_DIR/tmp-kybertest"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

"$OTBN_AS" -o "$TMPDIR/hmac_sha3_test.o" "$SOURCE_DIR/hmac_sha3_test.s"
"$OTBN_AS" -o "$TMPDIR/hmac_sha3.o" "$SOURCE_DIR/hmac_sha3.s"
"$OTBN_AS" -o "$TMPDIR/kmac_sha3_template.o" "$SOURCE_DIR/kmac_sha3_template.s"

"$OTBN_LD" -o "$TMPDIR/hmac_sha3_test.elf" \
    "$TMPDIR/hmac_sha3_test.o" \
    "$TMPDIR/hmac_sha3.o" \
    "$TMPDIR/kmac_sha3_template.o"

export PYTHONPATH="$OT_ROOT:$PYTHONPATH"

echo "Running simulation..."
"$OTBN_SIM" --verbose --dump-dmem "$TMPDIR/dmem.bin" "$TMPDIR/hmac_sha3_test.elf" > "$TMPDIR/sim_standalone.log" 2>&1
echo "DMEM dumped to: $TMPDIR/dmem.bin"

echo "Comparing DMEM expectation..."
"$OTBN_SIM_TEST" --verbose "$OTBN_SIM" --expected_dmem "$SOURCE_DIR/hmac_sha3_test.dexp" "$TMPDIR/hmac_sha3_test.elf" > "$TMPDIR/sim_test.log" 2>&1
echo "Test complete. Log: $TMPDIR/sim_test.log"
