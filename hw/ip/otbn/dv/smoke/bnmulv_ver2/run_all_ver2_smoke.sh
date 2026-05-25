#!/bin/bash
# Run ALL ver2 smoke tests sequentially
set -o pipefail
set -e
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"

TESTS=(
  "bnmulv8S"
  "bnmulv16H"
  "bnmulvl8S"
  "bnmulvl16H"
  "bnaddsubv"
  "bnaddsubvm"
  "bnshv"
  "bntrn"
)

PASSED=0
FAILED=0

for test in "${TESTS[@]}"; do
  echo ""
  echo "========================================"
  echo "  Running: $test"
  echo "========================================"
  if "$SCRIPT_DIR/run_${test}.sh"; then
    ((PASSED++))
  else
    ((FAILED++))
    echo "*** FAILED: $test ***"
  fi
done

echo ""
echo "========================================"
echo "  Results: $PASSED passed, $FAILED failed"
echo "========================================"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
