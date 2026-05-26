#!/bin/bash
# Run all 7 hybrid KEM OTBN RTL+ISS co-simulation tests (ver0_base)
# Pure software baseline — no KMAC, no BN vector extensions.
set -euo pipefail
rm -rf build/lowrisc_ip_otbn_top_sim_0.1
SCRIPT_DIR="$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
NC='\033[0m'

TESTS=(
  "run_sha3_co_sim.sh"
  "run_hmac_co_sim.sh"
  "run_hkdf_co_sim.sh"
  "run_p256_ecdh_co_sim.sh"
  "run_mlkem_keypair_co_sim.sh"
  "run_mlkem_encap_co_sim.sh"
  "run_mlkem_decap_co_sim.sh"
)

PASS=0
FAIL=0

for t in "${TESTS[@]}"; do
  echo -e "${BLUE}===== ${t} =====${NC}"
  if bash "$SCRIPT_DIR/$t"; then
    ((PASS++))
  else
    ((FAIL++))
  fi
  echo ""
done

echo -e "${BLUE}===== Results: ${GREEN}${PASS} PASS${NC}, ${RED}${FAIL} FAIL${NC} =====${NC}"
[[ $FAIL -eq 0 ]] || exit 1
