#!/bin/bash
set -euo pipefail
cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")"
for s in run_sha3_co_sim.sh run_hmac_co_sim.sh run_hkdf_co_sim.sh run_p256_co_sim.sh run_mlkem_keypair_co_sim.sh run_mlkem_encap_co_sim.sh run_mlkem_decap_co_sim.sh; do
  echo "=== $s ==="
  bash "$s" || echo "FAIL: $s"
  echo
done
