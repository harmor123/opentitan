#!/bin/bash
# ================================================================
# Run all OTBN ISS tests for Hybrid KEM
# ================================================================
set -e

SANDBOX="--sandbox_writable_path=/run/user/1000/ccache-tmp"
BASE="//test_hybrid_kem_paper/otbn/test"

echo "============================================================"
echo "Hybrid KEM — OTBN ISS Tests"
echo "============================================================"

echo ""
echo "--- ML-KEM-768 Keypair ---"
bazel test ${BASE}:mlkem768_keypair_test --test_output=errors ${SANDBOX} 2>&1 | tail -3

echo ""
echo "--- ML-KEM-768 Encap ---"
bazel test ${BASE}:mlkem768_encap_test --test_output=errors ${SANDBOX} 2>&1 | tail -3

echo ""
echo "--- ML-KEM-768 Decap ---"
bazel test ${BASE}:mlkem768_decap_test --test_output=errors ${SANDBOX} 2>&1 | tail -3

echo ""
echo "--- P-256 ECDH ---"
bazel test ${BASE}:p256_ecdh_test --test_output=errors ${SANDBOX} 2>&1 | tail -3

echo ""
echo "--- HKDF-SHA3-256 ---"
bazel test ${BASE}:hkdf_test --test_output=errors ${SANDBOX} 2>&1 | tail -3

echo ""
echo "============================================================"
echo "All ISS tests complete"
echo "============================================================"
