# ================================================================
# BUILD — Hybrid KEM (ML-KEM-768 + P-256 ECDH) ver0_base baseline
#
# Pure software implementation: no KMAC hardware, no BN vector
# extensions. All crypto uses software Keccak-f[1600] on OTBN.
#
# Targets:
#   hybrid_kem_test   — Functional test mode (HYBRID_KEM_TEST_MODE)
#   hybrid_kem_prod   — Production mode (TRNG entropy source)
#
# OTBN ISS simulation tests (fast, instruction-set verification):
#   bazel test //test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0_test
#
# Ibex integration test (full-chip Verilator):
#   bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_test_sim_verilator
# ================================================================

load("//rules/opentitan:defs.bzl", "opentitan_test", "EARLGREY_TEST_ENVS")
load("@bazel_skylib//lib:dicts.bzl", "dicts")

# ---- Functional test mode ----
opentitan_test(
    name = "hybrid_kem_test",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
        "ibex/otbn_utils.h",
    ],
    defines = ["HYBRID_KEM_TEST_MODE"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_keypair_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_encap_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_decap_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_ecdh_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0",
    ],
)

# ---- Production security mode ----
opentitan_test(
    name = "hybrid_kem_prod",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
        "ibex/otbn_utils.h",
    ],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:ibex",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_keypair_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_encap_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_decap_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_ecdh_ver0",
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0",
    ],
)
