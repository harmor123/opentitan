# ================================================================
# BUILD — Hybrid KEM (ML-KEM-768 + P-256 ECDH) Ibex test targets
#
# Validated targets (all PASS on Verilator):
#   bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_minimal_sim_verilator
#   bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_mlkem_only_sim_verilator
#   bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_p256_only_sim_verilator
#
# Note: Binary size > ~22KB text triggers Heisenbug (Alert 48).
# Keep each test binary with only ONE OTBN app linked.
# ================================================================

load("//rules/opentitan:defs.bzl", "opentitan_test", "EARLGREY_TEST_ENVS")

# ---- OTBN init + secure wipe ----
opentitan_test(
    name = "hybrid_kem_minimal",
    srcs = ["ibex/hybrid_kem_minimal.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)

# ---- ML-KEM-768 KeyGen only ----
opentitan_test(
    name = "hybrid_kem_mlkem_only",
    srcs = ["ibex/hybrid_kem_mlkem_only.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
    ],
)

# ---- P-256 ECDH only ----
opentitan_test(
    name = "hybrid_kem_p256_only",
    srcs = ["ibex/hybrid_kem_p256_only.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
    ],
)

# ---- ML-KEM-768 Encap only ----
opentitan_test(
    name = "hybrid_kem_encap_only",
    srcs = ["ibex/hybrid_kem_encap_only.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
    ],
)

# ---- ML-KEM-768 Decap only ----
opentitan_test(
    name = "hybrid_kem_decap_only",
    srcs = ["ibex/hybrid_kem_decap_only.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
    ],
)

# ---- Phase 1: KeyGen (ML-KEM + P-256) 2 apps per §2.1 ----
opentitan_test(
    name = "hybrid_kem_keygen",
    srcs = ["ibex/hybrid_kem_keygen.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
    ],
)

# ---- Phase 2: Encap+Decap (4 apps: encap+decap+p256+hkdf) per §2.2 ----
opentitan_test(
    name = "hybrid_kem_encap_decap",
    srcs = ["ibex/hybrid_kem_encap_decap.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256",
    ],
)

# ---- HKDF-SHA3-256 only ----
opentitan_test(
    name = "hybrid_kem_hkdf_only",
    srcs = ["ibex/hybrid_kem_hkdf_only.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256",
    ],
)
