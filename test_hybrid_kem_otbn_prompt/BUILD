# ================================================================
# BUILD — Hybrid KEM (ML-KEM-768 + P-256 ECDH) Ibex test targets
#
# Phase 1: ibex/phase1_keygen/   — p256_keygen, mlkem_keygen
# Phase 2: ibex/phase2_encap_decap/ — mlkem_encap, mlkem_decap, hkdf
# Misc:    ibex/                 — combined, p256_multi_test
#
# Rule: ONE OTBN binary per test target for chip sim.
# ================================================================

load("//rules/opentitan:defs.bzl", "opentitan_test", "EARLGREY_TEST_ENVS")

# ================================================================
# Phase 1 — KeyGen
# ================================================================

opentitan_test(
    name = "phase1_p256_keygen",
    srcs = ["ibex/phase1_keygen/p256_keygen.c"],
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

# Minimal test: EXACT copy of p256_only + mlkem768_keypair dep (not executed)
opentitan_test(
    name = "p256_plus_mlkem",
    srcs = ["ibex/p256_plus_mlkem.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
    ],
)

# Phase 1 integration: p256_keygen + mlkem_keygen (ISS/FPGA, not chip sim)
opentitan_test(
    name = "phase1_keygen_integration",
    srcs = ["ibex/phase1_keygen/hybrid_kem_keygen.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
    ],
)

opentitan_test(
    name = "phase1_mlkem_keygen",
    srcs = ["ibex/phase1_keygen/mlkem_keygen.c"],
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

# ================================================================
# Phase 2 — Encap / Decap
# ================================================================

opentitan_test(
    name = "phase2_mlkem_encap",
    srcs = ["ibex/phase2_encap_decap/mlkem_encap.c"],
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

opentitan_test(
    name = "phase2_mlkem_decap",
    srcs = ["ibex/phase2_encap_decap/mlkem_decap.c"],
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

opentitan_test(
    name = "phase2_hkdf",
    srcs = ["ibex/phase2_encap_decap/hkdf_only.c"],
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

# ================================================================
# Misc
# ================================================================

# Combined OTBN binary (mode dispatch — ML-KEM modes 1/2/3 verified)
opentitan_test(
    name = "hybrid_kem_combined",
    srcs = ["ibex/hybrid_kem_combined.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/combined:hybrid_kem_all",
    ],
)

# Minimal reproduction: our p256_ecdh + official run_p256 → Alert 48
opentitan_test(
    name = "p256_multi_test",
    srcs = ["ibex/p256_multi_test.c"],
    exec_env = EARLGREY_TEST_ENVS,
    deps = [
        "//hw/top/dt",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing:entropy_testutils",
        "//sw/device/lib/testing:otbn_testutils",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//sw/otbn/crypto:run_p256",
    ],
)
