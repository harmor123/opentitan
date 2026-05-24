# ================================================================
# BUILD — Hybrid KEM (ML-KEM-768 + P-256 ECDH) OTBN + Ibex build
#
# Requires: OpenTitan Bazel rules
#
# 构建:
#   bazel build //test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair_bin
#   bazel test  //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_keypair_test
# ================================================================

load("//rules/opentitan:defs.bzl", "opentitan_test")

# ---- 功能测试模式 ----
opentitan_test(
    name = "hybrid_kem_test",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
    ],
    defines = ["HYBRID_KEM_TEST_MODE"],
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/testing:otbn_testutils",
    ],
)

# ---- 生产安全模式 ----
opentitan_test(
    name = "hybrid_kem_prod",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
    ],
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf",
        "//sw/device/lib/dif:otbn",
        "//sw/device/lib/testing:otbn_testutils",
    ],
)
