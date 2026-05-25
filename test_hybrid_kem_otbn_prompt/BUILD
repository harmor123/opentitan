# ================================================================
# BUILD — Hybrid KEM (ML-KEM-768 + P-256 ECDH) OTBN + Ibex build
#
# OTBN ISS 仿真测试 (快速, 仅指令集验证):
#   bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_keypair_test
#   bazel test //test_hybrid_kem_otbn_prompt/otbn/test:hkdf_test
#   bazel test //test_hybrid_kem_otbn_prompt/otbn/test:...
#
# OTBN RTL+ISS 联调 (RTL 硬件正确性验证):
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh            # 全部 5 个
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh hkdf       # 单个
#
# Ibex 集成测试 (全芯片 Verilator):
#   bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_test_sim_verilator \
#     --sandbox_writable_path=/run/user/1000/ccache-tmp
# ================================================================

load("//rules/opentitan:defs.bzl", "opentitan_test", "EARLGREY_TEST_ENVS")
load("@bazel_skylib//lib:dicts.bzl", "dicts")

# ---- 功能测试模式 ----
opentitan_test(
    name = "hybrid_kem_test",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
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
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256",
    ],
)

# ---- 生产安全模式 ----
opentitan_test(
    name = "hybrid_kem_prod",
    srcs = [
        "ibex/hybrid_kem.c",
        "ibex/hybrid_kem.h",
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
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256",
    ],
)
