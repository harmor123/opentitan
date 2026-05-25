# BUILD — OTBN simulation tests (ver0_base pure software)
#
# Uses otbn_sim_test to run each OTBN app on the ISS simulator
# with hardcoded test vectors and verify against expected outputs.
#
# No --bnmulv_version_id=2 copts (baseline OTBN instructions).
# No KMAC hardware dependencies (pure software SHA3).

load("//rules:otbn.bzl", "otbn_sim_test")

package(default_visibility = ["//visibility:public"])

exports_files([
    "hmac_test.s",
    "mlkem_base_keypair_test.s",
    "mlkem_base_encap_test.s",
    "mlkem_base_decap_test.s",
    "p256_ecdh_shared_key_test.s",
    "sha3_shake_test.s",
    "hkdf_test.s",
])

# ================================================================
# ML-KEM-768 KeyPair
# ================================================================

otbn_sim_test(
    name = "mlkem768_keypair_test",
    srcs = ["mlkem_base_keypair_test.s"],
    dexp = "mlkem768_keypair_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem_keypair",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:symmetric",
    ],
)

# ================================================================
# ML-KEM-768 Encap
# ================================================================

otbn_sim_test(
    name = "mlkem768_encap_test",
    srcs = ["mlkem_base_encap_test.s"],
    dexp = "mlkem768_encap_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem_encap",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:symmetric",
    ],
)

# ================================================================
# ML-KEM-768 Decap
# ================================================================

otbn_sim_test(
    name = "mlkem768_decap_test",
    srcs = ["mlkem_base_decap_test.s"],
    dexp = "mlkem768_decap_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem_encap",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem_decap",
        "//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:symmetric",
    ],
)

# ================================================================
# P-256 ECDH
# ================================================================

otbn_sim_test(
    name = "p256_ecdh_test",
    srcs = ["p256_ecdh_shared_key_test.s"],
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_base",
        "//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_isoncurve_proj",
        "//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_shared_key",
    ],
)

# ================================================================
# HKDF-SHA3-256 (pure software)
# ================================================================

otbn_sim_test(
    name = "hkdf_test",
    srcs = ["hkdf_test.s"],
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_lib",
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hmac_sha3",
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:sha3_shake",
    ],
)

# ================================================================
# HMAC-SHA3-256 (pure software)
# ================================================================

otbn_sim_test(
    name = "hmac_test",
    srcs = ["hmac_test.s"],
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hmac_sha3",
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:sha3_shake",
    ],
)

# ================================================================
# SHA3 / SHAKE (official OpenTitan test, pure software Keccak-f)
# ================================================================

otbn_sim_test(
    name = "sha3_shake_test",
    srcs = ["sha3_shake_test.s"],
    dexp = "sha3_shake_test.exp",
    deps = [
        "//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:sha3_shake",
    ],
)
