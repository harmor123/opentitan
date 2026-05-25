load("//rules:otbn.bzl", "otbn_sim_test")

package(default_visibility = ["//visibility:public"])

exports_files([
    "hmac_test.s",
    "mlkem_base_keypair_test.s",
    "mlkem_base_encap_test.s",
    "mlkem_base_decap_test.s",
    "p256_ecdh_shared_key_test.s",
    "sha3_test.s",
    "hkdf_test.s",
])

# ================================================================
# ML-KEM-768 KeyPair
# ================================================================

otbn_sim_test(
    name = "mlkem768_keypair_test",
    srcs = ["mlkem_base_keypair_test.s"],
    copts = ["--bnmulv_version_id=2"],
    dexp = "mlkem768_keypair_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem_keypair",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
    ],
)

# ================================================================
# ML-KEM-768 Encap
# ================================================================

otbn_sim_test(
    name = "mlkem768_encap_test",
    srcs = ["mlkem_base_encap_test.s"],
    copts = ["--bnmulv_version_id=2"],
    dexp = "mlkem768_encap_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
    ],
)

# ================================================================
# ML-KEM-768 Decap
# ================================================================

otbn_sim_test(
    name = "mlkem768_decap_test",
    srcs = ["mlkem_base_decap_test.s"],
    copts = ["--bnmulv_version_id=2"],
    dexp = "mlkem768_decap_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem_encap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem_decap",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
    ],
)

# ================================================================
# P-256 ECDH
# ================================================================

otbn_sim_test(
    name = "p256_ecdh_test",
    srcs = ["p256_ecdh_shared_key_test.s"],
    dexp = "p256_ecdh_shared_key_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_base",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_isoncurve_proj",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_shared_key",
    ],
)

# ================================================================
# HKDF-SHA3-256
# ================================================================

otbn_sim_test(
    name = "hkdf_test",
    srcs = ["hkdf_test.s"],
    dexp = "hkdf_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256_lib",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hmac_sha3",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:kmac_sha3_template",
    ],
)

# ================================================================
# HMAC-SHA3-256
# ================================================================

otbn_sim_test(
    name = "hmac_test",
    srcs = ["hmac_test.s"],
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:hmac_sha3",
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:kmac_sha3_template",
    ],
)

# ================================================================
# KMAC / SHA3
# ================================================================

otbn_sim_test(
    name = "kmac_sha3_test",
    srcs = ["sha3_test.s"],
    dexp = "sha3_test.dexp",
    deps = [
        "//test_hybrid_kem_otbn_prompt/otbn/hkdf:kmac_sha3_template",
    ],
)
