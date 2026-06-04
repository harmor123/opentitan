load("//rules:otbn.bzl", "otbn_sim_test")

package(default_visibility = ["//visibility:public"])

exports_files([
    "mlkem_base_keypair_test.s",
    "mlkem_base_encap_test.s",
    "mlkem_base_decap_test.s",
    "p256_ecdh_shared_key_test.s",
    "hkdf_test.s",
])

otbn_sim_test(
    name = "mlkem768_keypair_test",
    srcs = ["mlkem_base_keypair_test.s"],
    deps = [
        "//test_hybrid_kem_paper/otbn/mlkem768:basemul",
        "//test_hybrid_kem_paper/otbn/mlkem768:cbd",
        "//test_hybrid_kem_paper/otbn/mlkem768:ntt",
        "//test_hybrid_kem_paper/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_paper/otbn/mlkem768:kmac_sha3",
        "//test_hybrid_kem_paper/otbn/mlkem768:mlkem_keypair_s",
    ],
    dexp = "kp.dexp",
    copts = ["--bnmulv_version_id=2"],
)

otbn_sim_test(
    name = "mlkem768_encap_test",
    srcs = ["mlkem_base_encap_test.s"],
    deps = [
        "//test_hybrid_kem_paper/otbn/mlkem768:basemul",
        "//test_hybrid_kem_paper/otbn/mlkem768:cbd",
        "//test_hybrid_kem_paper/otbn/mlkem768:ntt",
        "//test_hybrid_kem_paper/otbn/mlkem768:intt",
        "//test_hybrid_kem_paper/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_paper/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_paper/otbn/mlkem768:kmac_sha3",
        "//test_hybrid_kem_paper/otbn/mlkem768:mlkem_encap_s",
    ],
    dexp = "enc.dexp",
    copts = ["--bnmulv_version_id=2"],
)

otbn_sim_test(
    name = "mlkem768_decap_test",
    srcs = ["mlkem_base_decap_test.s"],
    deps = [
        "//test_hybrid_kem_paper/otbn/mlkem768:basemul",
        "//test_hybrid_kem_paper/otbn/mlkem768:cbd",
        "//test_hybrid_kem_paper/otbn/mlkem768:ntt",
        "//test_hybrid_kem_paper/otbn/mlkem768:intt",
        "//test_hybrid_kem_paper/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_paper/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly",
        "//test_hybrid_kem_paper/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_paper/otbn/mlkem768:kmac_sha3",
        "//test_hybrid_kem_paper/otbn/mlkem768:mlkem_decap_s",
        "//test_hybrid_kem_paper/otbn/mlkem768:mlkem_encap_s",
    ],
    dexp = "dec.dexp",
    copts = ["--bnmulv_version_id=2"],
)

otbn_sim_test(
    name = "p256_ecdh_test",
    srcs = ["p256_ecdh_shared_key_test.s"],
    deps = [
        "//sw/otbn/crypto:p256_base",
        "//sw/otbn/crypto:p256_isoncurve",
        "//sw/otbn/crypto:p256_isoncurve_proj",
        "//sw/otbn/crypto:p256_shared_key",
    ],
    dexp = "p256.dexp",
)

otbn_sim_test(
    name = "hkdf_test",
    srcs = ["hkdf_test.s"],
    deps = [
        "//test_hybrid_kem_paper/otbn/hkdf:hkdf_sha3_256_lib",
        "//test_hybrid_kem_paper/otbn/hkdf:hmac_sha3_lib",
        "//test_hybrid_kem_paper/otbn/hkdf:kmac_sha3_lib",
    ],
    dexp = "hkdf_test.dexp",
)
