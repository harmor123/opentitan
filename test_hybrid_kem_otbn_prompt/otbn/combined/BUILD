load("//rules:otbn.bzl", "otbn_binary", "otbn_library", "otbn_sim_test")

# ================================================================
# ML-KEM-768 combined binary (keypair + encap + decap)
# Shared libs compiled once; mode dispatch via mlkem_entry.s
# ================================================================

otbn_binary(
    name = "mlkem_combined",
    srcs = ["mlkem_entry.s"],
    args = ["--bnmulv_version_id=2"],
    deps = [
        ":mlkem_phases",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
    ],
)

package(default_visibility = ["//visibility:public"])

exports_files(["test_mode1.s"])

# Entry point library — provides main, mode, stack
otbn_library(
    name = "hybrid_entry",
    srcs = ["hybrid_entry.s"],
)

# P-256 test data (pre-filled d0, d1, x, y)
otbn_library(
    name = "p256_test_data",
    srcs = ["p256_ecdh_shared_key_test_data.s"],
)

# ML-KEM renamed phase files + test data — compiled with ver2
otbn_library(
    name = "mlkem_phases",
    srcs = [
        "mlkem_keypair.s",
        "mlkem_encap.s",
        "mlkem_decap.s",
        "kp_test_data.s",
        "enc_test_data.s",
        "dec_test_data.s",
    ],
    copts = ["--bnmulv_version_id=2"],
)

# Combined binary: p256 + hkdf (v1) + ML-KEM (ver2 via deps)
otbn_binary(
    name = "hybrid_kem_all",
    srcs = [
        # Entry point
        "hybrid_entry.s",
        # P-256 ECDH (v1, no ver2 needed)
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_base.s",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_isoncurve_proj.s",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_shared_key.s",
        # HKDF (v1, no ver2 needed)
        "hkdf_sha3_256.s",
        "hmac_sha3.s",
        # Test data (v1)
        "p256_ecdh_shared_key_test_data.s",
        "hkdf_test_data.s",
    ],
    deps = [
        # ML-KEM shared libraries (ver2 via copts in mlkem768 BUILD)
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
        # Renamed ML-KEM phase files (ver2 via local otbn_library)
        ":mlkem_phases",
    ],
)

# HKDF library (combined local copies)
otbn_library(
    name = "hkdf_combined",
    srcs = [
        "hkdf_sha3_256.s",
        "hmac_sha3.s",
        "hkdf_test_data.s",
    ],
)

# Test: mode 1 (KeyGen) dispatch — ISS only
otbn_sim_test(
    name = "combined_mode1_keypair",
    srcs = ["test_mode1.s"],
    copts = ["--bnmulv_version_id=2"],
    deps = [
        ":hybrid_entry",
        ":mlkem_phases",
        ":p256_test_data",
        ":hkdf_combined",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_base",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_isoncurve_proj",
        "//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_shared_key",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:basemul",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:cbd",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:ntt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:intt",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:poly_gen_matrix",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_keys",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:pack_ciphertext",
        "//test_hybrid_kem_otbn_prompt/otbn/mlkem768:kmac_sha3",
    ],
)
