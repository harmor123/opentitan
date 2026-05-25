# BUILD — ML-KEM-768 OTBN apps (ver0_base pure software)
#
# Uses software sha3_init/update/final (no KMAC hardware, no BN vector extensions).
# Three binaries: keypair, encap, decap — each self-contained.
# Libraries for otbn_sim_test targets.

load("//rules:otbn.bzl", "otbn_binary", "otbn_library")

# ---- ML-KEM common libraries ----
# Note: symmetric.s provides sha3_init/update/final/keccakf/shake_{xof,out}
# for ML-KEM.  No separate sha3_shake library needed here.

otbn_library(
    name = "basemul",
    srcs = ["basemul.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "cbd",
    srcs = ["cbd.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "intt",
    srcs = ["intt.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "ntt",
    srcs = ["ntt.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "pack_keys",
    srcs = ["pack_keys.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "pack_ciphertext",
    srcs = ["pack_ciphertext.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "poly",
    srcs = ["poly.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "poly_gen_matrix",
    srcs = ["poly_gen_matrix.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "symmetric",
    srcs = ["symmetric.s"],
    visibility = ["//visibility:public"],
)

# ---- ML-KEM algorithm libraries ----

otbn_library(
    name = "mlkem_keypair",
    srcs = ["mlkem_keypair_kp.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "mlkem_encap",
    srcs = ["mlkem_encap.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "mlkem_decap",
    srcs = ["mlkem_decap.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "mlkem_decap_encap",
    srcs = ["mlkem_decap_encap.s"],
    visibility = ["//visibility:public"],
)

# ---- OTBN binaries (for Ibex integration) ----

MLKEM_COMMON_SRCS = [
    "basemul.s",
    "cbd.s",
    "intt.s",
    "ntt.s",
    "pack_keys.s",
    "poly.s",
    "poly_gen_matrix.s",
    "symmetric.s",
]

otbn_binary(
    name = "mlkem768_keypair_ver0",
    srcs = [
        "mlkem_keypair_test.s",
        "mlkem_keypair_kp.s",
    ] + MLKEM_COMMON_SRCS,
    visibility = ["//visibility:public"],
)

otbn_binary(
    name = "mlkem768_encap_ver0",
    srcs = [
        "mlkem_encap_test.s",
        "mlkem_encap.s",
        "pack_ciphertext.s",
    ] + MLKEM_COMMON_SRCS,
    visibility = ["//visibility:public"],
)

otbn_binary(
    name = "mlkem768_decap_ver0",
    srcs = [
        "mlkem_decap_test.s",
        "mlkem_decap.s",
        "mlkem_decap_encap.s",
        "pack_ciphertext.s",
    ] + MLKEM_COMMON_SRCS,
    visibility = ["//visibility:public"],
)
