# BUILD — HKDF-SHA3-256 OTBN app (ver0_base pure software)
#
# Uses software sha3_init/update/final (no KMAC hardware).
# DMEM-based interface for Ibex host integration.

load("//rules:otbn.bzl", "otbn_binary", "otbn_library")

# ---- Libraries (for otbn_sim_test deps) ----

otbn_library(
    name = "sha3_shake",
    srcs = ["sha3_shake.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "hmac_sha3",
    srcs = ["hmac_sha3.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "hkdf_sha3_256_lib",
    srcs = ["hkdf_sha3_256.s"],
    visibility = ["//visibility:public"],
)

# ---- OTBN binary (for Ibex integration) ----

otbn_binary(
    name = "hkdf_sha3_256_ver0",
    srcs = [
        "hkdf_wrapper.s",
        "hkdf_sha3_256.s",
        "hmac_sha3.s",
        "sha3_shake.s",
    ],
    visibility = ["//visibility:public"],
)
