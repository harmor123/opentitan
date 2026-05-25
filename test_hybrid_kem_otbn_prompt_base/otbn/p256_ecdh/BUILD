# BUILD — P-256 ECDH OTBN app (ver0_base pure software)
#
# No KMAC dependency — P-256 code is identical to reference.
# Libraries for otbn_sim_test targets.

load("//rules:otbn.bzl", "otbn_binary", "otbn_library")

# ---- Libraries (for otbn_sim_test deps) ----

otbn_library(
    name = "p256_base",
    srcs = ["p256_base.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "p256_isoncurve_proj",
    srcs = ["p256_isoncurve_proj.s"],
    visibility = ["//visibility:public"],
)

otbn_library(
    name = "p256_shared_key",
    srcs = ["p256_shared_key.s"],
    visibility = ["//visibility:public"],
)

# ---- OTBN binary (for Ibex integration) ----

otbn_binary(
    name = "p256_ecdh_ver0",
    srcs = [
        "p256_ecdh_test.s",
        "p256_shared_key.s",
        "p256_base.s",
        "p256_isoncurve_proj.s",
    ],
    visibility = ["//visibility:public"],
)
