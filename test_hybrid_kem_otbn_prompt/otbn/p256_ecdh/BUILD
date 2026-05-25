load("//rules:otbn.bzl", "otbn_binary", "otbn_library")

package(default_visibility = ["//visibility:public"])

otbn_library(
    name = "p256_base",
    srcs = ["p256_base.s"],
)

otbn_library(
    name = "p256_isoncurve_proj",
    srcs = ["p256_isoncurve_proj.s"],
)

otbn_library(
    name = "p256_shared_key",
    srcs = ["p256_shared_key.s"],
)

otbn_binary(
    name = "p256_ecdh",
    srcs = [
        "p256_base.s", "p256_isoncurve_proj.s", "p256_shared_key.s",
        "//test_hybrid_kem_otbn_prompt/otbn/test:p256_ecdh_shared_key_test.s",
    ],
)
