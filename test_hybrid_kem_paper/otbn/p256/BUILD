load("//rules:otbn.bzl", "otbn_binary")

package(default_visibility = ["//visibility:public"])

otbn_binary(
    name = "p256_ecdh_shared_key",
    srcs = [
        "p256_ecdh_shared_key_test.s",
        "p256_base.s",
        "p256_isoncurve.s",
        "p256_isoncurve_proj.s",
        "p256_shared_key.s",
    ],
)
