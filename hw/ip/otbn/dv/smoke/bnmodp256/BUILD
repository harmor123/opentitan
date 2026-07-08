load("//rules:otbn.bzl", "otbn_binary")

package(default_visibility = ["//visibility:public"])

otbn_binary(
    name = "modp256_smoke_test",
    srcs = ["modp256_smoke_test.s"],
    copts = ["--bnmulv_version_id=2"],
)
