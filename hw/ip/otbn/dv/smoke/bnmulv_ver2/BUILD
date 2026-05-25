# Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of
# "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN"
# (https://eprint.iacr.org/2025/2028)
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules:otbn.bzl", "otbn_binary")

package(default_visibility = ["//visibility:public"])

otbn_binary(
    name = "bnmulv8S_smoke_test",
    srcs = [
        "bnmulv8S_smoke_test.s",
    ],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bnmulv16H_smoke_test",
    srcs = [
        "bnmulv16H_smoke_test.s",
    ],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bnmulvl8S_smoke_test",
    srcs = [
        "bnmulvl8S_smoke_test.s",
    ],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_shv_smoke_test",
    srcs = ["bn_shv_smoke_test.s"],
    copts = ["--bnmulv_version_id=2"],
)


otbn_binary(
    name = "bnmulvl16H_smoke_test",
    srcs = [
        "bnmulvl16H_smoke_test.s",
    ],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_addvm_16H_smoke_test",
    srcs = ["bn_addvm_16H_smoke_test.s"],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_mulqacc_long_test",
    srcs = ["bn_mulqacc_long_test.s"],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_mulv_acc_chain",
    srcs = ["bn_mulv_acc_chain.s"],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_mulv_lane_test",
    srcs = ["bn_mulv_lane_test.s"],
    copts = ["--bnmulv_version_id=2"],
)

otbn_binary(
    name = "bn_trn_smoke_test",
    srcs = ["bn_trn_smoke_test.s"],
    copts = ["--bnmulv_version_id=2"],
)
