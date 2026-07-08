load("//rules:otbn.bzl", "otbn_binary")

package(default_visibility = ["//visibility:public"])

otbn_binary(name = "bench_empty_p256_1", srcs = ["bench_empty_p256_1.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_empty_p256_3", srcs = ["bench_empty_p256_3.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_p256_field_mul", srcs = ["bench_p256_field_mul.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_p256_field_sqr", srcs = ["bench_p256_field_sqr.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_p256_field_add", srcs = ["bench_p256_field_add.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_p256_field_sub", srcs = ["bench_p256_field_sub.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_p256_field_inv", srcs = ["bench_p256_field_inv.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/p256:p256_base_lib",
])

otbn_binary(name = "bench_empty_mlkem", srcs = ["bench_empty_mlkem.s"])

otbn_binary(name = "bench_mlkem_ntt", srcs = ["bench_mlkem_ntt.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/mlkem768:ntt",
])

otbn_binary(name = "bench_mlkem_intt", srcs = ["bench_mlkem_intt.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/mlkem768:intt",
])

otbn_binary(name = "bench_mlkem_basemul", srcs = ["bench_mlkem_basemul.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/mlkem768:basemul",
])

otbn_binary(name = "bench_empty_keccak", srcs = ["bench_empty_keccak.s"])

otbn_binary(name = "bench_keccak_f1600", srcs = ["bench_keccak_f1600.s"], deps = [
    "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/hkdf:sha3_shake_lib",
])
