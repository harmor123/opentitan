load("@rules_python//python:defs.bzl", "py_binary")
load("//rules:otbn.bzl", "otbn_autogen_sim_test", "otbn_library")

package(default_visibility = ["//visibility:public"])

py_binary(
    name = "mul_testgen",
    srcs = ["mul_testgen.py"],
    deps = [
        "//hw/ip/otbn/util/shared:testgen",
    ],
)

otbn_library(
    name = "mul",
    srcs = ["mul.s"],
)


[
    otbn_autogen_sim_test(
        name = "mul_test" + str(i),
        srcs = ["mul_test.s"],
        seed = i,
        testgen = ":mul_testgen",
        deps = [
            ":mul",
        ],
    )
    for i in range(1)
]