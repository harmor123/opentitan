/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * 大数乘法测试，使用 1016 个 32 字节 limb 的操作数。
 * 输入 x 和 y 由测试生成器提供，结果存入 result 缓冲区。
 * 此测试旨在验证内存是否扩展至 128 KiB，不检查计算结果正确性。
 */

.section .text.start
main:
  /* 初始化全零寄存器 */
  bn.xor  w31, w31, w31

  /* 操作数 limb 计数（1024） */
  li      x30, 1016
  li      x31, 1016

  /* 计算乘法：dmem[result] = mul(dmem[x], dmem[y]) */
  la      x10, x
  la      x11, y
  la      x12, result
  jal     x1, bignum_mul

  ecall

.data

/* 结果缓冲区，2*1016*32 = 65024 字节 */
.balign 32
result:
.zero 65024