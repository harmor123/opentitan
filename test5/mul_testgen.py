#!/usr/bin/env python3
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import argparse
import random
from typing import TextIO, Optional
from hw.ip.otbn.util.shared.testgen import write_test_data

# 每个操作数包含 1023 个 256-bit limb（32 字节），总大小 32736 字节（≈31.97 KiB）
OPERAND_LIMBS = 1016
LIMB_NBYTES = 32

def gen_mul_test(seed: Optional[int], data_file: TextIO, exp_file: TextIO):
    if seed is not None:
        random.seed(seed)
    operand_nbytes = LIMB_NBYTES * OPERAND_LIMBS
    x = random.getrandbits(8 * operand_nbytes)
    y = random.getrandbits(8 * operand_nbytes)
    x_bytes = int.to_bytes(x, byteorder='little', length=operand_nbytes)
    y_bytes = int.to_bytes(y, byteorder='little', length=operand_nbytes)

    inputs = {'x': x_bytes, 'y': y_bytes}
    write_test_data(inputs, data_file)

    # 不生成期望输出，测试仅依赖内存越界检测
    exp_file.write("")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--seed',
                        type=int,
                        required=False,
                        help='Seed value for pseudorandomness.')
    parser.add_argument('data',
                        metavar='FILE',
                        type=argparse.FileType('w'),
                        help='Output file for input DMEM values.')
    parser.add_argument('exp',
                        metavar='FILE',
                        type=argparse.FileType('w'),
                        help='Output file for expected register values.')
    args = parser.parse_args()

    gen_mul_test(args.seed, args.data, args.exp)