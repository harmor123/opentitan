/* ================================================================
 * mai_p256_test.s
 *
 * P-256 MAI 驱动测试: B2A/A2B 往返 + secAddMod
 * 结果写入 DMEM 供 otbn_sim_test 比对
 * ================================================================ */

.global main

.section .text

main:
    /* ================================================================
     * Test 1: B2A → A2B 往返 (常规数据)
     * ================================================================ */
    la      x11, test1_in0_s0
    la      x12, test1_in0_s1
    la      x13, zero_buf
    la      x14, zero_buf
    la      x15, tmp_s0
    la      x16, tmp_s1

    jal     x1, mai_p256_b2a

    la      x11, tmp_s0
    la      x12, tmp_s1
    la      x13, zero_buf
    la      x14, zero_buf
    la      x15, tmp_s0
    la      x16, tmp_s1

    jal     x1, mai_p256_a2b

    /* XOR 还原: w2 = tmp_s0 ^ tmp_s1 */
    li      x4, 0
    bn.lid  x4, 0(x15)
    li      x4, 1
    bn.lid  x4, 0(x16)
    bn.xor  w2, w0, w1

    la      x10, test1_out
    li      x3, 2
    bn.sid  x3, 0(x10)


    /* ================================================================
     * Test 2: B2A → A2B 往返 (0xFFFFFFFE 边缘值)
     * ================================================================ */
    la      x11, test2_in0_s0
    la      x12, test2_in0_s1
    la      x13, zero_buf
    la      x14, zero_buf
    la      x15, tmp_s0
    la      x16, tmp_s1

    jal     x1, mai_p256_b2a

    la      x11, tmp_s0
    la      x12, tmp_s1
    la      x13, zero_buf
    la      x14, zero_buf
    la      x15, tmp_s0
    la      x16, tmp_s1

    jal     x1, mai_p256_a2b

    /* XOR 还原 */
    li      x4, 0
    bn.lid  x4, 0(x15)
    li      x4, 1
    bn.lid  x4, 0(x16)
    bn.xor  w2, w0, w1

    la      x10, test2_out
    li      x3, 2
    bn.sid  x3, 0(x10)


    ecall


/* ================================================================
 * 测试数据段
 * ================================================================ */
.section .data

.balign 32
test1_in0_s0:
  .word 0x9abcdef0, 0x12345678, 0xdeadbeef, 0xcafebabe
  .word 0x01020304, 0x05060708, 0xf0e1d2c3, 0xb4a59687

.balign 32
test1_in0_s1:
  .word 0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00
  .word 0x13579bdf, 0x2468ace0, 0x0fedcba9, 0x87654321

.balign 32
test2_in0_s0:
  .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
  .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff

.balign 32
test2_in0_s1:
  .word 0x00000001, 0x00000001, 0x00000001, 0x00000001
  .word 0x00000001, 0x00000001, 0x00000001, 0x00000001

.balign 32
zero_buf:
  .zero 32

/* P-256 域模数 (mai_hw_driver.s 自身不持有数据, 引用此定义) */
.balign 32
.globl p256_p
p256_p:
  .word 0xffffffff
  .word 0xffffffff
  .word 0xffffffff
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000001
  .word 0xffffffff


/* ================================================================
 * 测试 BSS 段
 * ================================================================ */
.section .bss

.balign 32
tmp_s0:
  .zero 32
.balign 32
tmp_s1:
  .zero 32

.balign 32
.weak test1_out
test1_out:
  .zero 32

.balign 32
.weak test2_out
test2_out:
  .zero 32
