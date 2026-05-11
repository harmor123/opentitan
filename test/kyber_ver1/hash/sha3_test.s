/* ================================================================
 * test_sha3_all_hardware.s
 *
 * SHA3 / SHAKE 全量及边缘测试套件（硬件加速驱动版）
 *
 * 依赖: sha3_hw.s
 * 测试项:
 *   基础:
 *     1~6. SHA3-256/512 空消息及带消息，SHAKE128/256 挤出
 *   进阶边缘 (针对 Kyber 强化):
 *     7.   SHA3-256 恰好 32 字节 (测试循环正常结束)
 *     8.   SHA3-256 33 字节 (测试 1 字节尾部掩码)
 *     9.   SHA3-256 35 字节 (测试 3 字节尾部掩码)
 *     10.  SHA3-256 64 字节 (测试多完整块)
 *     11.  SHAKE128 连续挤出 64 字节 (★触发 CMD_RUN)
 * ================================================================ */

.section .text.start
.globl main
main:
    la      x2, stack_end
    addi    x2, x2, -64

    /* ---- 基础测试 ---- */
    /* ---- 1. SHA3-256 空消息 ---- */
    jal     x1, test_sha3_256_empty

    /* ---- 2. SHA3-512 空消息 ---- */
    jal     x1, test_sha3_512_empty

    /* ---- 3. SHA3-256 带消息 ---- */
    jal     x1, test_sha3_256_msg

    /* ---- 4. SHA3-512 带消息 ---- */
    jal     x1, test_sha3_512_msg

    /* ---- 5. SHAKE128 挤出 32 字节 ---- */
    jal     x1, test_shake128_msg

    /* ---- 6. SHAKE256 挤出 32 字节 ---- */
    jal     x1, test_shake256_msg

    /* ---- 进阶边缘测试 ---- */
    /* ---- 7. 恰好 32 字节 (测试循环完美退出) ---- */
    jal     x1, test_sha3_256_32b

    /* ---- 8. 33 字节 (测试 1 字节尾部掩码 is1) ---- */
    jal     x1, test_sha3_256_33b

    /* ---- 9. 35 字节 (测试 3 字节尾部掩码 is3) ---- */
    jal     x1, test_sha3_256_35b

    /* ---- 10. 64 字节 (测试连续两个完整块) ---- */
    jal     x1, test_sha3_256_64b

    /* ---- 11. SHAKE128 挤出 64 字节 (★核心：触发 CMD_RUN) ---- */
    jal     x1, test_shake128_64b_run

    ecall

/* ==================== 基础测试函数 ==================== */
test_sha3_256_empty:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, sha3_256_empty_out
    jal     x1, sha3_final
    ret

test_sha3_512_empty:
    la      x10, context
    li      x11, 64
    jal     x1, sha3_init
    la      x11, sha3_512_empty_out
    jal     x1, sha3_final
    ret

test_sha3_256_msg:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    la      x11, sha3_256_msg_out
    jal     x1, sha3_final
    ret

test_sha3_512_msg:
    la      x10, context
    li      x11, 64
    jal     x1, sha3_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    la      x11, sha3_512_msg_out
    jal     x1, sha3_final
    ret

test_shake128_msg:
    la      x10, context
    jal     x1, shake128_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    la      x11, shake128_out
    li      x12, 32
    jal     x1, shake_out
    jal     x1, kmac_release
    ret

test_shake256_msg:
    la      x10, context
    jal     x1, shake256_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    la      x11, shake256_out
    li      x12, 32
    jal     x1, shake_out
    jal     x1, kmac_release
    ret

/* ==================== 进阶边缘测试函数 ==================== */
test_sha3_256_32b:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_32b
    li      x12, 32
    jal     x1, sha3_update
    la      x11, sha3_256_32b_out
    jal     x1, sha3_final
    ret

test_sha3_256_33b:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_33b
    li      x12, 33
    jal     x1, sha3_update
    la      x11, sha3_256_33b_out
    jal     x1, sha3_final
    ret

test_sha3_256_35b:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_35b
    li      x12, 35
    jal     x1, sha3_update
    la      x11, sha3_256_35b_out
    jal     x1, sha3_final
    ret

test_sha3_256_64b:
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_64b
    li      x12, 64
    jal     x1, sha3_update
    la      x11, sha3_256_64b_out
    jal     x1, sha3_final
    ret

/* 挤出 64 字节，强制触发硬件的 CMD_RUN 状态 */
test_shake128_64b_run:
    la      x10, context
    jal     x1, shake128_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    /* 第一次 32 字节 */
    la      x11, shake128_64b_out_1
    li      x12, 32
    jal     x1, shake_out
    /* 第二次 32 字节 (此处底层必定执行 0x31 CMD_RUN) */
    la      x11, shake128_64b_out_2
    li      x12, 32
    jal     x1, shake_out
    jal     x1, kmac_release
    ret

/* ==================== 数据段 ==================== */
.data

/* 栈空间 */
.balign 32
.global stack
stack:
    .zero 1024
stack_end:

/* 基础测试消息 "what do " (8 bytes) */
.balign 32
my_message:
    .word 0x74616877    /* "what" little-endian */
    .word 0x206f6420    /* " do " little-endian */
    

/* 边缘测试专用输入数据 */
.balign 32
msg_32b:
    .zero 32

.balign 32
msg_33b:
    .zero 32
    .word 0x00000001

.balign 32
msg_35b:
    .zero 32
    .word 0x00030201

.balign 32
msg_64b:
    .zero 64

/* 基础测试输出缓冲区（必须 32 字节对齐） */
.balign 32
sha3_256_empty_out:   .zero 32

.balign 32
sha3_512_empty_out:   .zero 64

.balign 32
sha3_256_msg_out:     .zero 32

.balign 32
sha3_512_msg_out:     .zero 64

.balign 32
shake128_out:         .zero 32

.balign 32
shake256_out:         .zero 32

/* 边缘测试专用输出缓冲区 */
.balign 32
sha3_256_32b_out:     .zero 32

.balign 32
sha3_256_33b_out:     .zero 32

.balign 32
sha3_256_35b_out:     .zero 32

.balign 32
sha3_256_64b_out:     .zero 32

.balign 32
shake128_64b_out_1:   .zero 32

.balign 32
shake128_64b_out_2:   .zero 32
