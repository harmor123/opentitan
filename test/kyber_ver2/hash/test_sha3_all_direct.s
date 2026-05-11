/* ================================================================
 * test_sha3_all_direct.s
 *
 * 依赖: keccak_direct.s 
 * ================================================================ */

.section .text.start
.globl main
main:
    /* ---- 基础测试 ---- */
    jal     x1, test_sha3_256_empty
    jal     x1, test_sha3_512_empty
    jal     x1, test_sha3_256_msg
    jal     x1, test_sha3_512_msg
    jal     x1, test_shake128_msg
    jal     x1, test_shake256_msg

    /* ---- 进阶边缘测试 ---- */
    jal     x1, test_sha3_256_32b
    jal     x1, test_sha3_256_33b
    jal     x1, test_sha3_256_35b
    jal     x1, test_sha3_256_64b
    jal     x1, test_shake128_64b_run

    ecall

/* ==================== 基础测试函数 ==================== */
test_sha3_256_empty:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, sha3_256_empty_out
    jal     x1, sha3_final
    ret

test_sha3_512_empty:
    li      x11, 64
    jal     x1, sha3_init
    la      x11, sha3_512_empty_out
    jal     x1, sha3_final
    ret

test_sha3_256_msg:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    la      x11, sha3_256_msg_out
    jal     x1, sha3_final
    ret

test_sha3_512_msg:
    li      x11, 64
    jal     x1, sha3_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    la      x11, sha3_512_msg_out
    jal     x1, sha3_final
    ret

test_shake128_msg:
    jal     x1, shake128_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    la      x11, shake128_out
    jal     x1, shake_out
    ret

test_shake256_msg:
    jal     x1, shake256_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    la      x11, shake256_out
    jal     x1, shake_out
    ret

/* ==================== 进阶边缘测试函数 ==================== */
test_sha3_256_32b:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_32b
    li      x12, 32
    jal     x1, sha3_update
    la      x11, sha3_256_32b_out
    jal     x1, sha3_final
    ret

test_sha3_256_33b:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_33b
    li      x12, 33
    jal     x1, sha3_update
    la      x11, sha3_256_33b_out
    jal     x1, sha3_final
    ret

test_sha3_256_35b:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_35b
    li      x12, 35
    jal     x1, sha3_update
    la      x11, sha3_256_35b_out
    jal     x1, sha3_final
    ret

test_sha3_256_64b:
    li      x11, 32
    jal     x1, sha3_init
    la      x11, msg_64b
    li      x12, 64
    jal     x1, sha3_update
    la      x11, sha3_256_64b_out
    jal     x1, sha3_final
    ret

/* 挤出 64 字节，分两次独立写出 */
test_shake128_64b_run:
    jal     x1, shake128_init
    la      x11, my_message
    li      x12, 8
    jal     x1, sha3_update
    jal     x1, shake_xof
    la      x11, shake128_64b_out_1
    jal     x1, shake_out
    la      x11, shake128_64b_out_2
    jal     x1, shake_out
    ret

/* ==================== 数据段 ==================== */
.data

.balign 32
my_message:
    .word 0x74616877
    .word 0x206f6420

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
