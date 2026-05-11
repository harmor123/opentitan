/* ================================================================
 * test_sha3_all_hardware.s
 *
 * 适配极简 KMAC 驱动的全量及边缘测试套件
 * 特点：彻底抛弃 212 字节软件 context，纯硬件状态机流转
 * 依赖：kmac_sha3_template.s (提供所有 kmac_ 和 keccak_ 接口)
 * ================================================================ */

.section .text.start
.globl main
main:
    la      x2, stack_end
    addi    x2, x2, -64

    /* ---- 基础测试 ---- */
    jal     x1, test_sha3_256_empty
    jal     x1, test_sha3_512_empty
    jal     x1, test_sha3_256_msg
    jal     x1, test_sha3_512_msg
    jal     x1, test_shake128_msg
    jal     x1, test_shake256_msg

    /* ---- 进阶边缘测试 (针对 keccak_send_message 的尾部掩码) ---- */
    jal     x1, test_sha3_256_32b
    jal     x1, test_sha3_256_33b
    jal     x1, test_sha3_256_35b
    jal     x1, test_sha3_256_64b
    jal     x1, test_shake128_64b_run

    ecall

/* ==================== 基础测试函数 ==================== */
test_sha3_256_empty:
    addi    x10, x0, 0             /* Mode 0: SHA3-256 */
    jal     x1, kmac_init
    /* 空消息：不调用 keccak_send_message */
    jal     x1, kmac_process
    la      x10, sha3_256_empty_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_512_empty:
    addi    x10, x0, 1             /* Mode 1: SHA3-512 */
    jal     x1, kmac_init
    jal     x1, kmac_process
    la      x10, sha3_512_empty_out
    jal     x1, kmac_squeeze_32B
    /* 512位需要挤出两次 32 字节 */
    jal     x1, kmac_run          /* 驱动硬件产出下一块摘要 */
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_msg:
    addi    x10, x0, 0
    jal     x1, kmac_init
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_256_msg_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_512_msg:
    addi    x10, x0, 1
    jal     x1, kmac_init
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_512_msg_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_run
    addi    x10, x10, 32
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_shake128_msg:
    addi    x10, x0, 2             /* Mode 2: SHAKE128 */
    jal     x1, kmac_init
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, shake128_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_shake256_msg:
    addi    x10, x0, 3             /* Mode 3: SHAKE256 */
    jal     x1, kmac_init
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, shake256_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

/* ==================== 进阶边缘测试函数 ==================== */
test_sha3_256_32b:
    addi    x10, x0, 0
    jal     x1, kmac_init
    la      x10, msg_32b
    addi    x11, x0, 32
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_256_32b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_33b:
    addi    x10, x0, 0
    jal     x1, kmac_init
    la      x10, msg_33b
    addi    x11, x0, 33
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_256_33b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_35b:
    addi    x10, x0, 0
    jal     x1, kmac_init
    la      x10, msg_35b
    addi    x11, x0, 35
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_256_35b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_sha3_256_64b:
    addi    x10, x0, 0
    jal     x1, kmac_init
    la      x10, msg_64b
    addi    x11, x0, 64
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    la      x10, sha3_256_64b_out
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
    ret

test_shake128_64b_run:
    addi    x10, x0, 2
    jal     x1, kmac_init
    la      x10, my_message
    addi    x11, x0, 8
    jal     x1, keccak_send_message
    jal     x1, kmac_process
    /* 第一次挤出 32 字节 */
    la      x10, shake128_64b_out_1
    jal     x1, kmac_squeeze_32B
    /* 第二次挤出 32 字节 (触发 CMD_RUN) */
    jal     x1, kmac_run
    la      x10, shake128_64b_out_2
    jal     x1, kmac_squeeze_32B
    jal     x1, kmac_done
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

/* 基础测试输出缓冲区 */
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
