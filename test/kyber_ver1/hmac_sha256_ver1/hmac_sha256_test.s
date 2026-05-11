.section .text.start
.globl main
main:
    la      x2, stack_end

    /* 为 hmac 函数分配局部栈空间 */
    addi    x2, x2, -64

    /* 准备 HMAC 测试参数 */
    la      x10, my_key
    li      x11, 20          /* key_len = 20 bytes */
    la      x12, my_message
    li      x13, 8           /* msg_len = 8 bytes ("Hi There") */
    la      x14, my_hmac

    jal     x1, hmac
    ecall

.data

/* 栈空间 */
.balign 32
.global stack
stack:
    .zero 1024
stack_end:

/* -----------------------------------------------
 * 以下缓冲区为硬件 KMAC HMAC 所必需
 * ----------------------------------------------- */
.balign 32
.globl inner_hash
inner_hash:
    .zero 32

.balign 32
.globl key_buf
key_buf:
    .zero 200

.balign 32
.globl ipad
ipad:
    .zero 200

.balign 32
.globl opad
opad:
    .zero 200

/* 测试数据 */
.balign 32
my_key:
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b

.balign 32
my_message:
    .word 0x74616877        /* "what" */
    .word 0x206f6420        /* " do " (注意空格) */

.balign 32
my_hmac:
    .zero 32