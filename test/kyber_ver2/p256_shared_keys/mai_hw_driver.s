/* ================================================================
 * mai_hw_driver.s
 *
 * P-256 MAI 硬件极简驱动 —— 仅封装 MAI WSR/CSR 操作
 * ================================================================ */

.section .text

/* ----------------------------------------------------------------
 * mai_load_mod: 加载 256-bit 模数到 MOD WSR
 * x10 = ptr to 256-bit modulus (8 words, little-endian)
 * clobber: x4, w0
 * ---------------------------------------------------------------- */
.globl mai_load_mod
mai_load_mod:
    li      x4, 0
    bn.lid  x4, 0(x10)
    bn.wsrw MOD, w0
    ret

/* ----------------------------------------------------------------
 * mai_run_op: 执行一次 MAI 硬件运算 (通用接口)
 *
 * 调用前必须:
 *   1. 已 mai_load_mod 设置 MOD
 *   2. 设置 x11 = ptr in0_s0, x12 = ptr in0_s1
 *            x13 = ptr in1_s0, x14 = ptr in1_s1
 *            x15 = ptr out_res_s0, x16 = ptr out_res_s1
 *   3. x10 = MAI operation (11=A2B, 16=B2A, 12=secAddMod, 23=secAdd)
 *
 * clobber: x4, x5, x6, w0
 * ---------------------------------------------------------------- */
.globl mai_run_op
mai_run_op:
    /* 等待 MAI_READY */
    addi    x6, x0, 2
.wait_mai_ready:
    csrrs   x5, 0xfca, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_mai_ready

    /* 加载四个输入份额到 WSR */
    li      x4, 0
    bn.lid  x4, 0(x11)
    bn.wsrw 12, w0

    bn.lid  x4, 0(x12)
    bn.wsrw 13, w0

    bn.lid  x4, 0(x13)
    bn.wsrw 14, w0

    bn.lid  x4, 0(x14)
    bn.wsrw 15, w0

    /* mai_ctrl = (operation << 1) | MAI_START */
    slli    x5, x10, 1
    addi    x5, x5, 1
    csrrw   x0, 0x7e0, x5

    /* 等待 MAI_BUSY 清零 */
.wait_mai_done:
    csrrs   x5, 0xfca, x0
    andi    x5, x5, 1
    bne     x5, x0, .wait_mai_done

    /* 读取结果 */
    bn.wsrr w0, 10
    bn.sid  x4, 0(x15)

    bn.wsrr w0, 11
    bn.sid  x4, 0(x16)
    ret

/* ----------------------------------------------------------------
 * mai_p256_b2a: P-256 B2A (布尔→算术掩码转换)
 *
 * 调用前: x11-x16 = in/out 指针 (同 mai_run_op)
 * ---------------------------------------------------------------- */
.globl mai_p256_b2a
mai_p256_b2a:
    la      x10, p256_p
    jal     x1, mai_load_mod
    addi    x10, x0, 16          /* MAI_OPERATION B2A */
    jal     x1, mai_run_op
    ret

/* ----------------------------------------------------------------
 * mai_p256_a2b: P-256 A2B (算术→布尔掩码转换)
 *
 * 调用前: x11-x16 = in/out 指针 (同 mai_run_op)
 * ---------------------------------------------------------------- */
.globl mai_p256_a2b
mai_p256_a2b:
    la      x10, p256_p
    jal     x1, mai_load_mod
    addi    x10, x0, 11          /* MAI_OPERATION A2B */
    jal     x1, mai_run_op
    ret

/* p256_p and zero_buf are defined externally (in p256_base.s / caller).
 * This driver is pure code — no data section. */
