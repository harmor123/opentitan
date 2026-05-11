/* ================================================================
 * OpenTiton KMAC Hardware Driver – For Kyber (context label)
 *
 * 将软件 sha3 替换为 KMAC 硬件加速，保留完全相同的 API。
 *
 * 所有函数说明均以中文注释形式给出，方便集成与维护。
 *
 * 【 调用要求 —— Ibex-OTBN 内存共享契约】
 * 1. 指针对齐：传入的 x11 (数据指针) 必须严格 32 字节对齐 (256-bit)。
 * 2. 尾部补零：当消息长度 x12 不是 4 的倍数时 (例如 33, 35 字节)，
 *    调用方 必须在将数据写入 OTBN DMEM 时，
 *    手动将不足 4 字节的尾部用 0x00 填充至 4 字节对齐。
 *    (例如：传 33 字节，DMEM 中第 34, 35, 36 字节必须被 Ibex 预先写为 0)。
 * 3. 真实长度：x12 必须传入真实的消息字节数 (如 33)，绝不能传入补零后的长度。
 * 4. 硬件截断：OTBN 内部按向上取整读取 Word，并根据 x12 真实长度动态生成
 *    KMAC_BYTE_STROBE。KMAC 硬件据此自动屏蔽补零字节
 * ================================================================ */

.section .text

/* ---------- KMAC 寄存器地址 ---------- */
.equ KMAC_IF_STATUS,    0x7d9
.equ KMAC_INTR,         0x7da
.equ KMAC_CFG,          0x7db
.equ KMAC_MSG_SEND,     0x7dc
.equ KMAC_CMD,          0x7dd
.equ KMAC_BYTE_STROBE,  0x7de
.equ KMAC_STATUS,       0xfc2
.equ KMAC_DATA_S0,      8
.equ KMAC_DATA_S1,      9

/* ================================================================
 * 全局导出符号
 * ================================================================ */
.globl sha3_init
.globl shake128_init
.globl shake256_init
.globl sha3_update
.globl sha3_final
.globl shake_xof
.globl shake_out
.globl kmac_release

/* ================================================================
 * Name:        sha3_init
 *
 * Description: 初始化 SHA3‑256 或 SHA3‑512 哈希操作。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *              - x11: 输出摘要长度 (32 表示 SHA3‑256, 64 表示 SHA3‑512)
 *
 * Clobbers:    x5, x6, x7
 *              w0, w1 (通过 .init_hw 间接破坏)
 *
 * Flags:       无
 * ================================================================ */
sha3_init:
    sw      x11, 208(x10)          /* 保存 mdlen */
    addi    x5, x0, 200
    slli    x6, x11, 1
    sub     x5, x5, x6
    sw      x5, 204(x10)          /* rsiz = 200 - 2*mdlen */
    addi    x6, x0, 32
    beq     x11, x6, .init_256
    addi    x6, x0, 64
    beq     x11, x6, .init_512
    unimp
.init_256:
    li      x5, 0x04              /* mode=SHA3, kstrength=256 */
    jal     x1, .init_hw
    sw      x0, 200(x10)          /* pt = 0 */
    ret
.init_512:
    li      x5, 0x08              /* mode=SHA3, kstrength=512 */
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret

/* ---- 内部：配置硬件并进入 absorb 状态 (x5 = CFG_SHADOWED) ---- */
.init_hw:
.wait_idle_i:
    csrrs   x6, KMAC_STATUS, x0
    andi    x6, x6, 0x1
    beq     x6, x0, .wait_idle_i
    csrrw   x0, KMAC_CFG, x5
    li      x6, 0x7
    csrrw   x0, KMAC_INTR, x6
    csrrw   x0, KMAC_IF_STATUS, x6
    li      x6, 0x1D              /* CMD start */
    csrrw   x0, KMAC_CMD, x6
.wait_absorb_i:
    csrrs   x6, KMAC_STATUS, x0
    andi    x6, x6, 0x2
    beq     x6, x0, .wait_absorb_i
    ret

/* ================================================================
 * Name:        shake128_init
 *
 * Description: 初始化 SHAKE128 哈希操作 (安全强度 128 位)。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *
 * Clobbers:    x5, x6, x7 (通过 .init_hw)
 *              w0, w1 (通过 .init_hw)
 *
 * Flags:       无
 * ================================================================ */
shake128_init:
    addi    x5, x0, 168
    sw      x5, 204(x10)          /* rsiz = 168 */
    sw      x0, 208(x10)          /* mdlen = 0 */
    li      x5, 0x20              /* mode=SHAKE, kstrength=128 */
    jal     x1, .init_hw
    sw      x0, 200(x10)          /* pt = 0 */
    ret

/* ================================================================
 * Name:        shake256_init
 *
 * Description: 初始化 SHAKE256 哈希操作 (安全强度 256 位)。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *
 * Clobbers:    x5, x6, x7 (通过 .init_hw)
 *              w0, w1 (通过 .init_hw)
 *
 * Flags:       无
 * ================================================================ */
shake256_init:
    addi    x5, x0, 136
    sw      x5, 204(x10)          /* rsiz = 136 */
    sw      x0, 208(x10)          /* mdlen = 0 */
    li      x5, 0x24              /* mode=SHAKE, kstrength=256 */
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret

/* ================================================================
 * Name:        sha3_update
 *
 * Description: 向哈希引擎吸收数据 (支持任意长度)。
 *              利用 Ibex 补零契约：OTBN 放心按 32 字节宽读取，
 *              由硬件 STROBE 精确截断尾部补零。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *              - x11: 指向待吸收数据的指针 (4 字节对齐)
 *              - x12: 数据长度 (真实字节数)
 *
 * Clobbers:    x13..x17, x31
 *              w22, w23
 *
 * Flags:       无
 * ================================================================ */
sha3_update:
    beq     x12, x0, .upd_done
    addi    x13, x11, 0           /* x13: 数据指针 */
    addi    x14, x12, 0           /* x14: 真实剩余长度 */

.upd_loop:
    csrrs   x15, KMAC_IF_STATUS, x0
    andi    x15, x15, 0x1         /* MSG_WRITE_RDY */
    beq     x15, x0, .upd_loop

    addi    x15, x14, -32
    srli    x15, x15, 31          /* x15 = (x14 < 32) ? 1 : 0 */
    bne     x15, x0, .upd_tail

    /* ===== 完整 32 字节块 ===== */
    li      x15, -1               /* STROBE = 0xFFFFFFFF */
    csrrw   x0, KMAC_BYTE_STROBE, x15
    li      x15, 22
    bn.lid  x15, 0(x13)
    bn.wsrw KMAC_DATA_S0, w22
    bn.wsrw KMAC_DATA_S1, w23
    li      x15, 1
    csrrw   x0, KMAC_MSG_SEND, x15  /* 推入完整块 */
    addi    x13, x13, 32
    addi    x14, x14, -32
    bne     x14, x0, .upd_loop
    jal     x0, .upd_done

.upd_tail:
    beq     x14, x0, .upd_done

    /* ===== 尾部块：根据真实长度生成 STROBE 屏蔽补零 ===== */
    li      x15, 0
    li      x16, 1
    addi    x17, x14, 0
.gen_strobe:
    or      x15, x15, x16
    slli    x16, x16, 1
    addi    x17, x17, -1
    bne     x17, x0, .gen_strobe
    csrrw   x0, KMAC_BYTE_STROBE, x15

    /* 安全用 bn.lid 读取 32 字节（Ibex已补零，多余部分被STROBE屏蔽） */
    li      x15, 22
    bn.lid  x15, 0(x13)
    bn.wsrw KMAC_DATA_S0, w22
    bn.wsrw KMAC_DATA_S1, w23
    li      x15, 1
    csrrw   x0, KMAC_MSG_SEND, x15  /* 推入尾部块 */

.upd_done:
    ret

/* ================================================================
 * Name:        sha3_final
 *
 * Description: 完成 SHA‑3 哈希并输出指定长度的摘要。
 *              自动发送 DONE 命令，将 KMAC 释放回 Idle 状态。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *              - x11: 输出缓冲区指针 (32 位对齐)
 *
 * Clobbers:    x5..x7, x15, x28, x14
 *              w10, w11, w22
 *
 * Flags:       无
 * ================================================================ */
sha3_final:
    sw      x1, -4(sp)
    addi    x28, x11, 0
    li      x5, 0x2E
    csrrw   x0, KMAC_CMD, x5
.wait_done:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_done
    lw      x6, 208(x10)
    srli    x7, x6, 3
    addi    x15, x28, 0

    la      x13, tailbuf
    li      x12, 22

.rd_loop:
    beq     x7, x0, .final_done
.wait_digest:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x8
    beq     x5, x0, .wait_digest
    bn.wsrr w10, KMAC_DATA_S0
    bn.wsrr w11, KMAC_DATA_S1
    bn.xor  w10, w10, w11

    bn.mov  w22, w10
    bn.sid  x12, 0(x13)
    lw      x14, 0(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    lw      x14, 4(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    addi    x7, x7, -1
    jal     x0, .rd_loop
.final_done:
    li      x5, 0x16
    csrrw   x0, KMAC_CMD, x5
    lw      x1, -4(sp)
    ret

/* ================================================================
 * Name:        shake_xof
 *
 * Description: 结束吸收阶段，进入 SHAKE 挤出模式。
 *              发送 PROCESS 命令，等待完成并将上下文 pt 清零。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *
 * Clobbers:    x5, x6
 *
 * Flags:       无
 * ================================================================ */
shake_xof:
    li      x5, 0x2E
    csrrw   x0, KMAC_CMD, x5
.wait_done_s:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_done_s
    sw      x0, 200(x10)           /* pt = 0 */
    ret

/* ================================================================
 * Name:        shake_out
 *
 * Description: 从 SHAKE 状态挤出 32 字节输出。
 *              若需要新的排列则自动发送 CMD_RUN。
 *              调用者应在挤出全部所需数据后调用 kmac_release 释放硬件。
 *
 * Arguments:   - x10: 指向 212 字节上下文的指针 (32 字节对齐)
 *              - x11: 输出缓冲区指针 (32 位对齐)
 *
 * Clobbers:    x5..x7, x15, x16
 *              w10, w11, w22
 *
 * Flags:       无
 * ================================================================ */
shake_out:
    sw      x1, -4(sp)
    lw      x16, 200(x10)
    bne     x16, x0, .sq_run
    jal     x0, .sq_read
.sq_run:
    li      x5, 0x31
    csrrw   x0, KMAC_CMD, x5
.sq_read:
    li      x7, 4
    addi    x15, x11, 0

    la      x13, tailbuf
    li      x12, 22

.sq_rd_loop:
    beq     x7, x0, .sq_done
.wait_digest_out:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x8
    beq     x5, x0, .wait_digest_out
    bn.wsrr w10, KMAC_DATA_S0
    bn.wsrr w11, KMAC_DATA_S1
    bn.xor  w10, w10, w11
    bn.mov  w22, w10
    bn.sid  x12, 0(x13)
    lw      x14, 0(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    lw      x14, 4(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    addi    x7, x7, -1
    jal     x0, .sq_rd_loop
.sq_done:
    li      x16, 1
    sw      x16, 200(x10)
    lw      x1, -4(sp)
    ret

/* ================================================================
 * Name:        kmac_release
 *
 * Description: 发送 CMD_DONE 将 KMAC 硬件从 squeeze 状态释放回 Idle。
 *              所有使用 SHAKE 挤出后必须调用此函数，以便下次操作能正常初始化。
 *
 * Arguments:   无 (操作对象为 KMAC 硬件，与上下文无关)
 *
 * Clobbers:    x5
 *
 * Flags:       无
 * ================================================================ */
kmac_release:
    li      x5, 0x16               /* CMD_DONE */
    csrrw   x0, KMAC_CMD, x5
.wait_idle_rel:
    csrrs   x5, KMAC_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_idle_rel
    ret

/* ================================================================
 * 数据段
 * ================================================================ */
.section .data
.balign 32
.globl context
context:
    .zero 212                     /* 哈希上下文，由调用者一次性分配 */

.balign 32
tailbuf:
    .zero 32                      /* 摘要读取中转缓冲区 (仅用于 final/out 读出) */