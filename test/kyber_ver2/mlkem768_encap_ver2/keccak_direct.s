/* ================================================================
 * keccak_direct.s - CSR DIRECT (OTBN ISA Strict Compliant)
 *
 * 【 调用要求 —— Ibex-OTBN 内存共享契约】
 *  OTBN 程序由于缺乏 lb/sb 字节操作指令：
 *
 * 1. 指针对齐：传入的 x11 (数据指针) 必须严格 32 字节对齐 (256-bit)。
 *    虽然 OTBN 的 `lw` 允许在 32 字节物理行内进行 4 字节步长的读取，
 *    但源缓冲区基地址必须对齐到 32 字节边界，以匹配 DMEM 底层宽带特性。
 * 2. 尾部补零：当消息长度 x12 不是 4 的倍数时 (例如 33, 35 字节)，
 *    调用方 必须在将数据写入 OTBN DMEM 时，
 *    手动将不足 4 字节的尾部用 0x00 填充至 4 字节对齐。
 *    (例如：传 33 字节，DMEM 中第 34, 35, 36 字节必须被 Ibex 预先写为 0)。
 * 3. 真实长度：x12 必须传入真实的消息字节数 (如 33)，绝不能传入补零后的长度。
 * 4. 硬件截断：OTBN 内部会按向上取整读取 Word，并将真实长度 x12 左移写入 
 *    direct_cfg[26:5]。KMAC 硬件会根据此真实长度自动截断尾部补零，
 *    并在精确位置插入 10*1 padding，保证哈希结果 100% 正确。
 * ================================================================ */

.section .data
.balign 32
.globl context
context:
    .zero 2048                    /* 哈希消息拼接缓冲区 (利用硬件截断，无需清零) */

.balign 32
ctx_meta:
    .word 0                       /* offset: 当前已累积的消息长度 */
    .word 0                       /* cfg: 发送给 direct_cfg 的模式字 */
    .word 0                       /* md_len: SHA3 摘要长度 (SHAKE 时为 0) */

.section .text

/* ---------- DIRECT 模式寄存器地址 ---------- */
/* 0x7df : direct_cfg   (配置与长度寄存器：[1:0]模式, [4:2]强度, [26:5]总消息字节数) */
/* 0x7f0~0x7f7          (消息输入寄存器 Bit [255:0])                                         */
/* 0x7f8~0x7ff          (摘要输出寄存器 Bit [255:0])                                         */

/* ================================================================
 * 全局导出符号
 * ================================================================ */
.globl keccak_send_msg
.globl keccak_digest
.globl sha3_init
.globl shake128_init
.globl shake256_init
.globl sha3_update
.globl sha3_final
.globl shake_xof
.globl shake_out

/* ----------------------------------------------------------------
 * keccak_send_msg (底层核心)
 * ---------------------------------------------------------------- */

/* ================================================================
 * Name:        keccak_send_msg
 *
 * Description: 底层核心：通过 DIRECT CSR 向 KMAC 硬件发送消息。
 *              仅使用 x13 复用，以最精简指令完成 32 字节数据推送。
 *              将 cfg 与 msg_len 原子合并写入 direct_cfg 寄存器。
 *
 * Arguments:   - x10: 指向待发送数据的指针 (DMEM)
 *              - x5:  direct_cfg 配置字 (低 5 位)
 *              - x11: 消息总长度 (字节)
 *
 * Clobbers:    x5, x12, x13
 *
 * Flags:       无
 * ================================================================ */
keccak_send_msg:
    beq   x11, x0, .L_empty       /* 长度为 0 时，必须手动推入一次空块以触发 Keccak */

    addi  x12, x11, 31
    srli  x12, x12, 5             /* 计算需要发送的完整 32 字节块数 */

    slli  x13, x11, 5             /* 将消息长度左移 5 位，对齐到 direct_cfg [26:5] */
    or    x5, x5, x13             /* 合并低 5 位的 cfg 和高位的 len */
    csrrw x0, 0x7df, x5           /* 原子写入 direct_cfg，触发硬件准备 */

.L_loop:
    lw    x13, 0(x10)
    csrrw x0, 0x7f0, x13          /* 写入 direct_msg0 */
    lw    x13, 4(x10)
    csrrw x0, 0x7f1, x13          /* 写入 direct_msg1 */
    lw    x13, 8(x10)
    csrrw x0, 0x7f2, x13          /* 写入 direct_msg2 */
    lw    x13, 12(x10)
    csrrw x0, 0x7f3, x13          /* 写入 direct_msg3 */
    lw    x13, 16(x10)
    csrrw x0, 0x7f4, x13          /* 写入 direct_msg4 */
    lw    x13, 20(x10)
    csrrw x0, 0x7f5, x13          /* 写入 direct_msg5 */
    lw    x13, 24(x10)
    csrrw x0, 0x7f6, x13          /* 写入 direct_msg6 */
    lw    x13, 28(x10)
    csrrw x0, 0x7f7, x13          /* 写入 direct_msg7 */

    addi  x10, x10, 32            /* 指针移动到下一个 32 字节块 */
    addi  x12, x12, -1            /* 块计数器递减 */
    bne   x12, x0, .L_loop
    ret

.L_empty:
    csrrw x0, 0x7df, x5           /* 写入仅包含 cfg 的 direct_cfg (长度字段为 0) */
    li    x13, 0
    csrrw x0, 0x7f7, x13          /* 推入全 0 块，激活 Keccak 轮函数 */
    ret

/* ----------------------------------------------------------------
 * keccak_digest (底层核心)
 * ---------------------------------------------------------------- */

/* ================================================================
 * Name:        keccak_digest
 *
 * Description: 底层核心：从 KMAC DIRECT CSR 读取 32 字节摘要。
 *              利用 csrrs 读 CSR 不产生 Stall 的特性，极速拉取数据。
 *
 * Arguments:   - x11: 输出缓冲区指针 (DMEM)
 *
 * Clobbers:    x5
 *
 * Flags:       无
 * ================================================================ */
keccak_digest:
    csrrs x5, 0x7f8, x0           /* 读取 direct_dig0 */
    sw    x5, 0(x11)
    csrrs x5, 0x7f9, x0           /* 读取 direct_dig1 */
    sw    x5, 4(x11)
    csrrs x5, 0x7fa, x0           /* 读取 direct_dig2 */
    sw    x5, 8(x11)
    csrrs x5, 0x7fb, x0           /* 读取 direct_dig3 */
    sw    x5, 12(x11)
    csrrs x5, 0x7fc, x0           /* 读取 direct_dig4 */
    sw    x5, 16(x11)
    csrrs x5, 0x7fd, x0           /* 读取 direct_dig5 */
    sw    x5, 20(x11)
    csrrs x5, 0x7fe, x0           /* 读取 direct_dig6 */
    sw    x5, 24(x11)
    csrrs x5, 0x7ff, x0           /* 读取 direct_dig7 */
    sw    x5, 28(x11)
    ret


/* ================================================================
 * 同名流式 API 封装 (已剔除所有冗余清空操作)
 * ================================================================ */

/* ================================================================
 * Name:        sha3_init
 *
 * Description: 初始化 SHA3‑256 或 SHA3‑512 哈希操作。
 *              仅更新全局轻量级元数据 (ctx_meta)，零开销。
 *
 * Arguments:   - x11: 输出摘要长度 (32 表示 SHA3‑256, 64 表示 SHA3‑512)
 *
 * Clobbers:    x5, x6, x12
 *
 * Flags:       无
 * ================================================================ */
.globl sha3_init
sha3_init:
    la   x5, ctx_meta
    sw   x0, 0(x5)                /* offset = 0 */
    
    addi x6, x0, 32
    beq  x11, x6, .cfg_256
    li   x12, 0x10                /* SHA3-512 模式位 */
    jal  x0, .cfg_done
.cfg_256:
    li   x12, 0x08                /* SHA3-256 模式位 */
.cfg_done:
    sw   x12, 4(x5)               /* 保存 cfg */
    sw   x11, 8(x5)               /* 保存 md_len */
    ret

/* ================================================================
 * Name:        shake128_init
 *
 * Description: 初始化 SHAKE128 哈希操作 (安全强度 128 位)。
 *
 * Arguments:   无
 *
 * Clobbers:    x5, x12
 *
 * Flags:       无
 * ================================================================ */
.globl shake128_init
shake128_init:
    la   x5, ctx_meta
    sw   x0, 0(x5)                /* offset = 0 */
    li   x12, 0x02                /* SHAKE128 模式位 */
    sw   x12, 4(x5)
    sw   x0, 8(x5)                /* md_len = 0 (流式) */
    ret

/* ================================================================
 * Name:        shake256_init
 *
 * Description: 初始化 SHAKE256 哈希操作 (安全强度 256 位)。
 *
 * Arguments:   无
 *
 * Clobbers:    x5, x12
 *
 * Flags:       无
 * ================================================================ */
.globl shake256_init
shake256_init:
    la   x5, ctx_meta
    sw   x0, 0(x5)                /* offset = 0 */
    li   x12, 0x0a                /* SHAKE256 模式位 */
    sw   x12, 4(x5)
    sw   x0, 8(x5)                /* md_len = 0 (流式) */
    ret

/* ================================================================
 * Name:        sha3_update
 *
 * Description: 向哈希引擎追加数据 (支持任意长度)。
 *              遵循 Ibex-OTBN 契约：调用方保证数据已 4 字节对齐补零，
 *              内部按向上取整的 Word 数进行极速搬运。
 *
 * Arguments:   - x11: 指向待追加数据的指针 (4 字节对齐)
 *              - x12: 数据长度 (真实字节数)
 *
 * Clobbers:    x5, x6, x7, x13, x14, x15
 *
 * Flags:       无
 * ================================================================ */
.globl sha3_update
sha3_update:
    beq  x12, x0, .upd_done       /* 长度为 0 直接返回 */
    
    la   x5, ctx_meta
    lw   x6, 0(x5)                /* 读取 offset */
    la   x7, context
    add  x13, x7, x6              /* dst_ptr = context + offset */
    
    addi x14, x12, 3              /* 计算 num_words (向上取整) */
    srli x14, x14, 2             
    beq  x14, x0, .upd_done       /* 若不足 1 字则跳过 (实际被上方 beq 拦截) */
    
.upd_copy:
    lw   x15, 0(x11)              /* 按 32 位字搬运 */
    sw   x15, 0(x13)
    addi x11, x11, 4
    addi x13, x13, 4
    addi x14, x14, -1
    bne  x14, x0, .upd_copy
    
.upd_done:
    lw   x6, 0(x5)
    add  x6, x6, x12              /* 累加【真实】字节数到 offset */
    sw   x6, 0(x5)                /* 更新 offset */
    ret

/* ================================================================
 * Name:        sha3_final
 *
 * Description: 完成 SHA‑3 哈希并输出指定长度的摘要。
 *              根据初始化时保存的 md_len 自动计算挤出次数。
 *
 * Arguments:   - x11: 输出缓冲区指针 (32 位对齐)
 *
 * Clobbers:    x3, x5, x6, x14, x15
 *
 * Flags:       无
 * ================================================================ */
.globl sha3_final
sha3_final:
    addi x14, x11, 0              /* 暂存 out_ptr，防止被底层 send_msg 的 x13 误伤 */
    
    la   x5, ctx_meta
    lw   x15, 8(x5)               /* 读取 md_len */
    srli x15, x15, 5              /* 计算循环挤出次数 */
    
    lw   x6, 0(x5)                /* 读取 offset (真实消息长度) */
    lw   x3, 4(x5)                /* 读取 cfg */
    
    la   x10, context
    addi x11, x6, 0               /* x11 作为 send_msg 的长度参数 */
    addi x5, x3, 0                /* x5 作为 send_msg 的 cfg 参数 */
    jal  x1, keccak_send_msg
    
    beq  x15, x0, .sf_done
    addi x11, x14, 0              /* 恢复 out_ptr */
.sf_loop:
    jal  x1, keccak_digest        /* 循环挤出 32 字节块 */
    addi x11, x11, 32
    addi x15, x15, -1
    bne  x15, x0, .sf_loop
.sf_done:
    ret

/* ================================================================
 * Name:        shake_xof
 *
 * Description: 结束吸收阶段，进入 SHAKE 挤出模式。
 *              直接将累积的消息发送给硬件触发 Keccak 轮函数。
 *
 * Arguments:   无
 *
 * Clobbers:    x3, x5, x6
 *
 * Flags:       无
 * ================================================================ */
.globl shake_xof
shake_xof:
    la   x5, ctx_meta
    lw   x6, 0(x5)                /* 读取 offset */
    lw   x3, 4(x5)                /* 读取 cfg */
    la   x10, context
    addi x11, x6, 0               /* x11 作为 send_msg 的长度参数 */
    addi x5, x3, 0                /* x5 作为 send_msg 的 cfg 参数 */
    jal  x1, keccak_send_msg
    ret

/* ================================================================
 * Name:        shake_out
 *
 * Description: 从 SHAKE 状态挤出 32 字节输出。
 *              DIRECT 模式下硬件自动管理 Squeeze 状态，无需手动发 CMD。
 *
 * Arguments:   - x11: 输出缓冲区指针 (32 位对齐)
 *
 * Clobbers:    x5
 *
 * Flags:       无
 * ================================================================ */
.globl shake_out
shake_out:
    jal  x1, keccak_digest
    ret
