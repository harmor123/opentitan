/* ================================================================
 * kmac_sha3_template.s — OpenTitan KMAC 硬件极简驱动
 *
 * 寄存器分工:
 *   0xFC2 (kmac_status)    — FSM 状态: bit0=IDLE, bit1=ABSORB, bit2=SQUEEZE
 *   0x7D9 (kmac_if_status) — 数据握手: bit0=MSG_WRITE_RDY, bit3=DIGEST_VALID
 *   0x7DB (kmac_cfg)       — MODE + STRENGTH 配置
 *   0x7DC (msg_send)       — 触发消息吸收
 *   0x7DD (kmac_cmd)       — START/PROCESS/RUN/DONE 命令
 *   0x7DE (byte_strobe)    — 尾部字节有效位掩码
 *
 * 调用约定:
 *   破坏: x5, x6; 各函数具体破坏见注释
 *   w31 由调用者保证为 0 (或由各函数自行清零)
 * ================================================================ */

.section .text

/* ================================================================
 * kmac_init: 初始化 KMAC 硬件，进入 Absorb 状态
 *
 * 输入: x10 = mode (0=SHA3-256, 1=SHA3-512, 2=SHAKE128, 3=SHAKE256)
 * 破坏: x5, x6
 * ================================================================ */
.globl kmac_init
kmac_init:
    addi    x6, x0, 1
.wait_idle:
    csrrs   x5, 0xfc2, x0          /* kmac_status[0]: SHA3_IDLE */
    and     x5, x5, x6
    beq     x5, x0, .wait_idle

    /* 模式分发 */
    beq     x10, x0, .cfg_sha3_256
    addi    x5, x0, 1
    beq     x10, x5, .cfg_sha3_512
    addi    x5, x0, 2
    beq     x10, x5, .cfg_shake128
    addi    x5, x0, 3
    beq     x10, x5, .cfg_shake256
    ecall                           /* 非法 mode */

.cfg_sha3_256:
    addi    x5, x0, 4               /* MODE=SHA3, STRENGTH=L256 */
    jal     x0, .apply_cfg
.cfg_sha3_512:
    addi    x5, x0, 8               /* MODE=SHA3, STRENGTH=L512 */
    jal     x0, .apply_cfg
.cfg_shake128:
    addi    x5, x0, 32              /* MODE=SHAKE, STRENGTH=L128 */
    jal     x0, .apply_cfg
.cfg_shake256:
    addi    x5, x0, 36              /* MODE=SHAKE, STRENGTH=L256 */

.apply_cfg:
    csrrw   x0, 0x7db, x5           /* kmac_cfg */
    addi    x5, x0, 29              /* CMD_START = 0x1D */
    csrrw   x0, 0x7dd, x5           /* kmac_cmd */
    ret

/* ================================================================
 * keccak_send_message: 发送可变长度消息到 KMAC
 *
 * 输入: x10 = msg_ptr, x11 = byte_len
 * 破坏: x5, x6, x7, w0, w1, w31
 * ================================================================ */
.globl keccak_send_message
keccak_send_message:
    bn.xor  w31, w31, w31           /* w31 = 0 (移位零参考 / share1 零值) */

    /* 计算完整 32-byte WDR 数量 */
    srli    x5, x11, 5              /* x5 = byte_len / 32 */
    beq     x5, x0, _no_full_wdr
    slli    x5, x5, 5               /* x5 = 完整 WDR 字节偏移 */
    add     x5, x10, x5             /* x5 = 完整 WDR 结束地址 */

    /* 全量 WDR 不需要 strobe 约束，预设一次即可 */
    addi    x6, x0, -1              /* x6 = 0xFFFFFFFF */
    csrrw   x0, 0x7de, x6           /* byte_strobe = 全部有效 */

_full_chunk_loop:
    beq     x10, x5, _no_full_wdr
_wait_rdy_full:
    csrrs   x6, 0x7d9, x0           /* kmac_if_status[0]: MSG_WRITE_RDY */
    andi    x6, x6, 1
    beq     x6, x0, _wait_rdy_full

    bn.lid  x0, 0(x10++)            /* 加载 256-bit 明文到 w0 */
    bn.wsrw 8, w0                   /* kmac_data_s0 */
    bn.wsrw 9, w31                  /* kmac_data_s1 = 0 */

    csrrw   x0, 0x7dc, x6           /* msg_send = 1 (x6=1 from poll) */
    jal     x0, _full_chunk_loop

_no_full_wdr:
    andi    x5, x11, 31             /* x5 = 尾部字节数 (0~31) */
    beq     x5, x0, _keccak_send_message_end

_wait_rdy_tail:
    csrrs   x6, 0x7d9, x0           /* kmac_if_status[0]: MSG_WRITE_RDY */
    andi    x6, x6, 1
    beq     x6, x0, _wait_rdy_tail

    bn.lid  x0, 0(x10)              /* 加载尾部数据 (高位含垃圾) */

    /* 动态生成字节掩码: mask = (1 << (8*x5)) - 1 */
    bn.addi w1, w31, 1              /* w1 = 1 */
    addi    x7, x5, 0               /* x7 = 循环计数 */
_mask_loop:
    beq     x7, x0, _mask_done
    addi    x7, x7, -1
    bn.rshi w1, w1, w31 >> 248      /* w1 <<= 8 */
    jal     x0, _mask_loop
_mask_done:
    bn.subi w1, w1, 1               /* w1 = (1 << (8*x5)) - 1 */
    bn.and  w0, w0, w1              /* w0 &= mask, 清零高位垃圾 */

    bn.wsrw 8, w0                   /* kmac_data_s0 (masked) */
    bn.wsrw 9, w31                  /* kmac_data_s1 = 0 */

    /* byte_strobe = (1 << x5) - 1, 只标记尾部有效字节 */
    addi    x6, x0, 1
    sll     x6, x6, x5
    addi    x6, x6, -1
    csrrw   x0, 0x7de, x6
    addi    x6, x0, 1
    csrrw   x0, 0x7dc, x6           /* msg_send = 1 */

_keccak_send_message_end:
    ret

/* ================================================================
 * kmac_process: 结束 Absorb，触发 padding + Keccak-f，进入 Squeeze
 *
 * 破坏: x5, x6
 * ================================================================ */
.globl kmac_process
kmac_process:
    addi    x5, x0, 46              /* CMD_PROCESS = 0x2E */
    csrrw   x0, 0x7dd, x5           /* kmac_cmd */

    addi    x6, x0, 8               /* kmac_if_status[3]: DIGEST_VALID */
.wait_digest:
    csrrs   x5, 0x7d9, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_digest
    ret

/* ================================================================
 * _ensure_digest: 确保 DIGEST_VALID 置起，否则自动 kmac_run
 *
 * 每次读 word 前调用，彻底消除调用方对 block 边界的感知。
 * 输入: x6 = 8 (DIGEST_VALID 位掩码，调用者设定)
 * 破坏: x5
 * 保存/恢复: x1 (通过栈)，x6 (调用者负责)
 * ================================================================ */
_ensure_digest:
    csrrs   x5, 0x7d9, x0           /* kmac_if_status */
    and     x5, x5, x6
    bne     x5, x0, _ed_ret         /* DIGEST_VALID 已置起 → 直接返回 */

    /* Block 耗尽，需要 kmac_run */
    addi    sp, sp, -8
    sw      x1, 0(sp)               /* 保存 squeeze_32B 内的返回地址 */
    sw      x6, 4(sp)               /* 保存 DIGEST_VALID 掩码 */
    jal     x1, kmac_run
    lw      x6, 4(sp)
    lw      x1, 0(sp)
    addi    sp, sp, 8
_ed_ret:
    jalr    x0, x1, 0               /* 通过 x1 返回到调用点 */

/* ================================================================
 * kmac_squeeze_32B: 挤出 32 字节摘要到 DMEM
 *
 * 每个 word 读之前通过 _ensure_digest 自动检测 block 边界，
 * DIGEST_VALID 不可用时自动调用 kmac_run。
 *
 * 输入: x10 = out_ptr (32-byte aligned)
 * 破坏: x5, x6, w8, w9, w10, w31
 * ================================================================ */
.globl kmac_squeeze_32B
kmac_squeeze_32B:
    bn.xor  w31, w31, w31           /* w31 = 0 (bn.rshi 零参考) */
    addi    x6, x0, 8               /* DIGEST_VALID 位掩码 */

    /* Word 0 → w8[63:0] */
    jal     x1, _ensure_digest
    bn.wsrr w8, 8                   /* kmac_data_s0 */
    bn.wsrr w9, 9                   /* kmac_data_s1 */
    bn.xor  w8, w8, w9

    /* Word 1 → w8[127:64] */
    jal     x1, _ensure_digest
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10
    bn.rshi w9, w9, w31 >> 192      /* w9 <<= 64 */
    bn.or   w8, w8, w9

    /* Word 2 → w8[191:128] */
    jal     x1, _ensure_digest
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10
    bn.rshi w9, w9, w31 >> 128      /* w9 <<= 128 */
    bn.or   w8, w8, w9

    /* Word 3 → w8[255:192] */
    jal     x1, _ensure_digest
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10
    bn.rshi w9, w9, w31 >> 64       /* w9 <<= 192 */
    bn.or   w8, w8, w9

    addi    x5, x0, 8
    bn.sid  x5, 0(x10)              /* 存储 256-bit 到 DMEM */
    ret

/* ================================================================
 * kmac_run: 触发新一轮 Keccak-f 排列 (仅 SHAKE)
 *
 * 仅当 squeezed_count >= rate 时才需要调用。
 * 破坏: x5, x6
 * ================================================================ */
.globl kmac_run
kmac_run:
    addi    x5, x0, 49              /* CMD_RUN = 0x31 */
    csrrw   x0, 0x7dd, x5           /* kmac_cmd */

    /* 先等 FSM 离开 StSqueeze (进入 StProcessing = ABSORB 状态) */
    addi    x6, x0, 2               /* kmac_status[1]: SHA3_ABSORB */
.wait_run_absorb:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_run_absorb

    /* 再等 Keccak 完成，FSM 回到 StSqueeze */
    addi    x6, x0, 4               /* kmac_status[2]: SHA3_SQUEEZE */
.wait_run_squeeze:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_run_squeeze
    ret

/* ================================================================
 * kmac_done: 释放 KMAC 硬件，回到 Idle
 *
 * 破坏: x5, x6
 * ================================================================ */
.globl kmac_done
kmac_done:
    addi    x5, x0, 22              /* CMD_DONE = 0x16 */
    csrrw   x0, 0x7dd, x5           /* kmac_cmd */

    addi    x6, x0, 1               /* kmac_status[0]: SHA3_IDLE */
.wait_idle_rel:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_idle_rel
    ret
