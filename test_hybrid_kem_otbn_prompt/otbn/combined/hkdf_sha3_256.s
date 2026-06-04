/* ================================================================
 * hkdf_sha3_256.s -- OTBN HKDF-SHA3-256 密钥派生 (纯函数库)
 *
 * 依赖:
 *   kmac_sha3_template.s -- KMAC 硬件驱动 (kmac_init, keccak_send_message 等)
 *   hmac_sha3.s          -- HMAC-SHA3-256 (hmac_sha3_256)
 *
 * IKM 由 test wrapper 预拼在 ikm_prebuilt, 本模块直接引用.
 * 无数据段 -- 所有缓冲区由调用者通过 .globl label 提供.
 *
 * 公开子程序:
 *   hkdf_extract -- HKDF-Extract: PRK = HMAC-SHA3-256(salt, IKM)
 *   hkdf_expand  -- HKDF-Expand:  OKM = HKDF-Expand(PRK, L), info 为空
 *
 * 调用者需提供的 .globl 标签:
 *   input_salt     (32B, 32B对齐) -- HKDF salt
 *   ikm_prebuilt   (可变, 32B对齐) -- 预拼接的 IKM (len_cls||ss_e||len_pqc||ss_m||ctx||sid||role)
 *   input_lengths  (32B, 32B对齐) -- 长度字段结构体:
 *       +0: ctx_len  (4B)
 *       +4: sid_len  (4B)
 *       +8: role_len (4B)
 *      +12: okm_len  (4B)
 *      +16: padding  (16B, 共 32B)
 *   output_okm     (256B, 32B对齐) -- OKM 输出缓冲区
 *   t_buf          (32B, 32B对齐)  -- T(i) 暂存 (Expand 循环用)
 *   hmac_key_hashed(32B, 32B对齐)  -- PRK 暂存 (Extract 输出, Expand 输入)
 *   hmac_inner     (32B, 32B对齐)  -- HMAC 内部哈希输出
 *   ikm_buf        (1024B, 32B对齐) -- Expand 循环临时消息缓冲区
 *   hmac_ipad      (160B, 32B对齐) -- HMAC 工作区
 *   hmac_opad      (160B, 32B对齐) -- HMAC 工作区
 *   const_0x36     (160B, 32B对齐) -- HMAC 常量 (全 0x36)
 *   const_0x5c     (160B, 32B对齐) -- HMAC 常量 (全 0x5C)
 *
 * 算法 (RFC 5869):
 *   Extract:  PRK = HMAC-SHA3-256(salt, IKM)
 *   Expand:   T(1) = HMAC-SHA3-256(PRK, 0x01)
 *             T(i) = HMAC-SHA3-256(PRK, T(i-1) || i)
 *             OKM = T(1) || T(2) || ... || T(N), N = ceil(L/32)
 *   (info 为空字符串, 绑定信息已编码在 IKM 中)
 *
 * 关键设计:
 *   - PRK 存储在 hmac_key_hashed (32B < 136B, hmac_sha3_256 不会覆盖)
 *   - Expand 消息缓冲区用 ikm_buf (Extract 之后空闲, 避免与 hmac_opad 冲突)
 *   - 长度字段打包为 32B 结构体 input_lengths (1条 la + 4条 lw, 省指令)
 * ================================================================ */

.section .text

/* ================================================================
 * hkdf_extract -- HKDF-Extract 阶段
 *
 * PRK = HMAC-SHA3-256(salt, IKM)
 * 若 salt 为空则使用 32B 全零 (调用者保证传入有效 salt).
 *
 * 输入: 从 DMEM label 读取 (无寄存器参数)
 *       - input_salt (32B): HKDF salt
 *       - ikm_prebuilt: 预拼接的 IKM 字节序列
 *       - input_lengths: 长度字段结构体 (ctx_len, sid_len, role_len)
 * 输出: PRK -> hmac_key_hashed (32B)
 *
 * 破坏寄存器: x5-x8, x10-x14, ra
 * ================================================================ */
.globl hkdf_extract
hkdf_extract:
    addi    sp, sp, -8
    sw      ra, 4(sp)              /* Save return address (hmac_sha3_256 will overwrite ra) */

    /* ---- 计算 IKM 总长度 ----
     * IKM = be16(32) || ss_e(32) || be16(32) || ss_m(32)  (= 68B 固定)
     *       || ctx || sid || role                           (= 可变)
     * 长度字段从 input_lengths 结构体读取 (32B 对齐, 省 la 指令) */
    la      x8, input_lengths
    lw      x5, 0(x8)             /* ctx_len  at +0 */
    lw      x6, 4(x8)             /* sid_len  at +4 */
    lw      x7, 8(x8)             /* role_len at +8 */
    addi    x13, x5, 68            /* 68 = 2+32+2+32 (fixed header length) */
    add     x13, x13, x6
    add     x13, x13, x7           /* x13 = ikm_len */

    /* ---- HMAC(salt, IKM) -> PRK ----
     * PRK 存到 hmac_key_hashed (独立缓冲区, 不与 Expand 的 t_buf 冲突) */
    la      x10, input_salt        /* x10 = salt_ptr */
    addi    x11, x0, 32            /* x11 = salt_len = 32 */
    la      x12, ikm_prebuilt      /* x12 = ikm_ptr (pre-concatenated IKM) */
    la      x14, hmac_key_hashed   /* x14 = prk_out */
    jal     x1, hmac_sha3_256      /* PRK = HMAC-SHA3-256(salt, IKM) */

    lw      ra, 4(sp)
    addi    sp, sp, 8
    ret


/* ================================================================
 * hkdf_expand -- HKDF-Expand 阶段
 *
 * OKM = HKDF-Expand(PRK, L), info 为空字符串.
 * T(1) = HMAC-SHA3-256(PRK, 0x01)
 * T(i) = HMAC-SHA3-256(PRK, T(i-1) || i)
 * OKM = T(1) || T(2) || ... || T(N)
 *
 * 输入: 从 DMEM label 读取 (无寄存器参数)
 *       - hmac_key_hashed (32B): PRK (由 hkdf_extract 写入)
 *       - input_lengths[+12]: okm_len (L)
 * 输出: OKM -> output_okm
 *
 * 破坏寄存器: x8, x10-x29, x30
 * ================================================================ */
.globl hkdf_expand
hkdf_expand:
    /* ---- 读取 OKM 长度 L ----
     * L == 0 时直接返回 (空输出) */
    la      x8, input_lengths
    lw      x15, 12(x8)            /* okm_len at +12 */
    beq     x15, x0, expand_ret

    addi    x16, x15, 31
    srli    x16, x16, 5            /* N = ceil(L/32), number of iterations */
    li      x17, 1                 /* Counter i (starting from 1) */
    li      x18, 0                 /* Current write offset for okm (bytes) */
    li      x19, 0                 /* T_prev length (0 when i=1, no T_prev copy) */

expand_loop:
    /* ---- 构造 HMAC 消息: [T_prev (i>1)] || [counter_byte] ----
     * 临时缓冲区用 ikm_buf (Extract 后空闲, 不与 hmac_opad 冲突).
     * sw 写入 counter_byte 时会多写 3 字节 0x00, 但 msg_len 只取前 n 字节,
     * 多余字节不会被 keccak 吸收, 无影响. */
    la      x20, ikm_buf

    /* i > 1: first copy T_prev (32B) to message buffer */
    beq     x19, x0, 1f
    la      x21, t_buf             /* T_prev source: t_buf (previous round T(i-1)) */
    li      x22, 8                 /* 32B / 4 = 8 words */
2:  lw      x23, 0(x21)
    sw      x23, 0(x20)
    addi    x21, x21, 4
    addi    x20, x20, 4
    addi    x22, x22, -1
    bne     x22, x0, 2b

    /* Append single-byte counter (sw writes 4B, but msg_len controls only reading valid bytes) */
1:  andi    x21, x17, 0xFF        /* counter byte = i (1..N) */
    sw      x21, 0(x20)
    addi    x13, x19, 1            /* msg_len = T_prev_len + 1 */

    /* ---- 保存 Expand 循环状态到栈 ----
     * 注意: hmac_sha3_256 会使用 sp[-24..0], 与本栈帧 (sp+16..sp+36) 不重叠 */
    addi    sp, sp, -40
    sw      ra, 36(sp)             /* Return address (hmac_sha3_256 will overwrite ra) */
    sw      x15, 32(sp)            /* L (okm_len) */
    sw      x16, 28(sp)            /* N remaining */
    sw      x17, 24(sp)            /* counter i */
    sw      x18, 20(sp)            /* okm offset */
    sw      x19, 16(sp)            /* T_prev length */

    /* ---- T(i) = HMAC-SHA3-256(PRK, msg) ----
     * PRK 从 hmac_key_hashed 读取 (不会被 Expand 覆盖)
     * msg 在 ikm_buf 中
     * 输出到 hmac_inner */
    la      x10, hmac_key_hashed   /* key = PRK (fixed 32B) */
    addi    x11, x0, 32
    la      x12, ikm_buf           /* msg = T_prev || counter */
    la      x14, hmac_inner
    jal     x1, hmac_sha3_256

    /* ---- Restore Expand loop state ---- */
    lw      ra, 36(sp)
    lw      x15, 32(sp)
    lw      x16, 28(sp)
    lw      x17, 24(sp)
    lw      x18, 20(sp)
    lw      x19, 16(sp)
    addi    sp, sp, 40

    /* ---- 拷贝 T(i) -> t_buf (下一轮 T_prev) + output_okm ----
     * 拷贝字节数 = min(32, L - offset) */
    la      x20, hmac_inner        /* Source: T(i) */
    la      x21, t_buf             /* Target 1: next round T_prev */
    la      x22, output_okm        /* Target 2: OKM output */
    add     x22, x22, x18          /* Target 2 += okm offset */

    /* Check: remaining < 32 ? */
    sub     x23, x15, x18          /* remaining = L - offset */
    addi    x24, x0, 32
    sub     x30, x23, x24          /* remaining - 32 */
    srli    x30, x30, 31           /* Symbol: 1 if remaining < 32 */
    bne     x30, x0, expand_partial

    /* remaining >= 32: copy full 32B (8 words) */
    li      x25, 8
1:  lw      x26, 0(x20)
    sw      x26, 0(x21)
    sw      x26, 0(x22)
    addi    x20, x20, 4
    addi    x21, x21, 4
    addi    x22, x22, 4
    addi    x18, x18, 4
    addi    x25, x25, -1
    bne     x25, x0, 1b
    jal     x0, expand_copy_done

expand_partial:
    /* remaining < 32: copy by word, last word uses mask to handle trailing 1-3 bytes */
    srli    x25, x23, 2            /* Number of full words */
    beq     x25, x0, expand_partial_tail
1:  lw      x26, 0(x20)
    sw      x26, 0(x21)
    sw      x26, 0(x22)
    addi    x20, x20, 4
    addi    x21, x21, 4
    addi    x22, x22, 4
    addi    x18, x18, 4
    addi    x23, x23, -4
    addi    x25, x25, -1
    bne     x25, x0, 1b

expand_partial_tail:
    /* tail 1-3 bytes: read-modify-write + mask (OTBN has no lb/sb) */
    andi    x23, x23, 3            /* tail byte count (1-3) */
    beq     x23, x0, expand_copy_done

    lw      x26, 0(x20)            /* src tail word */
    li      x27, 1
    slli    x28, x23, 3
    sll     x27, x27, x28
    addi    x27, x27, -1           /* byte mask: (1 << (8*tail)) - 1 */
    and     x26, x26, x27          /* keep only valid tail bytes */

    /* write t_buf (read-modify-write) */
    lw      x28, 0(x21)
    xori    x29, x27, -1           /* clear mask: ~byte_mask */
    and     x28, x28, x29
    or      x28, x28, x26
    sw      x28, 0(x21)

    /* write output_okm (read-modify-write) */
    lw      x28, 0(x22)
    and     x28, x28, x29
    or      x28, x28, x26
    sw      x28, 0(x22)

    add     x18, x18, x23          /* update offset */

expand_copy_done:
    /* update loop variable, continue next round */
    li      x19, 32                /* T_prev_len = 32 */
    addi    x17, x17, 1            /* i++ */
    addi    x16, x16, -1           /* N-- */
    bne     x16, x0, expand_loop   /* N > 0 -> continue */

expand_ret:
    ret
