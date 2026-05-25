/* ================================================================
 * hkdf_sha3_256.s — OTBN HKDF-SHA3-256 密钥派生 (ver0_base 纯函数库)
 *
 * 依赖:
 *   sha3_shake.s  — 软件 Keccak-f (sha3_init, sha3_update, sha3_final)
 *   hmac_sha3.s   — HMAC-SHA3-256 (hmac_sha3_256)
 *
 * 无 KMAC 硬件依赖. 无数据段 — 所有缓冲区由调用者通过 .globl label 提供.
 *
 * 公开子程序:
 *   hkdf_extract — PRK = HMAC-SHA3-256(salt, IKM)
 *   hkdf_expand  — OKM = HKDF-Expand(PRK, L), info 为空
 *
 * 调用者需提供的 .globl 标签:
 *   input_salt     (32B)      — HKDF salt
 *   ikm_prebuilt   (可变)     — 预拼接 IKM
 *   input_lengths  (32B)      — {ctx_len, sid_len, role_len, okm_len}
 *   output_okm     (256B)     — OKM 输出
 *   t_buf          (32B)      — T(i) 暂存
 *   ikm_buf        (1024B)    — Expand 临时消息缓冲
 *   hmac_key_hashed(32B)      — PRK 暂存 (Extract→Expand)
 *   hmac_inner     (32B)      — HMAC 内部哈希输出
 *   以及所有 HMAC 工作区标签 (hmac_ipad, hmac_opad, const_0x36, const_0x5c, context)
 *
 * 算法 (RFC 5869):
 *   Extract:  PRK = HMAC-SHA3-256(salt, IKM)
 *   Expand:   T(1) = HMAC-SHA3-256(PRK, 0x01)
 *             T(i) = HMAC-SHA3-256(PRK, T(i-1) || i)
 *             OKM = T(1) || T(2) || ... || T(N)
 * ================================================================ */

.section .text

/* ================================================================
 * hkdf_extract — PRK = HMAC-SHA3-256(salt, IKM)
 * 输入: 从 DMEM label 读取
 * 输出: PRK → hmac_key_hashed (32B)
 * ================================================================ */
.globl hkdf_extract
hkdf_extract:
    addi    sp, sp, -8
    sw      ra, 4(sp)

    /* 计算 IKM 总长度: 68 + ctx_len + sid_len + role_len */
    la      x8, input_lengths
    lw      x5, 0(x8)             /* ctx_len */
    lw      x6, 4(x8)             /* sid_len */
    lw      x7, 8(x8)             /* role_len */
    addi    x13, x5, 68
    add     x13, x13, x6
    add     x13, x13, x7

    /* PRK = HMAC-SHA3-256(salt, IKM) → hmac_key_hashed */
    la      x10, input_salt
    addi    x11, x0, 32
    la      x12, ikm_prebuilt
    la      x14, hmac_key_hashed
    jal     x1, hmac_sha3_256

    lw      ra, 4(sp)
    addi    sp, sp, 8
    ret


/* ================================================================
 * hkdf_expand — OKM = HKDF-Expand(PRK, L)
 * 输入: 从 DMEM label 读取 (hmac_key_hashed, input_lengths)
 * 输出: OKM → output_okm
 * ================================================================ */
.globl hkdf_expand
hkdf_expand:
    la      x8, input_lengths
    lw      x15, 12(x8)            /* okm_len */
    beq     x15, x0, expand_ret

    addi    x16, x15, 31
    srli    x16, x16, 5            /* N = ceil(L/32) */
    li      x17, 1                 /* counter i */
    li      x18, 0                 /* okm 偏移 */
    li      x19, 0                 /* T_prev 长度 */

expand_loop:
    /* 构造消息: [T_prev] || [counter_byte] → ikm_buf */
    la      x20, ikm_buf

    beq     x19, x0, 1f
    la      x21, t_buf
    li      x22, 8
2:  lw      x23, 0(x21)
    sw      x23, 0(x20)
    addi    x21, x21, 4
    addi    x20, x20, 4
    addi    x22, x22, -1
    bne     x22, x0, 2b

1:  andi    x21, x17, 0xFF
    sw      x21, 0(x20)
    addi    x13, x19, 1            /* msg_len = T_prev_len + 1 */

    /* 保存循环状态 */
    addi    sp, sp, -40
    sw      ra, 36(sp)
    sw      x15, 32(sp)
    sw      x16, 28(sp)
    sw      x17, 24(sp)
    sw      x18, 20(sp)
    sw      x19, 16(sp)

    /* T(i) = HMAC-SHA3-256(PRK, msg) → hmac_inner */
    la      x10, hmac_key_hashed
    addi    x11, x0, 32
    la      x12, ikm_buf
    la      x14, hmac_inner
    jal     x1, hmac_sha3_256

    /* 恢复循环状态 */
    lw      ra, 36(sp)
    lw      x15, 32(sp)
    lw      x16, 28(sp)
    lw      x17, 24(sp)
    lw      x18, 20(sp)
    lw      x19, 16(sp)
    addi    sp, sp, 40

    /* 拷贝 T(i) → t_buf + output_okm */
    la      x20, hmac_inner
    la      x21, t_buf
    la      x22, output_okm
    add     x22, x22, x18

    sub     x23, x15, x18          /* remaining */
    addi    x24, x0, 32
    sub     x30, x23, x24
    srli    x30, x30, 31
    bne     x30, x0, expand_partial

    /* remaining >= 32: 完整拷贝 8 words */
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
    /* remaining < 32: 按 word 拷贝, 尾部用掩码 */
    srli    x25, x23, 2
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
    andi    x23, x23, 3
    beq     x23, x0, expand_copy_done

    lw      x26, 0(x20)
    li      x27, 1
    slli    x28, x23, 3
    sll     x27, x27, x28
    addi    x27, x27, -1
    and     x26, x26, x27

    lw      x28, 0(x21)
    xori    x29, x27, -1
    and     x28, x28, x29
    or      x28, x28, x26
    sw      x28, 0(x21)

    lw      x28, 0(x22)
    and     x28, x28, x29
    or      x28, x28, x26
    sw      x28, 0(x22)

    add     x18, x18, x23

expand_copy_done:
    li      x19, 32
    addi    x17, x17, 1
    addi    x16, x16, -1
    bne     x16, x0, expand_loop

expand_ret:
    ret
