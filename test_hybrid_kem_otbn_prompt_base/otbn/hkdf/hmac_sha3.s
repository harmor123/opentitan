/* ================================================================
 * hmac_sha3.s — HMAC-SHA3-256 纯函数库 (ver0_base 纯软件基线)
 *
 * 依赖 sha3_shake.s 提供软件 Keccak-f (sha3_init, sha3_update,
 * sha3_final). 无 KMAC 硬件依赖.
 * 无数据段 — 所有缓冲区由调用者通过 .globl label 提供.
 *
 * 调用约定:
 *   x10 = key_ptr (密钥指针, 需 32B 对齐)
 *   x11 = key_len (密钥长度, 字节)
 *   x12 = msg_ptr (消息指针, 需 32B 对齐)
 *   x13 = msg_len (消息长度, 字节)
 *   x14 = out_ptr (32B 输出缓冲区, 需 32B 对齐)
 *
 *   破坏寄存器: x4-x9, x15-x17, x30, w4, w31
 *   调用者保存: x12(msg_ptr), x13(msg_len), x14(out_ptr), ra
 *
 * 算法 (RFC 2104):
 *   1. 若 key_len > B=136: key = SHA3-256(key)
 *   2. ipad = 0x36*136 XOR key
 *   3. opad = 0x5C*136 XOR key
 *   4. inner = SHA3-256(ipad || message)
 *   5. result = SHA3-256(opad || inner)
 *
 * 调用者需提供的 .globl 标签:
 *   hmac_ipad    (160B, 32B对齐) — ipad 工作区
 *   hmac_opad    (160B, 32B对齐) — opad 工作区
 *   hmac_inner   (32B,  32B对齐) — 内部哈希输出
 *   hmac_key_hashed (32B, 32B对齐) — 超长密钥哈希后存储
 *   const_0x36   (160B, 32B对齐) — 全 0x36 常量表
 *   const_0x5c   (160B, 32B对齐) — 全 0x5C 常量表
 *   context      (212B, 32B对齐) — SHA-3 上下文
 * ================================================================ */

.section .text

.globl hmac_sha3_256
hmac_sha3_256:
    /* ---- 保存调用者参数到栈 ---- */
    addi    sp, sp, -24
    sw      ra, 20(sp)
    sw      x12, 16(sp)           /* msg_ptr */
    sw      x13, 12(sp)           /* msg_len */
    sw      x14, 8(sp)            /* out_ptr */

    bn.xor  w31, w31, w31         /* 清零 WDR */

    /* ---- 超长密钥处理: key_len > 136 → SHA3-256(key) → 32B ---- */
    li      x5, 136
    sub     x30, x11, x5
    srli    x30, x30, 31
    bne     x30, x0, hmac_key_ok
    beq     x11, x5, hmac_key_ok

    /* H(key) → hmac_key_hashed (32B) — 使用软件 SHA3 */
    sw      x10, 4(sp)
    sw      x11, 0(sp)
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init
    la      x10, context
    lw      x11, 4(sp)
    lw      x12, 0(sp)
    jal     x1, sha3_update
    la      x10, context
    la      x11, hmac_key_hashed
    jal     x1, sha3_final

    la      x10, hmac_key_hashed
    addi    x11, x0, 32

hmac_key_ok:
    /* ---- 构造 ipad + opad: bn.lid/bn.sid 一次搬 32B ----
     * 同时填充两个缓冲区, 循环 5 次 (5×32B = 160B) */
    la      x5, hmac_ipad
    la      x6, hmac_opad
    la      x12, const_0x36
    la      x13, const_0x5c
    li      x4, 0
    li      x7, 5
1:  bn.lid  x4, 0(x12++)
    bn.sid  x4, 0(x5++)
    bn.lid  x4, 0(x13++)
    bn.sid  x4, 0(x6++)
    addi    x7, x7, -1
    bne     x7, x0, 1b

    /* ---- XOR key: ipad[i] ^= key[i], opad[i] ^= key[i] ---- */
    la      x5, hmac_ipad
    la      x6, hmac_opad
    srli    x7, x11, 2            /* 完整 word 数 */
    beq     x7, x0, pad_tail

pad_wloop:
    lw      x8, 0(x10)
    lw      x9, 0(x5)
    lw      x15, 0(x6)
    xor     x9, x9, x8
    xor     x15, x15, x8
    sw      x9, 0(x5)
    sw      x15, 0(x6)
    addi    x10, x10, 4
    addi    x5, x5, 4
    addi    x6, x6, 4
    addi    x7, x7, -1
    bne     x7, x0, pad_wloop

pad_tail:
    andi    x7, x11, 3
    beq     x7, x0, pad_done

    li      x16, 1
    slli    x17, x7, 3
    sll     x16, x16, x17
    addi    x16, x16, -1

    lw      x8, 0(x10)
    and     x8, x8, x16

    lw      x9, 0(x5)
    xor     x9, x9, x8
    sw      x9, 0(x5)

    lw      x9, 0(x6)
    xor     x9, x9, x8
    sw      x9, 0(x6)

pad_done:
    /* ---- 内部哈希: SHA3-256(ipad[0:136] || message) ---- */
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init

    la      x10, context
    la      x11, hmac_ipad
    addi    x12, x0, 136
    jal     x1, sha3_update

    la      x10, context
    lw      x11, 16(sp)           /* msg_ptr */
    lw      x12, 12(sp)           /* msg_len */
    jal     x1, sha3_update

    la      x10, context
    la      x11, hmac_inner
    jal     x1, sha3_final

    /* ---- 外部哈希: SHA3-256(opad[0:136] || inner_hash) ---- */
    la      x10, context
    li      x11, 32
    jal     x1, sha3_init

    la      x10, context
    la      x11, hmac_opad
    addi    x12, x0, 136
    jal     x1, sha3_update

    la      x10, context
    la      x11, hmac_inner
    addi    x12, x0, 32
    jal     x1, sha3_update

    la      x10, context
    lw      x11, 8(sp)            /* out_ptr */
    jal     x1, sha3_final

    /* ---- 返回 ---- */
    lw      ra, 20(sp)
    addi    sp, sp, 24
    ret
