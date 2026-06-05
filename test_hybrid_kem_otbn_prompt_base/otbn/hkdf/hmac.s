/*
 * 名称:        hmac
 *
 * 描述:        基于 SHA3-256 的 HMAC 消息认证码计算。
 *              实现 RFC 2104 定义的 HMAC 算法，使用 SHA3-256 作为底层哈希函数。
 *              内部使用 ipad 和 opad 进行两次哈希计算，最终输出 32 字节的 HMAC 值。
 *
 * 参数:        - x10: 密钥指针 (key_ptr)
 *              - x11: 密钥长度 (key_len)，单位字节
 *              - x12: 消息指针 (msg_ptr)
 *              - x13: 消息长度 (msg_len)，单位字节
 *              - x14: 输出缓冲区指针 (out_ptr)，用于存储 32 字节的 HMAC 结果
 *
 * 标志:        会破坏 FG0，对调用者无特殊含义。
 *
 * 破坏的寄存器: x5-x9, x16-x19, x28-x31, w0-w13, w21-w30（通过调用 sha3_* 函数间接破坏）
 *               以及栈上保存的 ra, x10-x14 被保护。
 */

.globl hmac_sha3_256

hmac_sha3_256:
  addi    sp, sp, -64
  sw      ra, 60(sp)
  sw      x10, 56(sp)
  sw      x11, 52(sp)
  sw      x12, 48(sp)
  sw      x13, 44(sp)
  sw      x14, 40(sp)

  /* ==========================================
   * 步骤 1.1: 处理超长密钥 (纯位运算判断)
   * ========================================== */
  lw      x18, 56(sp)
  lw      x19, 52(sp)
  li      x6, 136
  addi    x5, x19, -136
  srli    x5, x5, 31
  bne     x5, x0, key_preprocess_done
  beq     x19, x6, key_preprocess_done
  jal     x1, hash_long_key

hash_long_key:
  la      x10, context
  li      x11, 32
  jal     x1, sha3_init

  la      x10, context
  lw      x11, 56(sp)
  lw      x12, 52(sp)
  jal     x1, sha3_update

  la      x10, context
  la      x11, key_buf             /*  key_buf stores H(key) */
  jal     x1, sha3_final

  la      x5, key_buf
  sw      x5, 56(sp)
  li      x5, 32
  sw      x5, 52(sp)
  
  lw      x18, 56(sp)
  lw      x19, 52(sp)

key_preprocess_done:

  /* ==========================================
   * 步骤 1.2: 初始化 ipad 和 opad 为 0
   * ========================================== */
  la      x5, ipad
  li      x6, 0
  LOOPI   34, 2
    sw    x6, 0(x5)
    addi  x5, x5, 4
  
  la      x5, opad
  LOOPI   34, 2
    sw    x6, 0(x5)
    addi  x5, x5, 4

  /* ==========================================
   * 步骤 1.3: 按字拷贝 Key 到 ipad 和 opad
   * ========================================== */
  la      x16, ipad
  la      x17, opad
  srli    x7, x19, 2
  beq     x7, x0, copy_key_tail

copy_word_loop:
  lw      x5, 0(x18)
  sw      x5, 0(x16)
  sw      x5, 0(x17)
  addi    x18, x18, 4
  addi    x16, x16, 4
  addi    x17, x17, 4
  addi    x7, x7, -1
  bne     x7, x0, copy_word_loop

/* ==========================================
 * 步骤 1.4: 处理不足 4 字节的尾部 
 * ========================================== */
copy_key_tail:
  andi    x7, x19, 0x3
  beq     x7, x0, key_copy_done
  
  lw      x28, 0(x18)
  
  li      x5, 0x00FFFFFF           /* Default mask: 3 bytes */
  li      x6, 1
  beq     x7, x6, set_mask_1
  li      x6, 2
  beq     x7, x6, set_mask_2
  jal     x1, apply_tail_mask
  
set_mask_1:
  li      x5, 0x000000FF
  jal     x1, apply_tail_mask
  
set_mask_2:
  li      x5, 0x0000FFFF

apply_tail_mask:
  and     x28, x28, x5
  sw      x28, 0(x16)
  sw      x28, 0(x17)

key_copy_done:

  /* ==========================================
   * 步骤 2: ipad 异或 0x36，opad 异或 0x5c
   * ========================================== */
  li      x9, 0x36363636
  la      x5, ipad
  LOOPI   34, 4
    lw    x6, 0(x5)
    xor   x6, x6, x9
    sw    x6, 0(x5)
    addi  x5, x5, 4

  li      x9, 0x5c5c5c5c
  la      x5, opad
  LOOPI   34, 4
    lw    x6, 0(x5)
    xor   x6, x6, x9
    sw    x6, 0(x5)
    addi  x5, x5, 4

  /* ------------------------------------------
   * 步骤 3: 内部哈希 H(ipad || message)
   * ------------------------------------------ */
  la      x10, context
  li      x11, 32
  jal     x1, sha3_init

  la      x10, context
  la      x11, ipad
  li      x12, 136
  jal     x1, sha3_update

  la      x10, context
  lw      x11, 48(sp)
  lw      x12, 44(sp)
  jal     x1, sha3_update

  la      x10, context
  la      x11, inner_hash
  jal     x1, sha3_final

  /* ------------------------------------------
   * 步骤 4: 外部哈希 H(opad || inner_hash)
   * ------------------------------------------ */
  la      x10, context
  li      x11, 32
  jal     x1, sha3_init

  la      x10, context
  la      x11, opad
  li      x12, 136
  jal     x1, sha3_update

  la      x10, context
  la      x11, inner_hash
  li      x12, 32
  jal     x1, sha3_update

  la      x10, context
  lw      x11, 40(sp)
  jal     x1, sha3_final

  lw      ra, 60(sp)
  addi    sp, sp, 64
  ret
