/*
 * 名称:        hkdf_expand
 *
 * 描述:        基于 HMAC-SHA3-256 的 HKDF-Expand 密钥派生扩展。
 *              实现 RFC 5869 定义的 HKDF-Expand 算法，使用 HMAC-SHA3-256 作为底层 PRF。
 *              通过迭代计算 T(1) = HMAC(PRK, info || 0x01), T(2) = HMAC(PRK, T(1) || info || 0x02)...
 *              将伪随机密钥 (PRK) 和上下文信息 扩展为指定长度的输出密钥材料 (OKM)。
 *              注意：由于底层架构缺少单字节写入指令 (sb)，内部采用了特殊的“字级读-改-写”
 *              与移位掩码技术来实现末尾单字节计数器 (0x01, 0x02...) 的精确拼接。
 *              同时，为防止被底层 sha3_* 函数破坏循环状态，使用了专用的 .data 段隔离区 (hkdf_ctx) 保存变量。
 *
 * 参数:        - x10: 伪随机密钥指针 (prk_ptr)，固定长度 32 字节 (SHA3-256 输出长度)
 *              - x11: 上下文信息指针 (info_ptr)，可为空指针 (当 x12=0 时)
 *              - x12: 上下文信息长度 (info_len)，单位字节，取值范围 [0, 255]
 *              - x13: 期望输出长度 (L)，单位字节，取值范围 [1, 8160] (即 255 * 32)
 *              - x14: 输出密钥材料缓冲区指针 (okm_ptr)，需保证至少有 L 字节的有效空间
 *
 * 标志:        会破坏 FG0，对调用者无特殊含义。
 *
 * 破坏的寄存器: x5-x9, x16-x19, x20-x29, x28-x31, w0-w13, w21-w30（通过调用 hmac/sha3_* 函数间接破坏）
 *               以及栈上保存的 ra, x10-x14 被保护。
 *               (注: x20-x26 在函数内部通过 hkdf_ctx 进行了跨函数调用的恢复，但对外层调用者而言仍视为易失寄存器)
 */

.globl hkdf_expand
hkdf_expand:
  addi    sp, sp, -64
  sw      ra, 60(sp)
  sw      x10, 56(sp)
  sw      x11, 52(sp)
  sw      x12, 48(sp)
  sw      x13, 44(sp)
  sw      x14, 40(sp)

  addi    x20, x13, 31
  srli    x20, x20, 5    # x20 = N

  li      x21, 1         # x21 = 计数器 i
  li      x22, 0         # x22 = T_prev 长度
  li      x26, 0         # x26 = okm 偏移量

expand_loop:
  la      x5, hkdf_msg_buf

  /* ==========================================
   * 0. 备份 Counter (防止后续移位逻辑破坏)
   * ========================================== */
  addi    x23, x21, 0    # x23 = 真实的 i

  /* 1. 拷贝 T_prev */
  beq     x22, x0, skip_t_prev_copy
  la      x6, t_buf
  LOOPI   8, 4
    lw    x7, 0(x6)
    sw    x7, 0(x5)
    addi  x6, x6, 4
    addi  x5, x5, 4

skip_t_prev_copy:
  /* 2. 拷贝 info */
  lw      x6, 52(sp)
  lw      x7, 48(sp)
  srli    x8, x7, 2
  beq     x8, x0, copy_info_tail

copy_info_word_loop:
  lw      x9, 0(x6)
  sw      x9, 0(x5)
  addi    x6, x6, 4
  addi    x5, x5, 4
  addi    x8, x8, -1
  bne     x8, x0, copy_info_word_loop

copy_info_tail:
  andi    x8, x7, 0x3
  beq     x8, x0, info_copy_done
  lw      x28, 0(x6)
  li      x9, 0x000000FF
  li      x18, 1
  bne     x8, x18, check_info_2
  and     x28, x28, x9
  sw      x28, 0(x5)
  beq     x0, x0, info_copy_done
check_info_2:
  li      x18, 2
  bne     x8, x18, check_info_3
  li      x9, 0x0000FFFF
  and     x28, x28, x9
  sw      x28, 0(x5)
  beq     x0, x0, info_copy_done
check_info_3:
  li      x9, 0x00FFFFFF
  and     x28, x28, x9
  sw      x28, 0(x5)

info_copy_done:

  /* 3. 追加单字节 counter i (此处 x21 会被 slli 彻底破坏) */
  add     x5, x22, x7
  la      x6, hkdf_msg_buf
  add     x6, x6, x5
  srli    x9, x5, 2
  slli    x9, x9, 2
  la      x28, hkdf_msg_buf
  add     x28, x28, x9
  lw      x29, 0(x28)

  andi    x9, x5, 0x3
  li      x18, 1
  bne     x9, x18, append_shift_2
  slli    x21, x21, 8
  li      x18, 0x0000FF00
  and     x21, x21, x18
  or      x29, x29, x21
  sw      x29, 0(x28)
  beq     x0, x0, append_done
append_shift_2:
  li      x18, 2
  bne     x9, x18, append_shift_3
  slli    x21, x21, 16
  li      x18, 0x00FF0000
  and     x21, x21, x18
  or      x29, x29, x21
  sw      x29, 0(x28)
  beq     x0, x0, append_done
append_shift_3:
  li      x18, 3
  bne     x9, x18, append_shift_0
  slli    x21, x21, 24
  li      x18, 0xFF000000
  and     x21, x21, x18
  or      x29, x29, x21
  sw      x29, 0(x28)
  beq     x0, x0, append_done
append_shift_0:
  li      x18, 0x000000FF
  and     x21, x21, x18
  or      x29, x29, x21
  sw      x29, 0(x28)

append_done:

  /* ==========================================
   * 4. 计算下一轮 counter 并存入绝对安全区
   * ========================================== */
  addi    x23, x23, 1     # x23 = i + 1

  la      x5, hkdf_ctx
  sw      x20, 0(x5)      # 保存 N
  sw      x23, 4(x5)      # 保存 下一次的 i
  sw      x22, 8(x5)      # 保存 下一次的 T_prev_len
  sw      x26, 12(x5)     # 保存 下一次的 okm_offset

  /* 5. 调用 HMAC */
  lw      x10, 56(sp)
  li      x11, 32
  la      x12, hkdf_msg_buf
  add     x13, x22, x7
  addi    x13, x13, 1
  la      x14, t_buf
  jal     x1, hmac

  /* 6. 从安全区恢复 */
  la      x5, hkdf_ctx
  lw      x20, 0(x5)
  lw      x21, 4(x5)      # x21 拿到正确的下一轮 i
  lw      x22, 8(x5)
  lw      x26, 12(x5)

  /* 7. 拷贝 T(i) 到 okm */
  lw      x14, 40(sp)
  add     x14, x14, x26
  la      x5, t_buf
  LOOPI   8, 4
    lw    x6, 0(x5)
    sw    x6, 0(x14)
    addi  x5, x5, 4
    addi  x14, x14, 4

  /* 8. 更新状态 */
  addi    x26, x26, 32
  li      x22, 32
  addi    x20, x20, -1
  bne     x20, x0, expand_loop

  lw      ra, 60(sp)
  addi    sp, sp, 64
  ret
