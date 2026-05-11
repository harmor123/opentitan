/*
 * 名称:        hkdf (总控入口)
 *
 * 描述:        HKDF 完整流程的总控包装函数。内部自动完成 Extract 和 Expand。
 *              调用者无需关心中间态 PRK 的内存分配，直接传入原始参数即可获得最终 OKM。
 *
 * 参数:        - x10: 盐值指针 (salt_ptr)
 *              - x11: 盐值长度 (salt_len)
 *              - x12: 输入密钥材料指针 (ikm_ptr)
 *              - x13: 输入密钥材料长度 (ikm_len)
 *              - x14: 上下文信息指针 (info_ptr)
 *              - x15: 上下文信息长度 (info_len)
 *              - x16: 期望输出长度 (L)
 *              - x17: 输出缓冲区指针 (okm_ptr)
 *
 * 破坏的寄存器: 同子函数，ra 被保护。
 */
.globl hkdf
hkdf:
  addi    sp, sp, -32
  sw      ra, 28(sp)
  sw      x14, 24(sp)     # 暂存 info_ptr
  sw      x15, 20(sp)     # 暂存 info_len
  sw      x16, 16(sp)     # 暂存 L
  sw      x17, 12(sp)     # 暂存 okm_ptr

  /* --- 第一步：Extract ---  */
  la      x14, _int_prk_buf
  jal     x1, _hkdf_extract_internal

  /* --- 第二步：Expand ---  */
  la      x10, _int_prk_buf   # x10 = prk_ptr
  li      x11, 32             # x11 = prk_len (固定32)
  lw      x12, 24(sp)         # x12 = info_ptr
  lw      x13, 16(sp)         # x13 = L
  lw      x14, 12(sp)         # x14 = okm_ptr
  
  # 注意：expand 原本 x12 是 info_len，现在我们把接口微调一下
  lw      x15, 20(sp)         # x15 = info_len (传给 expand)
  
  jal     x1, _hkdf_expand_internal

  lw      ra, 28(sp)
  addi    sp, sp, 32
  ret


/* ==========================================
 * 以下为内部实现，不暴露 .globl，仅文件内可见
 * ========================================== */

/*
 * 内部 Extract (去掉了 .globl)
 * 接口: x10=salt, x11=salt_len, x12=ikm, x13=ikm_len, x14=prk_out
 */
_hkdf_extract_internal:
  addi    sp, sp, -32
  sw      ra, 28(sp)
  sw      x10, 24(sp)
  sw      x11, 20(sp)
  sw      x12, 16(sp)
  sw      x13, 12(sp)
  sw      x14, 8(sp)

  bne     x11, x0, _do_extract
  la      x10, _int_default_salt
  li      x11, 32

_do_extract:
  jal     x1, hmac

  lw      ra, 28(sp)
  addi    sp, sp, 32
  ret


/*
 * 内部 Expand (去掉了 .globl，并微调了参数接收方式)
 * 接口: x10=prk, x11=32, x12=info, x13=L, x14=okm, x15=info_len
 */
_hkdf_expand_internal:
  addi    sp, sp, -64
  sw      ra, 60(sp)
  sw      x10, 56(sp)
  sw      x12, 48(sp)     # 存 info_ptr
  sw      x13, 44(sp)     # 存 L
  sw      x14, 40(sp)     # 存 okm_ptr
  sw      x15, 36(sp)     # 新增：存 info_len (原本是 x12)

  addi    x20, x13, 31
  srli    x20, x20, 5

  li      x21, 1
  li      x22, 0
  li      x26, 0

expand_loop:
  la      x5, hkdf_msg_buf
  addi    x23, x21, 0

  beq     x22, x0, skip_t_prev_copy
  la      x6, t_buf
  LOOPI   8, 4
    lw    x7, 0(x6)
    sw    x7, 0(x5)
    addi  x6, x6, 4
    addi  x5, x5, 4

skip_t_prev_copy:
  /* 拷贝 info (从栈上 36(sp) 读长度，从 48(sp) 读指针) */
  lw      x6, 48(sp)
  lw      x7, 36(sp)     # 注意这里变了！
  srli    x3, x7, 2
  beq     x3, x0, copy_info_tail

copy_info_word_loop:
  lw      x9, 0(x6)
  sw      x9, 0(x5)
  addi    x6, x6, 4
  addi    x5, x5, 4
  addi    x3, x3, -1
  bne     x3, x0, copy_info_word_loop

copy_info_tail:
  andi    x3, x7, 0x3
  beq     x3, x0, info_copy_done
  lw      x28, 0(x6)
  li      x9, 0x000000FF
  li      x18, 1
  bne     x3, x18, check_info_2
  and     x28, x28, x9
  sw      x28, 0(x5)
  beq     x0, x0, info_copy_done
check_info_2:
  li      x18, 2
  bne     x3, x18, check_info_3
  li      x9, 0x0000FFFF
  and     x28, x28, x9
  sw      x28, 0(x5)
  beq     x0, x0, info_copy_done
check_info_3:
  li      x9, 0x00FFFFFF
  and     x28, x28, x9
  sw      x28, 0(x5)

info_copy_done:

  /* 追加 counter i */
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

  addi    x23, x23, 1
  la      x5, hkdf_ctx
  sw      x20, 0(x5)
  sw      x23, 4(x5)
  sw      x22, 8(x5)
  sw      x26, 12(x5)

  /* 调用 HMAC */
  lw      x10, 56(sp)
  li      x11, 32
  la      x12, hkdf_msg_buf
  add     x13, x22, x7
  addi    x13, x13, 1
  la      x14, t_buf
  jal     x1, hmac

  la      x5, hkdf_ctx
  lw      x20, 0(x5)
  lw      x21, 4(x5)
  lw      x22, 8(x5)
  lw      x26, 12(x5)

  /* 拷贝到 okm */
  lw      x14, 40(sp)
  add     x14, x14, x26
  la      x5, t_buf
  LOOPI   8, 4
    lw    x6, 0(x5)
    sw    x6, 0(x14)
    addi  x5, x5, 4
    addi  x14, x14, 4

  addi    x26, x26, 32
  li      x22, 32
  addi    x20, x20, -1
  bne     x20, x0, expand_loop

  lw      ra, 60(sp)
  addi    sp, sp, 64
  ret


/* ==========================================
 * 内部私有数据区 (不带 .globl，外部不可见，不污染命名空间)
 * ========================================== */
.balign 32
_int_default_salt:
  .zero 32

.balign 32
_int_prk_buf:
  .zero 32
