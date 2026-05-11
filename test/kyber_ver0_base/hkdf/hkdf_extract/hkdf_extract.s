/*
 * 名称:        hkdf_extract
 *
 * 描述:        基于 HMAC-SHA3-256 的 HKDF-Extract 密钥提取。
 *              实现 RFC 5869 定义的 HKDF-Extract 算法。
 *              如果提供的 salt 为空（长度为 0），则自动替换为 32 字节的全零串。
 *              核心逻辑为：PRK = HMAC-SHA3-256(salt, IKM)。
 *
 * 参数:        - x10: 盐值指针 (salt_ptr)
 *              - x11: 盐值长度 (salt_len)，单位字节。若为 0 则触发默认全零 salt
 *              - x12: 输入密钥材料指针 (ikm_ptr)
 *              - x13: 输入密钥材料长度 (ikm_len)，单位字节
 *              - x14: 输出伪随机密钥缓冲区指针 (prk_ptr)，需保证至少 32 字节空间
 *
 * 标志:        会破坏 FG0，对调用者无特殊含义。
 *
 * 破坏的寄存器: x5-x9, x16-x19, x28-x31, w0-w13, w21-w30（通过调用 hmac/sha3_* 间接破坏）
 *               以及栈上保存的 ra, x10-x14 被保护。
 */
.globl hkdf_extract
hkdf_extract:
  addi    sp, sp, -32
  sw      ra, 28(sp)
  sw      x10, 24(sp)
  sw      x11, 20(sp)
  sw      x12, 16(sp)
  sw      x13, 12(sp)
  sw      x14, 8(sp)

  /* ==========================================
   * 1. 检查 salt_len == 0，处理默认全零 salt
   * ========================================== */
  bne     x11, x0, call_hmac_extract
  la      x10, default_salt   # 加载默认的 32 字节 0x00 地址
  li      x11, 32             # 默认 salt 长度设为 32

call_hmac_extract:
  /* ==========================================
   * 2. 调用 HMAC(salt, ikm)
   * 参数已经完美对齐 hmac.s 的接口：
   * x10 = salt_ptr (key)
   * x11 = salt_len (key_len)
   * x12 = ikm_ptr  (msg)
   * x13 = ikm_len  (msg_len)
   * x14 = prk_ptr  (out)
   * ========================================== */
  jal     x1, hmac

  lw      ra, 28(sp)
  addi    sp, sp, 32
  ret

