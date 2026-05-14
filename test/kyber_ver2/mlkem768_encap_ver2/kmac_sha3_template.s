/* ================================================================
 * kmac_hw_driver.s
 *
 * 兼容标准 OpenTitan KMAC 硬件的极简驱动库
 * ================================================================ */

.section .text

/* ================================================================
 * kmac_init: 初始化 KMAC 硬件并进入 Absorb 状态
 * ================================================================ */
.globl kmac_init
kmac_init:
    addi    x6, x0, 1
.wait_idle:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_idle

    addi    x5, x0, 6
    csrrw   x0, 0x7d9, x5
    addi    x5, x0, 1
    csrrw   x0, 0x7da, x5

    beq     x10, x0, .cfg_sha3_256
    addi    x5, x0, 1
    beq     x10, x5, .cfg_sha3_512
    addi    x5, x0, 2
    beq     x10, x5, .cfg_shake128
    addi    x5, x0, 3
    beq     x10, x5, .cfg_shake256
    ecall

.cfg_sha3_256:
    addi    x5, x0, 4
    jal     x0, .apply_cfg
.cfg_sha3_512:
    addi    x5, x0, 8
    jal     x0, .apply_cfg
.cfg_shake128:
    addi    x5, x0, 32
    jal     x0, .apply_cfg
.cfg_shake256:
    addi    x5, x0, 36

.apply_cfg:
    csrrw   x0, 0x7db, x5
    addi    x5, x0, 29
    csrrw   x0, 0x7dd, x5

    addi    x6, x0, 2
.wait_absorb:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_absorb
    ret

/* ================================================================
 * keccak_send_message: 向 KMAC 核心发送可变长度消息
 * ================================================================ */
.globl keccak_send_message
keccak_send_message:
  bn.xor  w1, w1, w1
  srli    x5, x11, 5
  beq     x5, x0, _no_full_wdr
  slli    x5, x5, 5
  add     x5, x10, x5

_full_chunk_loop:
  beq     x10, x5, _no_full_wdr
  addi    x6, x0, 1
_wait_rdy_full:
  csrrs   x6, 0x7d9, x0
  andi    x6, x6, 1
  beq     x6, x0, _wait_rdy_full

  bn.lid  x0, 0(x10++)
  bn.wsrw 8, w0
  bn.wsrw 9, w1

  addi    x6, x0, -1
  csrrw   x0, 0x7de, x6
  addi    x6, x0, 1
  csrrw   x0, 0x7dc, x6

  jal     x0, _full_chunk_loop

_no_full_wdr:
  andi    x5, x11, 31
  beq     x5, x0, _keccak_send_message_end

  addi    x6, x0, 1
_wait_rdy_tail:
  csrrs   x6, 0x7d9, x0
  andi    x6, x6, 1
  beq     x6, x0, _wait_rdy_tail

  bn.lid  x0, 0(x10)

  /* 修复 OverflowError：动态生成掩码，清零 w0 高位垃圾数据 */
  bn.addi w1, w31, 1         /* w1 = 1 (省去一条 bn.xor) */
  addi    x7, x5, 0          /* x7 = x5 */
_mask_loop:
  beq     x7, x0, _mask_done
  addi    x7, x7, -1
  bn.rshi w1, w1, w31 >> 248 /* w1 <<= 8 */
  jal     x0, _mask_loop
_mask_done:
  bn.subi w1, w1, 1          /* w1 = mask */
  bn.and  w0, w0, w1         /* w0 &= mask */

  bn.wsrw 8, w0
  bn.xor  w1, w1, w1         /* 恢复 w1 = 0 */
  bn.wsrw 9, w1

  addi    x6, x0, 1
  sll     x6, x6, x5
  addi    x6, x6, -1
  csrrw   x0, 0x7de, x6
  addi    x6, x0, 1
  csrrw   x0, 0x7dc, x6

_keccak_send_message_end:
  ret

/* ================================================================
 * kmac_process: 结束 Absorb，进入 Squeeze 阶段
 * ================================================================ */
.globl kmac_process
kmac_process:
    addi    x5, x0, 46
    csrrw   x0, 0x7dd, x5

    addi    x6, x0, 8
.wait_digest:
    csrrs   x5, 0x7d9, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_digest
    ret

/* ================================================================
 * kmac_squeeze_32B: 挤出 32 字节摘要 
 *
 * 输入: x10 = out_ptr
 * 破坏: x5, x6, w8, w9, w10 (精简，不再破坏 w11, w12)
 * ================================================================ */
.globl kmac_squeeze_32B
kmac_squeeze_32B:
    /* 只需等待一次 Squeeze Valid，因为 Rate 足够大，后续 Word 直接读即可 */
    addi    x6, x0, 8
.wait_digest_0:
    csrrs   x5, 0x7d9, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_digest_0

    /* 读取 Word 0 */
    bn.wsrr w8, 8
    bn.wsrr w9, 9
    bn.xor  w8, w8, w9           /* Word 0 在 w8[63:0] 中，高位全 0 */

    /* 读取 Word 1 */
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10          /* Word 1 在 w9[63:0] 中 */
    bn.rshi w9, w9, w31 >> 192   /* w9 = Word1 << 64 */
    bn.or   w8, w8, w9

    /* 读取 Word 2 */
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10          /* Word 2 在 w9[63:0] 中 */
    bn.rshi w9, w9, w31 >> 128   /* w9 = Word2 << 128 */
    bn.or   w8, w8, w9

    /* 读取 Word 3 */
    bn.wsrr w9, 8
    bn.wsrr w10, 9
    bn.xor  w9, w9, w10          /* Word 3 在 w9[63:0] 中 */
    bn.rshi w9, w9, w31 >> 64    /* w9 = Word3 << 192 */
    bn.or   w8, w8, w9

    /* 将组装好的 256 位存入 DMEM */
    addi    x5, x0, 8
    bn.sid  x5, 0(x10)
    ret

/* ================================================================
 * kmac_run: 触发下一轮 Keccak-f 排列
 * ================================================================ */
.globl kmac_run
kmac_run:
    addi    x5, x0, 49
    csrrw   x0, 0x7dd, x5

    addi    x6, x0, 8
.wait_run_rdy:
    csrrs   x5, 0x7d9, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_run_rdy
    ret

/* ================================================================
 * kmac_done: 释放 KMAC 硬件回到 Idle
 * ================================================================ */
.globl kmac_done
kmac_done:
    addi    x5, x0, 22
    csrrw   x0, 0x7dd, x5

    addi    x6, x0, 1
.wait_idle_rel:
    csrrs   x5, 0xfc2, x0
    and     x5, x5, x6
    beq     x5, x0, .wait_idle_rel
    ret
