/* ================================================================
 * OpenTiton KMAC Hardware Driver – For Kyber (context label)
 *
 * 将软件 sha3 替换为 KMAC 硬件加速，保留完全相同的 API。
 * 上下文标签改为 context，匹配 Kyber 代码中的引用。
 * ================================================================ */

.section .text

.equ KMAC_IF_STATUS,    0x7d9
.equ KMAC_INTR,         0x7da
.equ KMAC_CFG,          0x7db
.equ KMAC_MSG_SEND,     0x7dc
.equ KMAC_CMD,          0x7dd
.equ KMAC_BYTE_STROBE,  0x7de
.equ KMAC_STATUS,       0xfc2
.equ KMAC_DATA_S0,      8
.equ KMAC_DATA_S1,      9

/* ---------- sha3_init ---------- */
.globl sha3_init
sha3_init:
    sw      x11, 208(x10)
    addi    x5, x0, 200
    slli    x6, x11, 1
    sub     x5, x5, x6
    sw      x5, 204(x10)
    addi    x6, x0, 32
    beq     x11, x6, .init_256
    addi    x6, x0, 64
    beq     x11, x6, .init_512
    unimp
.init_256:
    li      x5, 0x04
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret
.init_512:
    li      x5, 0x08
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret

.init_hw:
.wait_idle_i:
    csrrs   x6, KMAC_STATUS, x0
    andi    x6, x6, 0x1
    beq     x6, x0, .wait_idle_i
    csrrw   x0, KMAC_CFG, x5
    li      x6, 0x7
    csrrw   x0, KMAC_INTR, x6
    csrrw   x0, KMAC_IF_STATUS, x6
    li      x6, 0x1D
    csrrw   x0, KMAC_CMD, x6
.wait_absorb_i:
    csrrs   x6, KMAC_STATUS, x0
    andi    x6, x6, 0x2
    beq     x6, x0, .wait_absorb_i
    ret

/* ---------- shake128_init / shake256_init ---------- */
.globl shake128_init
shake128_init:
    addi    x5, x0, 168
    sw      x5, 204(x10)
    sw      x0, 208(x10)
    li      x5, 0x20
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret

.globl shake256_init
shake256_init:
    addi    x5, x0, 136
    sw      x5, 204(x10)
    sw      x0, 208(x10)
    li      x5, 0x24
    jal     x1, .init_hw
    sw      x0, 200(x10)
    ret

/* ---------- sha3_update ---------- */
.globl sha3_update
sha3_update:
    beq     x12, x0, .upd_done
    addi    x13, x11, 0
    addi    x14, x12, 0
    bn.xor  w23, w23, w23

.upd_loop:
.wait_rdy:
    csrrs   x15, KMAC_IF_STATUS, x0
    andi    x15, x15, 0x1
    beq     x15, x0, .wait_rdy
    addi    x16, x14, -32
    srli    x17, x16, 31
    bne     x17, x0, .upd_tail

    li      x15, -1
    csrrw   x0, KMAC_BYTE_STROBE, x15
    li      x15, 22
    bn.lid  x15, 0(x13)
    bn.wsrw KMAC_DATA_S0, w22
    bn.wsrw KMAC_DATA_S1, w23
    li      x15, 1
    csrrw   x0, KMAC_MSG_SEND, x15
    addi    x13, x13, 32
    addi    x14, x14, -32
    bne     x14, x0, .upd_loop
    jal     x0, .upd_done

.upd_tail:
    beq     x14, x0, .upd_done
    addi    x17, x14, 0               /* x17 = 消息原始长度 */
    la      x6, tailbuf
    addi    x7, x6, 0
    li      x3, 8
.clr_tail:
    sw      x0, 0(x7)
    addi    x7, x7, 4
    addi    x3, x3, -1
    bne     x3, x0, .clr_tail

    srli    x5, x14, 2                /* 完整 32-bit 字数量 */
    addi    x3, x13, 0                /* x3 = 源数据指针 */
    bne     x5, x0, .do_copy
    addi    x7, x6, 0                 /* 不足 4 字节时重置目标指针 */
    jal     x0, .tail_rem

.do_copy:
    addi    x7, x6, 0
    addi    x9, x5, 0
.copy_words:
    lw      x31, 0(x3)                
    sw      x31, 0(x7)
    addi    x7, x7, 4
    addi    x3, x3, 4
    addi    x9, x9, -1
    bne     x9, x0, .copy_words

.tail_rem:
    andi    x9, x14, 0x3
    beq     x9, x0, .tail_done_copy
    lw      x13, 0(x3)
    addi    x11, x0, 1
    beq     x9, x11, .is1
    addi    x11, x0, 2
    beq     x9, x11, .is2
    addi    x11, x0, 3
    beq     x9, x11, .is3
    jal     x0, .tail_done_copy
.is3:
    li      x12, 0xFFFFFF
    jal     x0, .apply_mask
.is2:
    li      x12, 0xFFFF
    jal     x0, .apply_mask
.is1:
    li      x12, 0xFF
.apply_mask:
    and     x13, x13, x12
    sw      x13, 0(x7)

.tail_done_copy:
    li      x15, 0
    li      x16, 1
    addi    x17, x17, 0               /* x17 此时为消息长度 */
.gen_strobe:
    or      x15, x15, x16
    slli    x16, x16, 1
    addi    x17, x17, -1
    bne     x17, x0, .gen_strobe
    csrrw   x0, KMAC_BYTE_STROBE, x15
    la      x13, tailbuf
    li      x15, 22
    bn.lid  x15, 0(x13)
    bn.wsrw KMAC_DATA_S0, w22
    bn.wsrw KMAC_DATA_S1, w23
    li      x15, 1
    csrrw   x0, KMAC_MSG_SEND, x15
.upd_done:
    ret

/* ---------- sha3_final ---------- */
.globl sha3_final
sha3_final:
    sw      x1, -4(sp)
    addi    x28, x11, 0
    li      x5, 0x2E
    csrrw   x0, KMAC_CMD, x5
.wait_done:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_done
    lw      x6, 208(x10)
    srli    x7, x6, 3
    addi    x15, x28, 0
.rd_loop:
    beq     x7, x0, .final_done
.wait_digest:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x8
    beq     x5, x0, .wait_digest
    bn.wsrr w10, KMAC_DATA_S0
    bn.wsrr w11, KMAC_DATA_S1
    bn.xor  w10, w10, w11
    la      x13, tailbuf
    bn.mov  w22, w10
    li      x12, 22
    bn.sid  x12, 0(x13)
    lw      x14, 0(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    lw      x14, 4(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    addi    x7, x7, -1
    jal     x0, .rd_loop
.final_done:
    li      x5, 0x16
    csrrw   x0, KMAC_CMD, x5
    lw      x1, -4(sp)
    ret

/* ---------- shake_xof ---------- */
.globl shake_xof
shake_xof:
    li      x5, 0x2E
    csrrw   x0, KMAC_CMD, x5
.wait_done_s:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_done_s
    sw      x0, 200(x10)
    ret

/* ---------- shake_out ---------- */
.globl shake_out
shake_out:
    sw      x1, -4(sp)
    lw      x16, 200(x10)
    bne     x16, x0, .sq_run
    jal     x0, .sq_read
.sq_run:
    li      x5, 0x31
    csrrw   x0, KMAC_CMD, x5
.sq_read:
    li      x7, 4
    addi    x15, x11, 0
.sq_rd_loop:
    beq     x7, x0, .sq_done
.wait_digest_out:
    csrrs   x5, KMAC_IF_STATUS, x0
    andi    x5, x5, 0x8
    beq     x5, x0, .wait_digest_out
    bn.wsrr w10, KMAC_DATA_S0
    bn.wsrr w11, KMAC_DATA_S1
    bn.xor  w10, w10, w11
    la      x13, tailbuf
    bn.mov  w22, w10
    li      x12, 22
    bn.sid  x12, 0(x13)
    lw      x14, 0(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    lw      x14, 4(x13)
    sw      x14, 0(x15)
    addi    x15, x15, 4
    addi    x7, x7, -1
    jal     x0, .sq_rd_loop
.sq_done:
    li      x16, 1
    sw      x16, 200(x10)
    lw      x1, -4(sp)
    ret

.globl kmac_release
kmac_release:
    li      x5, 0x16
    csrrw   x0, KMAC_CMD, x5
.wait_idle_rel:
    csrrs   x5, KMAC_STATUS, x0
    andi    x5, x5, 0x1
    beq     x5, x0, .wait_idle_rel
    ret

.section .data
.balign 32
.globl context
context:
    .zero 212

.balign 32
tailbuf:
    .zero 32