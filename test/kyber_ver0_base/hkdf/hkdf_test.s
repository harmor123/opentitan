.section .text.start
.globl main
main:
    la      x2, stack_end
    addi    x2, x2, -64
    
    la      x10, test_salt     # salt_ptr
    li      x11, 32            # salt_len
    la      x12, test_ikm      # ikm_ptr
    li      x13, 32            # ikm_len
    la      x14, test_info     # info_ptr
    li      x15, 32             # info_len
    li      x16, 64            # L
    la      x17, final_okm     # okm_ptr
    
    jal     x1, hkdf
    ecall

.data
.balign 32
.global stack
stack:
  .zero 1024              
stack_end:

/* 测试数据 */
.balign 32
test_salt:
  .rept 8
  .word 0x0b0b0b0b
  .endr

.balign 32
test_ikm:
  .rept 8
  .word 0x0b0b0b0b
  .endr


.balign 32
test_info:
  .rept 8
  .word 0x0b0b0b0b
  .endr

/* 最终输出 */
.balign 32
final_okm:
  .zero 64

.balign 32
.globl context
context:
  .zero 212

.globl rc
.balign 32
rc:
.balign 32
  .dword 0x0000000000000001
.balign 32
  .dword 0x0000000000008082
.balign 32
  .dword 0x800000000000808a
.balign 32
  .dword 0x8000000080008000
.balign 32
  .dword 0x000000000000808b
.balign 32
  .dword 0x0000000080000001
.balign 32
  .dword 0x8000000080008081
.balign 32
  .dword 0x8000000000008009
.balign 32
  .dword 0x000000000000008a
.balign 32
  .dword 0x0000000000000088
.balign 32
  .dword 0x0000000080008009
.balign 32
  .dword 0x000000008000000a
.balign 32
  .dword 0x000000008000808b
.balign 32
  .dword 0x800000000000008b
.balign 32
  .dword 0x8000000000008089
.balign 32
  .dword 0x8000000000008003
.balign 32
  .dword 0x8000000000008002
.balign 32
  .dword 0x8000000000000080
.balign 32
  .dword 0x000000000000800a
.balign 32
  .dword 0x800000008000000a
.balign 32
  .dword 0x8000000080008081
.balign 32
  .dword 0x8000000000008080
.balign 32
  .dword 0x0000000080000001
.balign 32
  .dword 0x8000000080008008

.balign 32
.globl inner_hash
inner_hash:
  .zero 32

.balign 32
.globl key_buf
key_buf:
  .zero 200

.balign 32
.globl ipad
ipad:
  .zero 200

.balign 32
.globl opad
opad:
  .zero 200

/* HKDF 专属隔离区 (保留) */
.balign 32
.globl hkdf_msg_buf
hkdf_msg_buf:
  .zero 320

.balign 32
.globl hkdf_ctx
hkdf_ctx:
  .zero 64

.balign 32
.globl t_buf
t_buf:
  .zero 32


