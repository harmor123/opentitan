.section .text.start
.globl main
main:
    la      x2, stack_end
    
    /* 为 hmac 函数分配局部栈空间 */
    addi    x2, x2, -64
    
    /* 准备 HMAC 测试参数 (测试向量 4.2) */
    la      x10, my_key
    li      x11, 20          /* key_len = 20 bytes */
    la      x12, my_message
    li      x13, 8           /* msg_len = 8 bytes ("Hi There") */
    la      x14, my_hmac
    
    jal     x1, hmac
    ecall

.data

/* 栈空间 */
.balign 32
.global stack
stack:
  .zero 1024              
stack_end:

/* 必须的上下文空间 */
.balign 32
.globl context
context:
  .zero 212

/* 必须的 Keccak 轮常数 
 * 警告：keccakf 内部使用 bn.lid x31, 0(x6++) 读取，x6每次自增32字节！
 * 所以这里必须严格每个常量占 32 字节，且头部必须 .balign 32 防止与 context 重叠！
 */
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

/* 辅助数据缓冲区 */
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

/* 测试数据 */
.balign 4
my_key:
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b
    .word 0x0b0b0b0b

.balign 4
my_message:
#    .word 0x48692054
#    .word 0x68657265
    
#    .word 0x54206948
#    .word 0x65726568
    .word 0x74616877        /* "what" */
    .word 0x206f6420        /* " do " (注意空格) */
  
.balign 4
my_hmac:
    .zero 32
