/* bn.shv smoke test — verify BignumShiftv (0x7F) with non-uniform 16H elements */

.section .text.start
.globl main
main:
    la      x2, w2_data
    li      x3, 2
    bn.lid  x3, 0(x2)

    /* bn.shv.8S w22, w2 << 1 */
    bn.shv.8S w22, w2 << 1

    /* bn.shv.8S w21, w2 >> 2 */
    bn.shv.8S w21, w2 >> 2

    /* bn.shv.16H w20, w2 << 1 — differing adjacent 16b values */
    bn.shv.16H w20, w2 << 1

    /* bn.shv.16H w19, w2 >> 3 — differing adjacent 16b values */
    bn.shv.16H w19, w2 >> 3

    xor     x2, x2, x2
    xor     x3, x3, x3
    xor     x4, x4, x4
    xor     x5, x5, x5
    ecall

.data
.balign 32
w2_data:
    /* alternating 16-bit: even=0xC001 (MSB=1), odd=0x1002 (MSB=0) */
    /* 32-bit word = {odd_16b, even_16b} = 0x1002C001 */
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
    .word 0x1002C001
