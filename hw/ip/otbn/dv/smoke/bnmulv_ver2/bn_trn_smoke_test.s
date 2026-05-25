/* bn.trn smoke test — verify trn1/trn2 at all element sizes */

.section .text.start
.globl main
main:
    /* Load test vectors */
    la      x2, trn_a
    li      x3, 2
    bn.lid  x3, 0(x2)     /* w2 = pattern A */

    la      x2, trn_b
    li      x3, 3
    bn.lid  x3, 0(x2)     /* w3 = pattern B */

    /* bn.trn1.8S w4, w2, w3 — 32-bit element transpose */
    bn.trn1.8S w4, w2, w3

    /* bn.trn2.8S w5, w2, w3 */
    bn.trn2.8S w5, w2, w3

    /* bn.trn1.16H w6, w2, w3 — 16-bit element transpose */
    bn.trn1.16H w6, w2, w3

    /* bn.trn2.16H w7, w2, w3 */
    bn.trn2.16H w7, w2, w3

    xor     x2, x2, x2
    xor     x3, x3, x3
    xor     x4, x4, x4
    xor     x5, x5, x5
    xor     x6, x6, x6
    xor     x7, x7, x7
    ecall

.data
.balign 32
trn_a:
    /* 8 x 32-bit: 0,1,2,3,4,5,6,7 (as 16-bit: 0x0001,0x0000, 0x0003,0x0002, ...) */
    .word 0x00000001  /* elem0 */
    .word 0x00000003  /* elem1 */
    .word 0x00000005  /* elem2 */
    .word 0x00000007  /* elem3 */
    .word 0x00000009  /* elem4 */
    .word 0x0000000B  /* elem5 */
    .word 0x0000000D  /* elem6 */
    .word 0x0000000F  /* elem7 */

trn_b:
    /* 8 x 32-bit: 10,11,12,13,14,15,16,17 */
    .word 0x00000011  /* elem0 */
    .word 0x00000013  /* elem1 */
    .word 0x00000015  /* elem2 */
    .word 0x00000017  /* elem3 */
    .word 0x00000019  /* elem4 */
    .word 0x0000001B  /* elem5 */
    .word 0x0000001D  /* elem6 */
    .word 0x0000001F  /* elem7 */
