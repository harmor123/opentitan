/* Lane-mode mulv.16H chain test — replicate ML-KEM basemul pattern */

.section .text.start
.globl main
main:
    la      x2, test_data
    li      x4, 2
    bn.lid  x4, 0(x2)

    li      x3, 0x0d010d01
    csrrw   x0, 0x7D0, x3

    bn.xor  w31, w31, w31
    bn.addi w26, w31, 1

    /* 3-instruction chain matching ML-KEM basemul */
    bn.mulv.16H.acc.z.lo w26, w0, w1
    bn.mulv.l.16H.lo     w26, w26, sw0.2
    bn.mulv.l.16H.acc.hi w26, w26, sw0.0

    xor     x2, x2, x2
    xor     x3, x3, x3
    xor     x4, x4, x4
    ecall

.data
.balign 32
test_data:
    .word 0x00010002
    .word 0x00030004
    .word 0x00050006
    .word 0x00070008
    .word 0x0009000a
    .word 0x000b000c
    .word 0x000d000e
    .word 0x000f0010
    .word 0x00110012
    .word 0x00130014
    .word 0x00150016
    .word 0x00170018
    .word 0x0019001a
    .word 0x001b001c
    .word 0x001d001e
    .word 0x001f0020
