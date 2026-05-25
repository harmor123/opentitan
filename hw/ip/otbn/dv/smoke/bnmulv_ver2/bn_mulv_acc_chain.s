/* mulv ACC chain test — two mulv.16H with same WDR, ACC should carry over */

.section .text.start
.globl main
main:
    la      x2, test_data
    li      x4, 4
    bn.lid  x4, 0(x2)

    /* mulv.16H.acc.z.lo w30, w0, w1 — zero ACC, mul, acc lo */
    bn.mulv.16H.acc.z.lo w30, w0, w1

    /* mulv.16H.acc.hi  w30, w0, w1 — accumulate with previous ACC */
    bn.mulv.16H.acc.hi  w30, w0, w1

    xor     x2, x2, x2
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
    .word 0x00210022
    .word 0x00230024
    .word 0x00250026
    .word 0x00270028
    .word 0x0029002a
    .word 0x002b002c
    .word 0x002d002e
    .word 0x002f0030
    .word 0x00310032
    .word 0x00330034
    .word 0x00350036
    .word 0x00370038
    .word 0x0039003a
    .word 0x003b003c
    .word 0x003d003e
    .word 0x003f0040
