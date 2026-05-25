/* bn.addvm.16H / bn.subvm.16H smoke test — verify BNMULV buffer_bit MOD path */

.section .text.start
.globl main
main:
    /* Step 1: Load MOD = 0x0d01 into each 16-bit slot via WDR then WSR write */
    la      x2, mod_data
    li      x3, 31
    bn.lid  x3, 0(x2)     /* w31 = all 0x0d01 */

    /* Copy MOD to w0 before WSR write to avoid random WDR */
    bn.mov  w0, w31
    bn.wsrw 0x0, w0       /* MOD[15:0] = 0x0d01, replicated */

    /* Step 2: Load test vectors */
    la      x2, vec_a
    li      x3, 2
    bn.lid  x3, 0(x2)     /* w2 = vec_a */

    la      x2, vec_b
    li      x3, 3
    bn.lid  x3, 0(x2)     /* w3 = vec_b */

    /* Step 3: Execute addvm.16H and subvm.16H */
    bn.addvm.16H w4, w2, w3
    bn.subvm.16H w5, w2, w3

    xor     x2, x2, x2
    xor     x3, x3, x3
    xor     x4, x4, x4
    xor     x5, x5, x5
    xor     x31, x31, x31
    ecall

.data
.balign 32
mod_data:
    /* MOD: each 16-bit slot = 0x0d01 (Kyber Q=3329) */
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01
    .word 0x0d010d01

vec_a:
    /* All 16-bit values < q (0x0D01): even=0x0B00, odd=0x0200 */
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00
    .word 0x02000B00

vec_b:
    /* All 16-bit values < q: 0x0555 */
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
    .word 0x05550555
