/* Smoke test for bn.addvm.16H, bn.subvm.16H — modular (mod q=0x0D01=3329) */
/* All inputs in [0, q-1], matching ML-KEM reduced input assumption. */
.section .text.start
.globl main
main:
  /* Load modulus q = 3329 = 0xD01 into MOD */
  li     x2, 20
  la     x3, mod_q
  bn.lid x2, 0(x3)
  bn.wsrw MOD, w20

  /* Load test vectors */
  addi   x2, x0, 2
  la     x3, vec_a
  bn.lid x2++, 0(x3)
  la     x3, vec_b
  bn.lid x2++, 0(x3)

  bn.addvm.16H  w10, w2, w3
  bn.subvm.16H  w11, w2, w3

  /* Store results */
  la     x7, result
  addi   x10, x0, 10
  bn.sid x10, 0(x7)
  addi   x11, x0, 11
  bn.sid x11, 32(x7)

  /* Clear working registers */
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
  bn.xor w12, w12, w12
  bn.xor w13, w13, w13
  bn.xor w14, w14, w14
  bn.xor w15, w15, w15
  bn.xor w16, w16, w16
  bn.xor w17, w17, w17
  bn.xor w18, w18, w18
  bn.xor w19, w19, w19
  bn.xor w20, w20, w20
  bn.xor w21, w21, w21
  bn.xor w22, w22, w22
  bn.xor w23, w23, w23
  bn.xor w24, w24, w24
  bn.xor w25, w25, w25
  bn.xor w26, w26, w26
  bn.xor w27, w27, w27
  bn.xor w28, w28, w28
  bn.xor w29, w29, w29
  bn.xor w30, w30, w30
  bn.xor w31, w31, w31

  addi x2, x0, 0
  addi x3, x0, 0

  xor  x8,  x8,  x8
  xor  x9,  x9,  x9
  xor  x10, x10, x10
  xor  x11, x11, x11
  xor  x12, x12, x12
  xor  x13, x13, x13
  xor  x14, x14, x14
  xor  x15, x15, x15
  xor  x16, x16, x16
  xor  x17, x17, x17
  xor  x18, x18, x18
  xor  x19, x19, x19
  xor  x20, x20, x20
  xor  x21, x21, x21
  xor  x22, x22, x22
  xor  x23, x23, x23
  xor  x24, x24, x24
  xor  x25, x25, x25
  xor  x26, x26, x26
  xor  x27, x27, x27
  xor  x28, x28, x28
  xor  x29, x29, x29
  xor  x30, x30, x30
  xor  x31, x31, x31

  ecall

.section .data

/*
  Modulus q = 3329 = 0x0D01 (ML-KEM prime)
*/
.balign 32
mod_q:
  .word 0x00000d01
  .zero 28

/*
  16-bit vec_a (all in [0, q-1]):
  [0x0000, 0x0001, 0x0D00, 0x0D00, 0x0001, 0x0000, 0x0D00, 0x0680,
   0x0001, 0x0CFF, 0x0000, 0x0D00, 0x0680, 0x0000, 0x0D00, 0x0001]
*/
vec_a:
  .word 0x00010000   /* [1]=0x0001, [0]=0x0000 */
  .word 0x0D000D00   /* [3]=0x0D00, [2]=0x0D00 */
  .word 0x00000001   /* [5]=0x0000, [4]=0x0001 */
  .word 0x06800D00   /* [7]=0x0680, [6]=0x0D00 */
  .word 0x0CFF0001   /* [9]=0x0CFF, [8]=0x0001 */
  .word 0x0D000000   /* [11]=0x0D00, [10]=0x0000 */
  .word 0x00000680   /* [13]=0x0000, [12]=0x0680 */
  .word 0x00010D00   /* [15]=0x0001, [14]=0x0D00 */

/*
  16-bit vec_b (all in [0, q-1]):
  [0x0000, 0x0000, 0x0001, 0x0000, 0x0D00, 0x0D00, 0x0001, 0x0680,
   0x0D00, 0x0001, 0x0001, 0x0001, 0x0001, 0x0D00, 0x0001, 0x0001]
*/
vec_b:
  .word 0x00000000   /* [1]=0, [0]=0 */
  .word 0x00000001   /* [3]=0, [2]=1 */
  .word 0x0D000D00   /* [5]=0xD00, [4]=0xD00 */
  .word 0x06800001   /* [7]=0x680, [6]=1 */
  .word 0x00010D00   /* [9]=1, [8]=0xD00 */
  .word 0x00010001   /* [11]=1, [10]=1 */
  .word 0x0D000001   /* [13]=0xD00, [12]=1 */
  .word 0x00010001   /* [15]=1, [14]=1 */

/*
  Expected addvm.16H (mod q=0x0D01):
  elem[0]:  (0    + 0)    % q = 0x0000
  elem[1]:  (1    + 0)    % q = 0x0001
  elem[2]:  (0xD00+ 1)    % q = 0x0000  (wrap: D01%D01=0)
  elem[3]:  (0xD00+ 0)    % q = 0x0D00
  elem[4]:  (1    + 0xD00)% q = 0x0000  (wrap)
  elem[5]:  (0    + 0xD00)% q = 0x0D00
  elem[6]:  (0xD00+ 1)    % q = 0x0000  (wrap)
  elem[7]:  (0x680+ 0x680)% q = 0x0D00  (680*2=D00<q)
  elem[8]:  (1    + 0xD00)% q = 0x0000  (wrap)
  elem[9]:  (0xCFF+ 1)    % q = 0x0D00  (CFF+1=D00<q)
  elem[10]: (0    + 1)    % q = 0x0001
  elem[11]: (0xD00+ 1)    % q = 0x0000  (wrap)
  elem[12]: (0x680+ 1)    % q = 0x0681
  elem[13]: (0    + 0xD00)% q = 0x0D00
  elem[14]: (0xD00+ 1)    % q = 0x0000  (wrap)
  elem[15]: (1    + 1)    % q = 0x0002

  Expected subvm.16H (mod q=0x0D01):
  elem[0]:  (0    - 0)    mod q = 0x0000
  elem[1]:  (1    - 0)    mod q = 0x0001
  elem[2]:  (0xD00- 1)    mod q = 0x0CFF
  elem[3]:  (0xD00- 0)    mod q = 0x0D00
  elem[4]:  (1    - 0xD00)mod q = 0x0002  (neg: +q=1-D00+D01=2)
  elem[5]:  (0    - 0xD00)mod q = 0x0001  (neg: 0-D00+D01=1)
  elem[6]:  (0xD00- 1)    mod q = 0x0CFF
  elem[7]:  (0x680- 0x680)mod q = 0x0000
  elem[8]:  (1    - 0xD00)mod q = 0x0002  (neg)
  elem[9]:  (0xCFF- 1)    mod q = 0x0CFE
  elem[10]: (0    - 1)    mod q = 0x0D00  (neg: 0-1+D01=D00=q-1)
  elem[11]: (0xD00- 1)    mod q = 0x0CFF
  elem[12]: (0x680- 1)    mod q = 0x067F
  elem[13]: (0    - 0xD00)mod q = 0x0001  (neg)
  elem[14]: (0xD00- 1)    mod q = 0x0CFF
  elem[15]: (1    - 1)    mod q = 0x0000
*/

.balign 32
.globl result
result:
  .zero 256
