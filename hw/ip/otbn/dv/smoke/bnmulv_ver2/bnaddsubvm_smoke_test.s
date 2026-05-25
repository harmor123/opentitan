/* Smoke test for bn.addvm.16H, bn.subvm.16H — modular edge cases */
.section .text.start
.globl main
main:
  /* Load modulus q = 3329 = 0xD01 into MOD (ML-KEM prime) */
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

  /* bn.addvm.16H: (a+b) mod q */
  bn.addvm.16H  w10, w2, w3

  /* bn.subvm.16H: (a-b) mod q */
  bn.subvm.16H  w11, w2, w3

  /* Store results */
  la     x7, result
  addi   x10, x0, 10
  bn.sid x10, 0(x10)
  addi   x11, x0, 11
  bn.sid x11, 32(x11)

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
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

/*
  16-bit vector vec_a for addvm/subvm
  Elements: [0, 1, 0x0D00=q-1, 0x0D01=q, 0x0D02=q+1, 0x0000, 0x0D00, 0x0001,
             0x0D00, 0x1A00=2q-2, 0x0000, 0x0D01, 0xffff=65535, 0x7fff, 0x8000, 0x0000]
*/
vec_a:
  .word 0x00010d00
  .word 0x1a000d00
  .word 0x00010000
  .word 0x0d020d01
  .word 0x0d000000
  .word 0x00000001
  .word 0x80007fff
  .word 0x0000ffff

/*
  16-bit vector vec_b for addvm/subvm
  Elements: [0, 0, 1, 1, 1, 0x0D01, 1, 1,
             1, 2, 0x0D01, 0x0D01, 1, 0x8000, 0x8000, 0x0001]
*/
vec_b:
  .word 0x00010001
  .word 0x00020001
  .word 0x00010d01
  .word 0x00010001
  .word 0x00010d00
  .word 0x00010001
  .word 0x80008000
  .word 0x00010000

/*
  Computed expected addvm.16H (mod q=0x0D01):
  elem[0]:  (0     + 0)     % 0xd01 = 0x0000
  elem[1]:  (1     + 0)     % 0xd01 = 0x0001
  elem[2]:  (0xd00 + 1)     % 0xd01 = 0x0000 (wrap: 0xd01 % 0xd01)
  elem[3]:  (0xd01 + 1)     % 0xd01 = 0x0001
  elem[4]:  (0xd02 + 1)     % 0xd01 = 0x0002
  elem[5]:  (0     + 0xd01) % 0xd01 = 0x0000
  elem[6]:  (0xd00 + 1)     % 0xd01 = 0x0000 (wrap)
  elem[7]:  (1     + 1)     % 0xd01 = 0x0002
  elem[8]:  (0xd00 + 1)     % 0xd01 = 0x0000 (wrap)
  elem[9]:  (0x1a00+ 2)     % 0xd01 = 0x0d01 -> 0x0000 (double wrap: 0x1a02%0xd01)
           0x1a02 / 0xd01 = 6658 / 3329 = 2 rem 0. So result = 0x0000
  elem[10]: (0     + 0xd01) % 0xd01 = 0x0000
  elem[11]: (0xd01 + 0xd01) % 0xd01 = 0x0000 (wrap)
  elem[12]: (0xffff+ 1)     % 0xd01 = 0x0000 mod 0xd01 = 0x0000 (65536%3329=...)
           65536 / 3329 = 19 rem 2285 = 19*3329=63251, 65536-63251=2285=0x8ED
           Wait, 16-bit unsigned mod. 0xffff + 1 = 0x10000 = 65536. 65536 % 3329.
           3329 * 19 = 63251. 65536 - 63251 = 2285 = 0x08ED.
  elem[13]: (0x7fff+ 0x8000)% 0xd01 = 0xffff % 0xd01 = 65535 % 3329
           3329 * 19 = 63251. 65535 - 63251 = 2284 = 0x08EC.
  elem[14]: (0x8000+ 0x8000)% 0xd01 = 0x10000 % 0xd01 = 65536 % 3329 = 2285 = 0x08ED
  elem[15]: (0     + 1)     % 0xd01 = 0x0001
*/
/*
  Expected subvm.16H (mod q=0x0D01):
  elem[0]:  (0     - 0)     mod 0xd01 = 0x0000
  elem[1]:  (1     - 0)     mod 0xd01 = 0x0001
  elem[2]:  (0xd00 - 1)     mod 0xd01 = 0x0CFF
  elem[3]:  (0xd01 - 1)     mod 0xd01 = 0x0D00
  elem[4]:  (0xd02 - 1)     mod 0xd01 = 0x0D01
  elem[5]:  (0     - 0xd01) mod 0xd01 = 0x0000 (a-b<0, add q: -3329+q=0)
  elem[6]:  (0xd00 - 1)     mod 0xd01 = 0x0CFF
  elem[7]:  (1     - 1)     mod 0xd01 = 0x0000
  elem[8]:  (0xd00 - 1)     mod 0xd01 = 0x0CFF
  elem[9]:  (0x1a00- 2)     mod 0xd01 = 0x19FE % 0xd01 = 0x19FE - 0xd01 = 0x19FE-0x0D01=0x0CFD
  elem[10]: (0     - 0xd01) mod 0xd01 = 0x0000
  elem[11]: (0xd01 - 0xd01) mod 0xd01 = 0x0000
  elem[12]: (0xffff- 1)     mod 0xd01 = 0xfffe % 0xd01 = 65534 % 3329
           3329 * 19 = 63251. 65534 - 63251 = 2283 = 0x08EB.
  elem[13]: (0x7fff- 0x8000)% 0xd01 = -1 mod 3329 = 3328 = 0x0D00
  elem[14]: (0x8000- 0x8000)% 0xd01 = 0 mod 3329 = 0x0000
  elem[15]: (0     - 1)     mod 0xd01 = -1 mod 3329 = 3328 = 0x0D00
*/

.balign 32
.globl result
result:
  .zero 256
