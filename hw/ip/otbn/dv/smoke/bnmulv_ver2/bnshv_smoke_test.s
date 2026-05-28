/* Smoke test for bn.shv.16H, bn.shv.8S — comprehensive shift coverage
 *
 * BUG: bn.shv.8S << 10 produced no shift (input=output) in ML-KEM encap.
 * Root cause: left-shift immediate > 1 was not correctly decoded in RTL.
 *
 * Test matrix:
 *   bn.shv.8S:  left  << 1, 10, 24, 31    right >> 1, 16, 24, 31
 *   bn.shv.16H: left  << 1,  8, 10, 15    right >> 1,  8, 15
 */
.section .text.start
.globl main
main:
  /* Load test vector: [0x80000000, 0x7fffffff, 0x00000001, 0xffffffff,
                         0x55555555, 0xaaaaaaaa, 0x12345678, 0x00000000] */
  addi   x2, x0, 0
  la     x3, vec_orig
  bn.lid x2, 0(x3)

  /* ── bn.shv.8S right shifts ── */
  bn.shv.8S   w10, w0 >> 1       /* result[0] */
  bn.shv.8S   w11, w0 >> 16      /* result[1] */
  bn.shv.8S   w12, w0 >> 24      /* result[2] */
  bn.shv.8S   w13, w0 >> 31      /* result[3] */

  /* ── bn.shv.8S left shifts ── */
  bn.shv.8S   w14, w0 << 1       /* result[4] */
  bn.shv.8S   w15, w0 << 10      /* result[5] ← BUG: was no-op in RTL */
  bn.shv.8S   w16, w0 << 24      /* result[6] */
  bn.shv.8S   w17, w0 << 31      /* result[7] */

  /* ── bn.shv.16H right shifts ── */
  bn.shv.16H  w18, w0 >> 1       /* result[8] */
  bn.shv.16H  w19, w0 >> 8       /* result[9] */
  bn.shv.16H  w20, w0 >> 15      /* result[10] */

  /* ── bn.shv.16H left shifts ── */
  bn.shv.16H  w21, w0 << 1       /* result[11] */
  bn.shv.16H  w22, w0 << 8       /* result[12] */
  bn.shv.16H  w23, w0 << 10      /* result[13] */
  bn.shv.16H  w24, w0 << 15      /* result[14] */

  /* Store results — one WDR each */
  la     x7, result
  addi   x10, x0, 10
  bn.sid x10, 0(x7)
  addi   x11, x0, 11
  bn.sid x11, 32(x7)
  addi   x12, x0, 12
  bn.sid x12, 64(x7)
  addi   x13, x0, 13
  bn.sid x13, 96(x7)
  addi   x14, x0, 14
  bn.sid x14, 128(x7)
  addi   x15, x0, 15
  bn.sid x15, 160(x7)
  addi   x16, x0, 16
  bn.sid x16, 192(x7)
  addi   x17, x0, 17
  bn.sid x17, 224(x7)
  addi   x18, x0, 18
  bn.sid x18, 256(x7)
  addi   x19, x0, 19
  bn.sid x19, 288(x7)
  addi   x20, x0, 20
  bn.sid x20, 320(x7)
  addi   x21, x0, 21
  bn.sid x21, 352(x7)
  addi   x22, x0, 22
  bn.sid x22, 384(x7)
  addi   x23, x0, 23
  bn.sid x23, 416(x7)
  addi   x24, x0, 24
  bn.sid x24, 448(x7)

  /* Clear working registers */
  .rept 31
  bn.xor w31, w31, w31
  .endr
  xor  x2, x2, x2
  xor  x3, x3, x3
  xor  x7, x7, x7
  xor  x8, x8, x8
  xor  x9, x9, x9
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

  ecall

.section .data

/*
  Test vector — each 32-bit element:
  [0x80000000, 0x7fffffff, 0x00000001, 0xffffffff,
   0x55555555, 0xaaaaaaaa, 0x12345678, 0x00000000]
*/
vec_orig:
  .word 0x00000000
  .word 0x12345678
  .word 0xaaaaaaaa
  .word 0x55555555
  .word 0xffffffff
  .word 0x00000001
  .word 0x7fffffff
  .word 0x80000000

/*
  Expected results
  =================

  ── bn.shv.8S right shifts ──

  >> 1:  0x80000000>>1=0x40000000  0x7fffffff>>1=0x3fffffff
         0x00000001>>1=0x00000000  0xffffffff>>1=0x7fffffff
         0x55555555>>1=0x2aaaaaaa  0xaaaaaaaa>>1=0x55555555
         0x12345678>>1=0x091a2b3c  0x00000000>>1=0x00000000
         => 0x00000000_091a2b3c_55555555_2aaaaaaa_7fffffff_00000000_3fffffff_40000000

  >> 16: 0x80000000>>16=0x00008000 0x7fffffff>>16=0x00007fff
         0x00000001>>16=0x00000000 0xffffffff>>16=0x0000ffff
         0x55555555>>16=0x00005555 0xaaaaaaaa>>16=0x0000aaaa
         0x12345678>>16=0x00001234 0x00000000>>16=0x00000000
         => 0x00000000_00001234_0000aaaa_00005555_0000ffff_00000000_00007fff_00008000

  >> 24: 0x80000000>>24=0x00000080 0x7fffffff>>24=0x0000007f
         0x00000001>>24=0x00000000 0xffffffff>>24=0x000000ff
         0x55555555>>24=0x00000055 0xaaaaaaaa>>24=0x000000aa
         0x12345678>>24=0x00000012 0x00000000>>24=0x00000000
         => 0x00000000_00000012_000000aa_00000055_000000ff_00000000_0000007f_00000080

  >> 31: 0x80000000>>31=0x00000001 0x7fffffff>>31=0x00000000
         0x00000001>>31=0x00000000 0xffffffff>>31=0x00000001
         0x55555555>>31=0x00000000 0xaaaaaaaa>>31=0x00000001
         0x12345678>>31=0x00000000 0x00000000>>31=0x00000000
         => 0x00000000_00000000_00000001_00000000_00000001_00000000_00000000_00000001

  ── bn.shv.8S left shifts ──

  << 1:  0x80000000<<1=0x00000000 0x7fffffff<<1=0xfffffffe
         0x00000001<<1=0x00000002 0xffffffff<<1=0xfffffffe
         0x55555555<<1=0xaaaaaaaa 0xaaaaaaaa<<1=0x55555554
         0x12345678<<1=0x2468acf0 0x00000000<<1=0x00000000
         => 0x00000000_2468acf0_55555554_aaaaaaaa_fffffffe_00000002_fffffffe_00000000

  << 10: 0x80000000<<10=0x00000000 0x7fffffff<<10=0xfffffc00
         0x00000001<<10=0x00000400 0xffffffff<<10=0xfffffc00
         0x55555555<<10=0x55555400 0xaaaaaaaa<<10=0xaaaaa800
         0x12345678<<10=0xd159e000 0x00000000<<10=0x00000000
         => 0x00000000_d159e000_aaaaa800_55555400_fffffc00_00000400_fffffc00_00000000

  << 24: 0x80000000<<24=0x00000000 0x7fffffff<<24=0xff000000
         0x00000001<<24=0x01000000 0xffffffff<<24=0xff000000
         0x55555555<<24=0x55000000 0xaaaaaaaa<<24=0xaa000000
         0x12345678<<24=0x78000000 0x00000000<<24=0x00000000
         => 0x00000000_78000000_aa000000_55000000_ff000000_01000000_ff000000_00000000

  << 31: 0x80000000<<31=0x00000000 0x7fffffff<<31=0x80000000
         0x00000001<<31=0x80000000 0xffffffff<<31=0x80000000
         0x55555555<<31=0x80000000 0xaaaaaaaa<<31=0x00000000
         0x12345678<<31=0x00000000 0x00000000<<31=0x00000000
         => 0x00000000_00000000_00000000_80000000_80000000_80000000_80000000_00000000

  ── bn.shv.16H right shifts ──

  16-bit elements (from MSB): 0x0000,0x8000, 0x7fff,0xffff, 0x0000,0x0001, 0xffff,0xffff,
                              0x5555,0x5555, 0xaaaa,0xaaaa, 0x5678,0x1234, 0x0000,0x0000

  >> 1:  0x0000,0x4000, 0x3fff,0x7fff, 0x0000,0x0000, 0x7fff,0x7fff,
         0x2aaa,0x2aaa, 0x5555,0x5555, 0x2b3c,0x091a, 0x0000,0x0000
         => 0x00000000_091a2b3c_55555555_2aaa2aaa_7fff7fff_00000000_7fff3fff_40000000

  >> 8:  0x0000,0x0080, 0x007f,0x00ff, 0x0000,0x0000, 0x00ff,0x00ff,
         0x0055,0x0055, 0x00aa,0x00aa, 0x0056,0x0012, 0x0000,0x0000
         => 0x00000000_00120056_00aa00aa_00550055_00ff00ff_00000000_00ff007f_00800000

  >> 15: 0x0000,0x0001, 0x0000,0x0001, 0x0000,0x0000, 0x0001,0x0001,
         0x0000,0x0000, 0x0001,0x0001, 0x0000,0x0000, 0x0000,0x0000
         => 0x00000000_00000000_00010001_00000000_00010001_00000000_00000001_00000000

  ── bn.shv.16H left shifts ──

  << 1:  0x0000,0x0000, 0xfffe,0xfffe, 0x0000,0x0002, 0xfffe,0xfffe,
         0xaaaa,0xaaaa, 0x5554,0x5554, 0xacf0,0x2468, 0x0000,0x0000
         => 0x00000000_2468acf0_55545554_aaaaaaaa_fffefffe_00020000_fffefffe_00000000

  << 8:  0x0000,0x0000, 0xff00,0xff00, 0x0000,0x0100, 0xff00,0xff00,
         0x5500,0x5500, 0xaa00,0xaa00, 0x7800,0x3400, 0x0000,0x0000
         => 0x00000000_34007800_aa00aa00_55005500_ff00ff00_01000000_ff00ff00_00000000

  << 10: 0x0000,0x0000, 0xfc00,0xfc00, 0x0000,0x0400, 0xfc00,0xfc00,
         0x5400,0x5400, 0xa800,0xa800, 0xe000,0xd000, 0x0000,0x0000
         => 0x00000000_d000e000_a800a800_54005400_fc00fc00_04000000_fc00fc00_00000000

  << 15: 0x0000,0x0000, 0x8000,0x8000, 0x0000,0x8000, 0x8000,0x8000,
         0x8000,0x8000, 0x0000,0x0000, 0x0000,0x0000, 0x0000,0x0000
         => 0x00000000_00000000_00000000_80008000_80008000_80000000_80008000_00000000
*/

.balign 32
.globl result
result:
  .zero 480   /* 15 WDRs x 32 bytes */
