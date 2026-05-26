/* Smoke test for bn.trn1/trn2 all element widths — recognizable patterns */
.section .text.start
.globl main
main:
  addi   x2, x0, 2
  la     x3, vec_a
  bn.lid x2++, 0(x3)
  la     x3, vec_b
  bn.lid x2++, 0(x3)

  /* bn.trn1.16H — 16-bit even interleave */
  bn.trn1.16H  w10, w2, w3

  /* bn.trn2.16H — 16-bit odd interleave */
  bn.trn2.16H  w11, w2, w3

  /* bn.trn1.8S — 32-bit even interleave */
  bn.trn1.8S   w12, w2, w3

  /* bn.trn2.8S — 32-bit odd interleave */
  bn.trn2.8S   w13, w2, w3

  /* bn.trn1.4D — 64-bit even interleave */
  bn.trn1.4D   w14, w2, w3

  /* bn.trn2.4D — 64-bit odd interleave */
  bn.trn2.4D   w15, w2, w3

  /* bn.trn1.2Q — 128-bit even interleave */
  bn.trn1.2Q   w16, w2, w3

  /* bn.trn2.2Q — 128-bit odd interleave */
  bn.trn2.2Q   w17, w2, w3

  /* Store results */
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

  /* Clear working registers */
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
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

  xor  x4,  x4,  x4
  xor  x5,  x5,  x5
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
  vec_a — recognizable 16-bit ascending pattern
  elem[0..15] = {0x0000, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777,
                 0x8888, 0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff}
*/
vec_a:
  .word 0x33332222
  .word 0x11110000
  .word 0x77776666
  .word 0x55554444
  .word 0xbbbbaaaa
  .word 0x99998888
  .word 0xffffeeee
  .word 0xddddcccc

/*
  vec_b — recognizable 16-bit ascending pattern with 0x1000 offset
  [0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
   0x1008, 0x1009, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f]
*/
vec_b:
  .word 0x10031002
  .word 0x10011000
  .word 0x10071006
  .word 0x10051004
  .word 0x100b100a
  .word 0x10091008
  .word 0x100f100e
  .word 0x100d100c

/*
  Expected trn1.16H (even elements interleaved: {b[2i], a[2i]} per 32-bit):
  chunk[0] = {b[0], a[0]} = {0x1000, 0x0000} = 0x10000000
  chunk[1] = {b[2], a[2]} = {0x1002, 0x2222} = 0x10022222
  chunk[2] = {b[4], a[4]} = {0x1004, 0x4444} = 0x10044444
  chunk[3] = {b[6], a[6]} = {0x1006, 0x6666} = 0x10066666
  chunk[4] = {b[8], a[8]} = {0x1008, 0x8888} = 0x10088888
  chunk[5] = {b[10],a[10]}= {0x100a, 0xaaaa} = 0x100aaaaa
  chunk[6] = {b[12],a[12]}= {0x100c, 0xcccc} = 0x100ccccc
  chunk[7] = {b[14],a[14]}= {0x100e, 0xeeee} = 0x100eeeee
  res = 0x100eeeee_100ccccc_100aaaaa_10088888_10066666_10044444_10022222_10000000
*/

/*
  Expected trn2.16H (odd elements: {b[2i+1], a[2i+1]}):
  chunk[0] = {b[1], a[1]} = {0x1001, 0x1111} = 0x10011111
  chunk[1] = {b[3], a[3]} = {0x1003, 0x3333} = 0x10033333
  chunk[2] = {b[5], a[5]} = {0x1005, 0x5555} = 0x10055555
  chunk[3] = {b[7], a[7]} = {0x1007, 0x7777} = 0x10077777
  chunk[4] = {b[9], a[9]} = {0x1009, 0x9999} = 0x10099999
  chunk[5] = {b[11],a[11]}= {0x100b, 0xbbbb} = 0x100bbbbb
  chunk[6] = {b[13],a[13]}= {0x100d, 0xdddd} = 0x100ddddd
  chunk[7] = {b[15],a[15]}= {0x100f, 0xffff} = 0x100fffff
  res = 0x100fffff_100ddddd_100bbbbb_10099999_10077777_10055555_10033333_10011111
*/

/*
  Expected trn1.8S (32-bit even interleave):
  32-bit elements of vec_a: [0x11110000, 0x55554444, 0x99998888, 0xddddcccc,
                             0x33332222, 0x77776666, 0xbbbbaaaa, 0xffffeeee]
  32-bit elements of vec_b: [0x10011000, 0x10051004, 0x10091008, 0x100d100c,
                             0x10031002, 0x10071006, 0x100b100a, 0x100f100e]
  trn1.8S: {b[0],a[0], b[2],a[2], b[4],a[4], b[6],a[6]} = 8 even elements
  = {0x10011000, 0x11110000, 0x10051004, 0x55554444,
     0x10091008, 0x99998888, 0x100d100c, 0xddddcccc}
  res = 0xddddcccc_100d100c_99998888_10091008_55554444_10051004_11110000_10011000
*/
/*
  Expected trn2.8S (32-bit odd interleave):
  trn2.8S: {b[1],a[1], b[3],a[3], b[5],a[5], b[7],a[7]}
  = {0x10031002, 0x33332222, 0x10071006, 0x77776666,
     0x100b100a, 0xbbbbaaaa, 0x100f100e, 0xffffeeee}
  res = 0xffffeeee_100f100e_bbbbaaaa_100b100a_77776666_10071006_33332222_10031002
*/

/*
  Expected trn1.4D (64-bit even interleave):
  64-bit elements of vec_a: [0x3333222211110000, 0x7777666655554444,
                             0xbbbbaaaa99998888, 0xffffeeeeddddcccc]
  64-bit elements of vec_b: [0x1003100210011000, 0x1007100610051004,
                             0x100b100a10091008, 0x100f100e100d100c]
  trn1.4D: {b[0],a[0], b[2],a[2]}
  res = 0x100b100a10091008_bbbbaaaa99998888_1003100210011000_3333222211110000
*/
/*
  Expected trn2.4D (64-bit odd interleave):
  trn2.4D: {b[1],a[1], b[3],a[3]}
  res = 0x100f100e100d100c_ffffeeeeddddcccc_1007100610051004_7777666655554444
*/

/*
  Expected trn1.2Q (128-bit even interleave):
  128-bit elements of vec_a: [0x7777666655554444_3333222211110000,
                              0xffffeeeeddddcccc_bbbbaaaa99998888]
  128-bit elements of vec_b: [0x1007100610051004_1003100210011000,
                              0x100f100e100d100c_100b100a10091008]
  trn1.2Q: {b[0], a[0]}
  res = 0x1007100610051004_1003100210011000_7777666655554444_3333222211110000
*/
/*
  Expected trn2.2Q (128-bit odd interleave):
  trn2.2Q: {b[1], a[1]}
  res = 0x100f100e100d100c_100b100a10091008_ffffeeeeddddcccc_bbbbaaaa99998888
*/

.balign 32
.globl result
result:
  .zero 256
