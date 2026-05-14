/* test_mulvm.s — Paper 2 (ver1) syntax test.
 * Tests 3-instruction Montgomery: mulv.16H.acc.z.lo + mulv.l.16H.lo + mulv.l.16H.acc.hi + addv.m.16H
 * MOD = mu|q, mu = (-q)^-1 mod 2^16 = 0x0CFF, q = 3329 = 0x0D01
 * dexp: 32-bit big-endian words, bytes little-endian within word
 */
.section .text.start
.globl main
main:
    bn.xor w31, w31, w31
    bn.xor w18, w18, w18

    /* MOD <= {mu, q}: mu@[31:16]=0x0CFF, q@[15:0]=0x0D01 */
    la      x5, modulus
    li      x6, 2
    bn.lid  x6, 0(x5)
    la      x5, modulus_inv
    li      x6, 3
    bn.lid  x6, 0(x5)
    bn.or   w2, w2, w3 << 32
    bn.wsrw 0x0, w2
    bn.wsrr w16, 0x0

    /* Test 1: a=100, b=200, expected = 100*200*2^(-16) mod 3329 */
    bn.addi w0, w31, 100
    bn.addi w1, w31, 200
    /* 3-instruction Montgomery */
    bn.mulv.16H.acc.z.lo w2, w0, w1
    bn.mulv.l.16H.lo     w2, w2, sw0.2
    bn.mulv.l.16H.acc.hi w2, w2, sw0.0
    bn.addvm.16H         w2, w2, w18

    la      x10, test1_out
    li      x3, 2
    bn.sid  x3, 0(x10)

    /* Test 2: a=500, b=500 */
    bn.addi w0, w31, 500
    bn.addi w1, w31, 500
    bn.mulv.16H.acc.z.lo w2, w0, w1
    bn.mulv.l.16H.lo     w2, w2, sw0.2
    bn.mulv.l.16H.acc.hi w2, w2, sw0.0
    bn.addvm.16H         w2, w2, w18

    la      x10, test2_out
    li      x3, 2
    bn.sid  x3, 0(x10)

    /* Test 3: bn.subvm.16H — a=500, b=100 → 400 */
    bn.addi w0, w31, 500
    bn.addi w1, w31, 100
    bn.subvm.16H w2, w0, w1

    la      x10, test3_out
    li      x3, 2
    bn.sid  x3, 0(x10)

    /* Test 4: bn.subvm.16H — a=100, b=500 → 100-500+3329=2929 */
    bn.addi w0, w31, 100
    bn.addi w1, w31, 500
    bn.subvm.16H w2, w0, w1

    la      x10, test4_out
    li      x3, 2
    bn.sid  x3, 0(x10)

    /* Test 5: INTT(ramp 0..255) → verify INTT correctness */
    la      x10, test_input_intt
    la      x11, twiddles_intt
    la      x12, test5_out
    jal     x1, intt

    ecall

.data
.balign 32
modulus:
    .word 0x00000d01
    .zero 28
modulus_inv:
    .word 0x00000cff
    .zero 28

.balign 32
.weak test1_out
test1_out:
    .zero 32
.balign 32
.weak test2_out
test2_out:
    .zero 32
.balign 32
.weak test3_out
test3_out:
    .zero 32
.balign 32
.weak test4_out
test4_out:
    .zero 32

/* ===== INTT test data ===== */
.balign 32
test_input_intt:
    .word 0x00010000, 0x00030002, 0x00050004, 0x00070006
    .word 0x00090008, 0x000b000a, 0x000d000c, 0x000f000e
    .word 0x00110010, 0x00130012, 0x00150014, 0x00170016
    .word 0x00190018, 0x001b001a, 0x001d001c, 0x001f001e
    .word 0x00210020, 0x00230022, 0x00250024, 0x00270026
    .word 0x00290028, 0x002b002a, 0x002d002c, 0x002f002e
    .word 0x00310030, 0x00330032, 0x00350034, 0x00370036
    .word 0x00390038, 0x003b003a, 0x003d003c, 0x003f003e
    .word 0x00410040, 0x00430042, 0x00450044, 0x00470046
    .word 0x00490048, 0x004b004a, 0x004d004c, 0x004f004e
    .word 0x00510050, 0x00530052, 0x00550054, 0x00570056
    .word 0x00590058, 0x005b005a, 0x005d005c, 0x005f005e
    .word 0x00610060, 0x00630062, 0x00650064, 0x00670066
    .word 0x00690068, 0x006b006a, 0x006d006c, 0x006f006e
    .word 0x00710070, 0x00730072, 0x00750074, 0x00770076
    .word 0x00790078, 0x007b007a, 0x007d007c, 0x007f007e
    .word 0x00810080, 0x00830082, 0x00850084, 0x00870086
    .word 0x00890088, 0x008b008a, 0x008d008c, 0x008f008e
    .word 0x00910090, 0x00930092, 0x00950094, 0x00970096
    .word 0x00990098, 0x009b009a, 0x009d009c, 0x009f009e
    .word 0x00a100a0, 0x00a300a2, 0x00a500a4, 0x00a700a6
    .word 0x00a900a8, 0x00ab00aa, 0x00ad00ac, 0x00af00ae
    .word 0x00b100b0, 0x00b300b2, 0x00b500b4, 0x00b700b6
    .word 0x00b900b8, 0x00bb00ba, 0x00bd00bc, 0x00bf00be
    .word 0x00c100c0, 0x00c300c2, 0x00c500c4, 0x00c700c6
    .word 0x00c900c8, 0x00cb00ca, 0x00cd00cc, 0x00cf00ce
    .word 0x00d100d0, 0x00d300d2, 0x00d500d4, 0x00d700d6
    .word 0x00d900d8, 0x00db00da, 0x00dd00dc, 0x00df00de
    .word 0x00e100e0, 0x00e300e2, 0x00e500e4, 0x00e700e6
    .word 0x00e900e8, 0x00eb00ea, 0x00ed00ec, 0x00ef00ee
    .word 0x00f100f0, 0x00f300f2, 0x00f500f4, 0x00f700f6
    .word 0x00f900f8, 0x00fb00fa, 0x00fd00fc, 0x00ff00fe

.balign 32
.weak test5_out
test5_out:
    .zero 512

.globl twiddles_intt
twiddles_intt:
  /* Layer 7 */
  .word 0x06a506a5
  .word 0x09220922
  .word 0x0b230b23
  .word 0x09e709e7
  .word 0x067b067b
  .word 0x05370537
  .word 0x0b810b81
  .word 0x0a9f0a9f
  .word 0x070f070f
  .word 0x091d091d
  .word 0x03660366
  .word 0x04fe04fe
  .word 0x04a304a3
  .word 0x083f083f
  .word 0x05b905b9
  .word 0x0aa60aa6
  .word 0x05b405b4
  .word 0x01340134
  .word 0x03560356
  .word 0x05fa05fa
  .word 0x0c250c25
  .word 0x00880088
  .word 0x05050505
  .word 0x08b808b8
  .word 0x09430943
  .word 0x006c006c
  .word 0x05e605e6
  .word 0x04a104a1
  .word 0x036a036a
  .word 0x04bf04bf
  .word 0x07d707d7
  .word 0x09d009d0
  .word 0x004b004b
  .word 0x0ba40ba4
  .word 0x08a208a2
  .word 0x00930093
  .word 0x068c068c
  .word 0x00eb00eb
  .word 0x0c980c98
  .word 0x09b609b6
  .word 0x009c009c
  .word 0x03680368
  .word 0x025a025a
  .word 0x087a087a
  .word 0x06db06db
  .word 0x0c500c50
  .word 0x06f306f3
  .word 0x0ad60ad6
  .word 0x0bb80bb8
  .word 0x0a7d0a7d
  .word 0x07360736
  .word 0x09f709f7
  .word 0x01cc01cc
  .word 0x0ab60ab6
  .word 0x099a099a
  .word 0x0b530b53
  .word 0x0b5f0b5f
  .word 0x06360636
  .word 0x03090309
  .word 0x00f600f6
  .word 0x01230123
  .word 0x0b5b0b5b
  .word 0x04e304e3
  .word 0x044f044f
  /* Layer 6 */
  .word 0x04fb04fb
  .word 0x04290429
  .word 0x02d502d5
  .word 0x09400940
  .word 0x03b703b7
  .word 0x058d058d
  .word 0x09c309c3
  .word 0x005a005a
  .word 0x0a5c0a5c
  .word 0x0b410b41
  .word 0x05e405e4
  .word 0x018e018e
  .word 0x00f700f7
  .word 0x0c960c96
  .word 0x010f010f
  .word 0x03550355
  .word 0x07440744
  .word 0x048a048a
  .word 0x029a029a
  .word 0x00080008
  .word 0x06080608
  .word 0x072e072e
  .word 0x090a090a
  .word 0x0a750a75
  .word 0x0c830c83
  .word 0x06520652
  .word 0x01400140
  .word 0x0afd0afd
  .word 0x011a011a
  .word 0x050d050d
  .word 0x02280228
  .word 0x083a083a
  /* Layer 5 */
  .word 0x06230623
  .word 0x00cd00cd
  .word 0x0b660b66
  .word 0x06060606
  .word 0x0aa10aa1
  .word 0x0a250a25
  .word 0x09080908
  .word 0x02a902a9
  .word 0x00820082
  .word 0x06420642
  .word 0x074f074f
  .word 0x033d033d
  .word 0x0b820b82
  .word 0x0bf90bf9
  .word 0x052d052d
  .word 0x0ac40ac4
  /* Layer 4--2 */
  .half 0x0745
  .half 0x05c2
  .half 0x04b2
  .half 0x093f
  .half 0x0c4b
  .half 0x06d8
  .half 0x0a93
  .half 0x00ab
  .half 0x0c37
  .half 0x0be2
  .half 0x0773
  .half 0x072c
  .half 0x05ed
  .half 0x0167
  /* Layer 1 */
  .half 0x078c /* ((758*2^16) mod KYBER_Q)*(1/128) mod KYBER_Q */
  /* [(2^32 mod KYBER_Q)*(1/128)] mod KYBER_Q */
  .half 0x05a1