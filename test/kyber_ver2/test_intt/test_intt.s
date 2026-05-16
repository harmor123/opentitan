/*
 * Minimal INTT test: verify INTT(NTT(x)) == x * 256 mod q
 * Input: all-ones polynomial (256 coeffs of value 1)
 * Expected output: all-256s (256 coeffs of value 256 = 0x0100)
 */

.text
.globl main
main:
  /* Zero all registers */
  bn.xor w0, w0, w0
  bn.xor w1, w1, w1
  bn.xor w2, w2, w2
  bn.xor w3, w3, w3
  bn.xor w4, w4, w4
  bn.xor w5, w5, w5
  bn.xor w6, w6, w6
  bn.xor w7, w7, w7
  bn.xor w8, w8, w8
  bn.xor w9, w9, w9
  bn.xor w10, w10, w10
  bn.xor w11, w11, w11
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

  /* Set up MOD = {mu, q} and w16 = {mu, q} */
  li      x5, 2
  la      x6, modulus
  bn.lid  x5++, 0(x6)       /* w2 = modulus (q=0x0D01 in lane0) */
  la      x6, modulus_inv
  bn.lid  x5, 0(x6)         /* w3 = modulus_inv (mu=0x0CFF in lane0) */
  bn.or   w2, w2, w3 << 32  /* w2: lane0=q=0x0D01, lane1=mu=0x0CFF */
  bn.wsrw 0x0, w2           /* MOD = {mu, q} */

  /* Save w16 = sw0 = {mu, q} for Montgomery multiplication */
  bn.wsrr w16, 0x0          /* w16 = {mu, q} */

  /* Set MOD = 2q for NTT/INTT lazy reduction (preserve mu in w16 for Montgomery) */
  bn.shv.8S w0, w16 << 1    /* w0 = 2*{mu, q} */
  bn.wsrw 0x0, w0           /* MOD = {2*mu, 2q} */

  /* Setup GPRs for WDR indexing */
  li x3, 4
  li x9, 5
  li x13, 6
  li x14, 7
  li x15, 8
  li x16, 9
  li x17, 10
  li x18, 11
  li x19, 12
  li x20, 13
  li x21, 14
  li x22, 15

  /* Step 1: Copy input to test_buffer */
  la   x10, test_input
  li   x4, 0
  bn.lid x4,  0(x10++)
  li   x5, 1
  bn.lid x5,  0(x10++)
  li   x6, 2
  bn.lid x6,  0(x10++)
  li   x7, 3
  bn.lid x7,  0(x10++)
  bn.lid x3,  0(x10++)
  bn.lid x9,  0(x10++)
  bn.lid x13, 0(x10++)
  bn.lid x14, 0(x10++)
  bn.lid x15, 0(x10++)
  bn.lid x16, 0(x10++)
  bn.lid x17, 0(x10++)
  bn.lid x18, 0(x10++)
  bn.lid x19, 0(x10++)
  bn.lid x20, 0(x10++)
  bn.lid x21, 0(x10++)
  bn.lid x22, 0(x10++)

  /* Store to test_buffer */
  la   x12, test_buffer
  li   x4, 0
  bn.sid x4,  0(x12++)
  li   x5, 1
  bn.sid x5,  0(x12++)
  li   x6, 2
  bn.sid x6,  0(x12++)
  li   x7, 3
  bn.sid x7,  0(x12++)
  bn.sid x3,  0(x12++)
  bn.sid x9,  0(x12++)
  bn.sid x13, 0(x12++)
  bn.sid x14, 0(x12++)
  bn.sid x15, 0(x12++)
  bn.sid x16, 0(x12++)
  bn.sid x17, 0(x12++)
  bn.sid x18, 0(x12++)
  bn.sid x19, 0(x12++)
  bn.sid x20, 0(x12++)
  bn.sid x21, 0(x12++)
  bn.sid x22, 0(x12++)

  /* Step 2: NTT */
  la   x10, test_buffer
  la   x11, twiddles_ntt
  add  x12, x0, x10        /* output = input (in-place) */
  jal  x1, ntt

  /* Step 3: INTT */
  la   x10, test_buffer
  la   x11, twiddles_intt
  add  x12, x0, x10        /* output = input (in-place) */
  jal  x1, intt

  /* Step 4: Load result from test_buffer and store to test_output */
  la   x10, test_buffer
  li   x4, 0
  bn.lid x4,  0(x10++)
  li   x5, 1
  bn.lid x5,  0(x10++)
  li   x6, 2
  bn.lid x6,  0(x10++)
  li   x7, 3
  bn.lid x7,  0(x10++)
  li   x3, 4
  bn.lid x3,  0(x10++)
  li   x9, 5
  bn.lid x9,  0(x10++)
  li   x13, 6
  bn.lid x13, 0(x10++)
  li   x14, 7
  bn.lid x14, 0(x10++)
  li   x15, 8
  bn.lid x15, 0(x10++)
  li   x16, 9
  bn.lid x16, 0(x10++)
  li   x17, 10
  bn.lid x17, 0(x10++)
  li   x18, 11
  bn.lid x18, 0(x10++)
  li   x19, 12
  bn.lid x19, 0(x10++)
  li   x20, 13
  bn.lid x20, 0(x10++)
  li   x21, 14
  bn.lid x21, 0(x10++)
  li   x22, 15
  bn.lid x22, 0(x10++)

  /* Store to test_output */
  la   x12, test_output
  li   x4, 0
  bn.sid x4,  0(x12++)
  li   x5, 1
  bn.sid x5,  0(x12++)
  li   x6, 2
  bn.sid x6,  0(x12++)
  li   x7, 3
  bn.sid x7,  0(x12++)
  bn.sid x3,  0(x12++)
  bn.sid x9,  0(x12++)
  bn.sid x13, 0(x12++)
  bn.sid x14, 0(x12++)
  bn.sid x15, 0(x12++)
  bn.sid x16, 0(x12++)
  bn.sid x17, 0(x12++)
  bn.sid x18, 0(x12++)
  bn.sid x19, 0(x12++)
  bn.sid x20, 0(x12++)
  bn.sid x21, 0(x12++)
  bn.sid x22, 0(x12++)

  ecall


.data
.balign 32

/* Test input: all-ones in Montgomery domain = 256 coeffs of R mod q = 0x08ED */
.globl test_input
/* Test input: all-ones in Montgomery domain = 256 coeffs of R mod q = 0x08ED */
.globl test_input
test_input:
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED
  .word 0x08ED08ED

.globl test_buffer
test_buffer:
  .zero 2048

.balign 32
.globl test_output
test_output:
  .zero 2048

/* Modulus constants */
.globl modulus
modulus:
  .word 0x00000d01
  .space 28

.globl modulus_inv
modulus_inv:
  .word 0x00000cff
  .space 28

/* NTT Twiddle Factors (copied from mlkem_base_encap_test.s) */
.globl twiddles_ntt
twiddles_ntt:
  .half 0x0a0b
  .half 0x0b9a
  .half 0x0714
  .half 0x05d5
  .half 0x058e
  .half 0x011f
  .half 0x00ca
  .half 0x0c56
  .half 0x026e
  .half 0x0629
  .half 0x00b6
  .half 0x03c2
  .half 0x084f
  .half 0x073f
  .half 0x05bc
  .half 0x0000
  .word 0x023d023d
  .word 0x07d407d4
  .word 0x01080108
  .word 0x017f017f
  .word 0x09c409c4
  .word 0x05b205b2
  .word 0x06bf06bf
  .word 0x0c7f0c7f
  .word 0x0a580a58
  .word 0x03f903f9
  .word 0x02dc02dc
  .word 0x02600260
  .word 0x06fb06fb
  .word 0x019b019b
  .word 0x0c340c34
  .word 0x06de06de
  .word 0x04c704c7
  .word 0x0ad90ad9
  .word 0x07f407f4
  .word 0x0be70be7
  .word 0x02040204
  .word 0x0bc10bc1
  .word 0x06af06af
  .word 0x007e007e
  .word 0x028c028c
  .word 0x03f703f7
  .word 0x05d305d3
  .word 0x06f906f9
  .word 0x0cf90cf9
  .word 0x0a670a67
  .word 0x08770877
  .word 0x05bd05bd
  .word 0x09ac09ac
  .word 0x0bf20bf2
  .word 0x006b006b
  .word 0x0c0a0c0a
  .word 0x0b730b73
  .word 0x071d071d
  .word 0x01c001c0
  .word 0x02a502a5
  .word 0x0ca70ca7
  .word 0x033e033e
  .word 0x07740774
  .word 0x094a094a
  .word 0x03c103c1
  .word 0x0a2c0a2c
  .word 0x08d808d8
  .word 0x08060806
  .word 0x08b208b2
  .word 0x081e081e
  .word 0x01a601a6
  .word 0x0bde0bde
  .word 0x0c0b0c0b
  .word 0x09f809f8
  .word 0x06cb06cb
  .word 0x01a201a2
  .word 0x01ae01ae
  .word 0x03670367
  .word 0x024b024b
  .word 0x0b350b35
  .word 0x030a030a
  .word 0x05cb05cb
  .word 0x02840284
  .word 0x01490149
  .word 0x022b022b
  .word 0x060e060e
  .word 0x00b100b1
  .word 0x06260626
  .word 0x04870487
  .word 0x0aa70aa7
  .word 0x09990999
  .word 0x0c650c65
  .word 0x034b034b
  .word 0x00690069
  .word 0x0c160c16
  .word 0x06750675
  .word 0x0c6e0c6e
  .word 0x045f045f
  .word 0x015d015d
  .word 0x0cb60cb6
  .word 0x03310331
  .word 0x052a052a
  .word 0x08420842
  .word 0x09970997
  .word 0x08600860
  .word 0x071b071b
  .word 0x0c950c95
  .word 0x03be03be
  .word 0x04490449
  .word 0x07fc07fc
  .word 0x0c790c79
  .word 0x00dc00dc
  .word 0x07070707
  .word 0x09ab09ab
  .word 0x0bcd0bcd
  .word 0x074d074d
  .word 0x025b025b
  .word 0x07480748
  .word 0x04c204c2
  .word 0x085e085e
  .word 0x08030803
  .word 0x099b099b
  .word 0x03e403e4
  .word 0x05f205f2
  .word 0x02620262
  .word 0x01800180
  .word 0x07ca07ca
  .word 0x06860686
  .word 0x031a031a
  .word 0x01de01de
  .word 0x03df03df
  .word 0x065c065c

.globl twiddles_intt
twiddles_intt:
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
  .half 0x078c
  .half 0x05a1
