/* Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */
/* Modified by Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of */
/* "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN" */
/* (https://eprint.iacr.org/2025/2028) */
/* Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham. */


/*
 * Testwrapper for mlkem_decap
*/

.section .text.start


/* Entry point. */
.globl main
main:
  /* Init all-zero register. */

  bn.xor  w0, w0, w0
  bn.xor  w1, w1, w1
  bn.xor  w2, w2, w2
  bn.xor  w3, w3, w3
  bn.xor  w4, w4, w4
  bn.xor  w5, w5, w5
  bn.xor  w6, w6, w6
  bn.xor  w7, w7, w7
  bn.xor  w8, w8, w8
  bn.xor  w9, w9, w9
  bn.xor  w10, w10, w10
  bn.xor  w11, w11, w11
  bn.xor  w12, w12, w12
  bn.xor  w13, w13, w13
  bn.xor  w14, w14, w14
  bn.xor  w15, w15, w15
  bn.xor  w16, w16, w16
  bn.xor  w17, w17, w17
  bn.xor  w18, w18, w18
  bn.xor  w19, w19, w19
  bn.xor  w20, w20, w20
  bn.xor  w21, w21, w21
  bn.xor  w22, w22, w22
  bn.xor  w23, w23, w23
  bn.xor  w24, w24, w24
  bn.xor  w25, w25, w25
  bn.xor  w26, w26, w26
  bn.xor  w27, w27, w27
  bn.xor  w28, w28, w28
  bn.xor  w29, w29, w29
  bn.xor  w30, w30, w30

  bn.xor  w31, w31, w31

  /* MOD <= dmem[modulus] = KYBER_Q */
  li      x5, 2
  la      x6, modulus
  bn.lid  x5, 0(x6)
  bn.wsrw 0x0, w2

  /* Load stack pointer */
  la   x2, stack_end
  la   x10, ct
  la   x11, dk 
  la   x12, ss
  jal  x1, crypto_kem_dec

  ecall

.data
.balign 32
.global stack
stack:
  .zero 20000
stack_end:
.globl ss
ss:
  .zero 32

.balign 32

.globl ct
ct:
  .word 0x4ae03b1d
  .word 0x98b4146a
  .word 0x61de65e3
  .word 0x3ab200a7
  .word 0xc3db0120
  .word 0xcf87d3dc
  .word 0x5f69f1a1
  .word 0x47ad1a11
  .word 0x3e22344b
  .word 0xe5290a10
  .word 0xa5163d3c
  .word 0xa6e169d7
  .word 0x02be504f
  .word 0x5484099a
  .word 0xa2496723
  .word 0x32c003c7
  .word 0x2d9d19fb
  .word 0x905002ee
  .word 0x9a60bcbb
  .word 0x134c2814
  .word 0xfef8f25f
  .word 0x363a99a9
  .word 0xb0378268
  .word 0x777e5438
  .word 0xc0cad5a7
  .word 0xde441143
  .word 0x0179f734
  .word 0xf02725fe
  .word 0xc1cad498
  .word 0x994b6759
  .word 0x21a7e604
  .word 0xd186c890
  .word 0x535a0c41
  .word 0xc1b78b07
  .word 0x219c748d
  .word 0xab2de43d
  .word 0x8c3bc8e6
  .word 0xacc8fe1f
  .word 0x47d032b9
  .word 0x6ee1a552
  .word 0x1b71580e
  .word 0x01e7c7f3
  .word 0x57499f19
  .word 0x4074e045
  .word 0x88dda893
  .word 0xa56ba06c
  .word 0x36094ebb
  .word 0x9ee9585f
  .word 0x90b6e608
  .word 0x061b0c2a
  .word 0x42fde842
  .word 0x256a4171
  .word 0x9a212e12
  .word 0xcecda819
  .word 0x62aa666e
  .word 0xf82d30ff
  .word 0x5465b457
  .word 0x2b29cf79
  .word 0x31eaa7e9
  .word 0xb77ca42b
  .word 0x9bad737e
  .word 0xea564b2d
  .word 0x350c24ca
  .word 0xcd961627
  .word 0x750f56ad
  .word 0x1664b0b1
  .word 0xe6f53c0c
  .word 0xab03932f
  .word 0x76449295
  .word 0xc77cd680
  .word 0xef921557
  .word 0x05e3b4df
  .word 0x4f5e4dc4
  .word 0x7c5e65e4
  .word 0xcf78edf9
  .word 0x82eab670
  .word 0x9124693d
  .word 0x190d6266
  .word 0x4633e0f5
  .word 0x9a9b6bf0
  .word 0x845926ef
  .word 0x2bf061dd
  .word 0x69b0c694
  .word 0x66444add
  .word 0x0255fd2f
  .word 0x485a6812
  .word 0x01d79e3e
  .word 0x7367c33e
  .word 0x45dcc6aa
  .word 0x5ba81dce
  .word 0x135c0414
  .word 0x943259d2
  .word 0xbffdc10e
  .word 0x667faaac
  .word 0xef1adc03
  .word 0xae2ff5f9
  .word 0xac2f87db
  .word 0xcbf57314
  .word 0xff0cb28f
  .word 0x59852471
  .word 0x3a903879
  .word 0x95481e7d
  .word 0x94626222
  .word 0x713b77d4
  .word 0x7901dccb
  .word 0x750813c8
  .word 0x113f3f5f
  .word 0xc278c15b
  .word 0x1cfbdc95
  .word 0x7db5bfcf
  .word 0x97b6333d
  .word 0xa62da841
  .word 0x15738f13
  .word 0x61bd1992
  .word 0x6a222050
  .word 0xac8fb524
  .word 0x466e2681
  .word 0xca6c6a8e
  .word 0x8da5e26b
  .word 0xf7a346ec
  .word 0x0cc4c742
  .word 0x6fe62b8d
  .word 0x4c322cb0
  .word 0x9a5d583b
  .word 0x4d60a4d0
  .word 0xe9c9b66c
  .word 0xcb0679f6
  .word 0x1a6d6029
  .word 0x34be4177
  .word 0xdcff24eb
  .word 0xc74b631f
  .word 0xcacf764f
  .word 0xdf7ed50d
  .word 0xe7c86262
  .word 0xccd01cf6
  .word 0xbd9173cf
  .word 0xef9bd62b
  .word 0xf3fa35df
  .word 0x9ba33369
  .word 0x94f6f41d
  .word 0xd2bb4d98
  .word 0x8ec377d4
  .word 0x55c029d3
  .word 0xa5c80b8d
  .word 0xb4756f71
  .word 0xdc17ff3b
  .word 0x9f99a580
  .word 0x522f7a39
  .word 0x7a4fddd3
  .word 0x43396b9c
  .word 0x73350c5b
  .word 0x51f565eb
  .word 0x49bfdd4a
  .word 0x70f26589
  .word 0xaf9bc1a6
  .word 0x486e46ce
  .word 0x0af13536
  .word 0x06226890
  .word 0x240d5ca0
  .word 0x79394b99
  .word 0x8fccfe34
  .word 0x26634408
  .word 0xba3e9da4
  .word 0xcd2272ec
  .word 0x99b276cf
  .word 0x82520780
  .word 0x04feb497
  .word 0xfe8b1da2
  .word 0xe4ec2776
  .word 0xde89d4be
  .word 0x89577002
  .word 0x00e6c5da
  .word 0x796f4826
  .word 0x14932fde
  .word 0x9e09d876
  .word 0xd82d7de2
  .word 0xe2b98675
  .word 0x24a20deb
  .word 0xc148e919
  .word 0xde8e9987
  .word 0x6ab0ac7f
  .word 0xfcdc2bc9
  .word 0xb28213e4
  .word 0x62cbf19a
  .word 0xd4161ab4
  .word 0x95e5d9d8
  .word 0x3b03fe80
  .word 0x5ed4ee0b
  .word 0x74eeb023
  .word 0x00a90cc4
  .word 0x093a794d
  .word 0x52dac968
  .word 0x3079adbe
  .word 0xb4844f9c
  .word 0x141552e8
  .word 0x3016a0ca
  .word 0x6f72748d
  .word 0x91bc9f89
  .word 0x7d52e300
  .word 0xd0ca2ed9
  .word 0xf8be35ce
  .word 0x1c919a69
  .word 0x61f1ec36
  .word 0xa5a7ffe7
  .word 0xf9a1033e
  .word 0xa3e328e0
  .word 0xe8985b15
  .word 0x84ee8619
  .word 0x3a942f90
  .word 0x207ba480
  .word 0xb291ffaa
  .word 0xead13d19
  .word 0x8ec3f297
  .word 0x3bf05689
  .word 0xb9d406e2
  .word 0xbf67c706
  .word 0x96c2fd11
  .word 0x6003c2fa
  .word 0xe1181b5c
  .word 0x51a2018c
  .word 0x107842c7
  .word 0x8bd54512
  .word 0x049831fb
  .word 0x97e27d06
  .word 0x37d4d165
  .word 0x41a36b74
  .word 0xd7da6d2c
  .word 0xf3c201cb
  .word 0x51265ead
  .word 0x69b2253b
  .word 0x3feba9fc
  .word 0xa948ce84
  .word 0xe38601e9
  .word 0x8b5051a8
  .word 0x2d29a2ee
  .word 0x6bb93b8d
  .word 0x35f7a15b
  .word 0x9a15d4f0
  .word 0x202c9527
  .word 0x1d674566
  .word 0xa7d3f245
  .word 0x72e75e95
  .word 0xb2d47f9b
  .word 0x1f88ba0d
  .word 0xa7bf39ac
  .word 0x60f7fa5b
  .word 0x2de3c839
  .word 0x674e3836
  .word 0x6fabbe18
  .word 0xf338f8ce
  .word 0xe0343a91
  .word 0x194cfb05
  .word 0xff9c6aa8
  .word 0xc6ff522f
  .word 0x72d74b69
  .word 0x86514014
  .word 0x6e212c7c
  .word 0x9de512e7
  .word 0x37aa028a
  .word 0x134aab3e
  .word 0xe6a38e17
  .word 0x965fff8b
  .word 0x6d6877bf
  .word 0x1427f9a2
  .word 0x7eccf934
  .word 0x06cdfd38
  .word 0x39d65847
  .word 0x8abda1e7
  .word 0xfaf57d89
  .word 0xe41857b7
  .word 0xe98f852f
  .word 0x795652ba

.globl dk
dk:
    .word 0xcd46fae7
  .word 0xdab4c107
  .word 0xa348cb48
  .word 0x9f47e1af
  .word 0xac1b7196
  .word 0xc462d25c
  .word 0xbcc5aa3d
  .word 0x5c2d6668
  .word 0x55830b5d
  .word 0xd1b9da1b
  .word 0xe4d7a448
  .word 0x5616c63d
  .word 0x587fb21f
  .word 0x718c8342
  .word 0x6c452247
  .word 0xb2447c4c
  .word 0x66e0a848
  .word 0x3040ad37
  .word 0xd25b39e5
  .word 0x1a3681a7
  .word 0xc161239e
  .word 0x04393819
  .word 0xdb2e8187
  .word 0x8c04bd21
  .word 0xb283e945
  .word 0x5c989433
  .word 0x7e602b5a
  .word 0x575097fc
  .word 0x749f7e3c
  .word 0x6642ce90
  .word 0x97925979
  .word 0x42e68cc5
  .word 0x33672a0f
  .word 0x9a8101b9
  .word 0x509e59e2
  .word 0x77f0f970
  .word 0x94b9e0b9
  .word 0x2c558073
  .word 0x2b24b6c4
  .word 0x4688f230
  .word 0x38620ed5
  .word 0x740bcbbd
  .word 0xfe5c172f
  .word 0x47c6abbb
  .word 0x9332f0a2
  .word 0x967d8c99
  .word 0x5add1341
  .word 0x407be479
  .word 0x239c6b7c
  .word 0xf3a42d25
  .word 0x02b51e40
  .word 0xfdc13c1f
  .word 0x0187c743
  .word 0x718772b9
  .word 0x85b91200
  .word 0x350fac44
  .word 0x7a8b78c0
  .word 0x5d9414a5
  .word 0x44ce8041
  .word 0x0128129d
  .word 0xf3b77977
  .word 0x97f116b5
  .word 0x29755a58
  .word 0xd3572a90
  .word 0xc100c008
  .word 0x0896e342
  .word 0x8170bad3
  .word 0x1a3a8b21
  .word 0x9ee3e429
  .word 0x270c214f
  .word 0xd0302ca9
  .word 0x281a61bf
  .word 0xc7443a03
  .word 0xb26aa113
  .word 0x7d71590a
  .word 0xae1ae7a1
  .word 0xfc5b6778
  .word 0x6d97a366
  .word 0xab7eacfb
  .word 0x4a6189fc
  .word 0x9ee0e724
  .word 0xef48e4f7
  .word 0x23a828c5
  .word 0xa2cbc230
  .word 0x17c88b12
  .word 0x8897b62a
  .word 0x8f2ceeba
  .word 0x81301a72
  .word 0x5c83b7b3
  .word 0xc8f9fd9d
  .word 0x42a92537
  .word 0x06e4b0fc
  .word 0x254beb45
  .word 0x7c2c628d
  .word 0x270b78d5
  .word 0x69421409
  .word 0xa83f82eb
  .word 0xa24055a8
  .word 0x71a19a74
  .word 0x94118531
  .word 0x07d91dbc
  .word 0xc309f808
  .word 0x6699d80d
  .word 0x20dd2382
  .word 0x4202af06
  .word 0x7d0c5039
  .word 0xb7ef6f85
  .word 0x8a98cd16
  .word 0x2f8aea2d
  .word 0x226a03c1
  .word 0x8001243e
  .word 0x65229199
  .word 0xa5eecc5a
  .word 0xb242c112
  .word 0xd3c1d7f9
  .word 0xe9341a92
  .word 0x82f00449
  .word 0xd99dd897
  .word 0x6bd33ff6
  .word 0x9bf903a8
  .word 0x7119f51a
  .word 0xf3deaff5
  .word 0x8b8a6109
  .word 0xf45fc29c
  .word 0x430a9010
  .word 0xbcb18a71
  .word 0x9aacc24a
  .word 0x157f6157
  .word 0x3ac82a0e
  .word 0x372e0306
  .word 0x5af1923a
  .word 0x70a8aac4
  .word 0xa52ce776
  .word 0x95da1221
  .word 0x28930cc0
  .word 0x8970faea
  .word 0xa34a3201
  .word 0x92c3e94d
  .word 0x2d498378
  .word 0x45971a79
  .word 0x3c189d2d
  .word 0x6c45b437
  .word 0xac132184
  .word 0x7e59fe6c
  .word 0x3482e451
  .word 0xe97e99e0
  .word 0x5f6a45cf
  .word 0xe14026a3
  .word 0x49a61efb
  .word 0x6862ff14
  .word 0x75652be1
  .word 0x2b2eb8d5
  .word 0x1d507a81
  .word 0x914f072b
  .word 0xaca23cfb
  .word 0x3e392a6e
  .word 0x7f52c1a6
  .word 0xa9dd0c95
  .word 0xa7a1e82d
  .word 0xa7361060
  .word 0x4b6db533
  .word 0xc7acfc51
  .word 0xdc25d103
  .word 0xc5681287
  .word 0x97b7b193
  .word 0xe7150047
  .word 0x076d5cba
  .word 0x56930d5a
  .word 0x1a5ab0ac
  .word 0xb75e6280
  .word 0xc46b0ebb
  .word 0x6eb4e0db
  .word 0x5c53812c
  .word 0xa5b29bcd
  .word 0xb19d024f
  .word 0x6cf13c8b
  .word 0xbe0003c3
  .word 0x390e7316
  .word 0xe7cf5749
  .word 0x07fc88a3
  .word 0xac3e58f8
  .word 0x91221fb0
  .word 0x13f9f3c0
  .word 0x3f0e6ab3
  .word 0x786d4385
  .word 0x2349cc43
  .word 0x7016091e
  .word 0x721c793b
  .word 0x5ba5ed0e
  .word 0xccbbaa47
  .word 0x8272764c
  .word 0x3b39ee84
  .word 0x3eab81b7
  .word 0x946059bc
  .word 0x44bcac96
  .word 0xf5619a22
  .word 0xec9d6ca1
  .word 0x815c0f6d
  .word 0xbe0f9cb9
  .word 0xdce647ab
  .word 0x92a7b792
  .word 0xc515a1a7
  .word 0x3b228bf3
  .word 0x43a13e3e
  .word 0xff8309d2
  .word 0x75d38b1b
  .word 0x356a271e
  .word 0xfc36c395
  .word 0x87469d38
  .word 0x2403f8b1
  .word 0x37ca9837
  .word 0x069f8035
  .word 0x6dd8e114
  .word 0xce06ab1d
  .word 0xa7aa95e8
  .word 0x96b5eb46
  .word 0xa56812ce
  .word 0xb2bfcdc3
  .word 0xa7fce957
  .word 0x70381352
  .word 0x7c8e0c33
  .word 0x21e42922
  .word 0x6058e129
  .word 0x17e9c7b5
  .word 0x42304baf
  .word 0x86b6dc9c
  .word 0x066c5457
  .word 0x46a8e573
  .word 0xcc64a7ec
  .word 0xb177b11c
  .word 0x21339d3b
  .word 0xe839203e
  .word 0xd2808bf1
  .word 0x7c73c08e
  .word 0x14105ca0
  .word 0x44d0005b
  .word 0x0ef3496e
  .word 0xef9e23fa
  .word 0x82377f00
  .word 0x04759285
  .word 0xf48925a3
  .word 0xe372773a
  .word 0x9c05526c
  .word 0x0854e9ad
  .word 0x899f17f8
  .word 0xc7f5c24e
  .word 0x1405daef
  .word 0xf6095837
  .word 0xa711932d
  .word 0xecb1bb79
  .word 0x875a3550
  .word 0x8bc7a675
  .word 0x3fc563e5
  .word 0xa49b51fb
  .word 0xc521609f
  .word 0x945fcad7
  .word 0x48007013
  .word 0x7b4a5840
  .word 0xfca37858
  .word 0xd03a4938
  .word 0x58b59972
  .word 0xd3836281
  .word 0x7608037a
  .word 0xa927cfb3
  .word 0x35aec888
  .word 0x6a500ddb
  .word 0x4f31a2a8
  .word 0x045f6b3a
  .word 0x51be5437
  .word 0x02b792b8
  .word 0xee50065a
  .word 0x76ffa540
  .word 0xc909636c
  .word 0x61165c26
  .word 0xb1e55aca
  .word 0x84f3e1aa
  .word 0x9a2529d3
  .word 0xc6ed4cf7
  .word 0x04fc290f
  .word 0xe32428b2
  .word 0x08ed8678
  .word 0xb5d65c49
  .word 0x0ebe4c50
  .word 0x7194cc13
  .word 0x3e0499cf
  .word 0x8307756e
  .word 0xcb471b2c
  .word 0xa86822ac
  .word 0x02322078
  .word 0x448e2330
  .word 0x9ba9cf7a
  .word 0x53b73263
  .word 0x42e57c1c
  .word 0xca931b03
  .word 0x5f8f2514
  .word 0x870cb398
  .word 0xb2016d3f
  .word 0x343f85c5
  .word 0x04186902
  .word 0xa7084780
  .word 0xa55bfaec
  .word 0x88ef0f98
  .word 0xa8f5ce36
  .word 0x7583ac2d
  .word 0xcb3462e0
  .word 0xc54cd6be
  .word 0x06acb2a4
  .word 0xd9b4a084
  .word 0x44663e86
  .word 0x494833a8
  .word 0xfbdbcfc0
  .word 0xb0841b85
  .word 0xb06f8ce4
  .word 0x52d00148
  .word 0x6876d52f
  .word 0x6744169b
  .word 0xdab44a60
  .word 0xcfab342e
  .word 0x4492dc76
  .word 0x574e4c67
  .word 0x7c78f530
  .word 0x42219067
  .word 0x1540134c
  .word 0x3349244d
  .word 0x0e94bc0d
  .word 0x03e17bba
  .word 0x0a94ec99
  .word 0x6040356b
  .word 0x50669914
  .word 0x89a148b1
  .word 0x5e7f4743
  .word 0xa0410f95
  .word 0x8834b61a
  .word 0xf006f2fa
  .word 0x31a725f2
  .word 0x84776709
  .word 0xec6d1b79
  .word 0xeb600e98
  .word 0xbfbb968f
  .word 0xb0222247
  .word 0xf9128a24
  .word 0x7da18861
  .word 0x523eb868
  .word 0xa27b82c9
  .word 0x7582bcc6
  .word 0x46ae310b
  .word 0x287a82b9
  .word 0x38b3fc77
  .word 0xb8683a00
  .word 0x969caac1
  .word 0x03d2556b
  .word 0x57117478
  .word 0xdbf60577
  .word 0xb4f95915
  .word 0x18578a25
  .word 0x835d5020
  .word 0xa29a00c1
  .word 0x75b384b2
  .word 0x6a61aca7
  .word 0xa242291b
  .word 0x3ec494b4
  .word 0xb9c170b3
  .word 0x2b52cd4a
  .word 0xc7178c20
  .word 0x607e0735
  .word 0x0c41412f
  .word 0xa13e1bfb
  .word 0xc3582109
  .word 0xcc43eab6
  .word 0x0903a77a
  .word 0x64a90fa6
  .word 0x2a332147
  .word 0xbd55c40d
  .word 0xe6d563b5
  .word 0x1012e26e
  .word 0x8d592a87
  .word 0x8351a913
  .word 0x7a509a11
  .word 0x453b3476
  .word 0x4b20b34b
  .word 0x9b4683ad
  .word 0xa7522756
  .word 0xe8e5003a
  .word 0x87d9a6c5
  .word 0x7893ca0a
  .word 0x0bc20569
  .word 0x5df40285
  .word 0xd2a81491
  .word 0xe02ebdc7
  .word 0x80b77f08
  .word 0x587850fa
  .word 0x146f028b
  .word 0x68c06c19
  .word 0x7b5ea7f6
  .word 0xea3a444a
  .word 0xaf5c4241
  .word 0xa312a22d
  .word 0x44f6ade6
  .word 0x90c26451
  .word 0x439d408f
  .word 0x0be45e96
  .word 0xc854d689
  .word 0x48973041
  .word 0xe2909b6a
  .word 0x387444b0
  .word 0xb7361891
  .word 0x6be784ca
  .word 0x00e68e7a
  .word 0xa8553ba1
  .word 0xb2a03db8
  .word 0x2b382508
  .word 0x25bec3da
  .word 0xc7246004
  .word 0x53407688
  .word 0xfa2c92f1
  .word 0x16b8a1a2
  .word 0x6da33022
  .word 0x8ecf36bb
  .word 0xb1a1c862
  .word 0x90519d5f
  .word 0xf5b40a07
  .word 0xf8baa370
  .word 0xad047c63
  .word 0xb4a45119
  .word 0x7a5b0b61
  .word 0xc35633b2
  .word 0x12a8369e
  .word 0x59a25885
  .word 0xafa8e114
  .word 0x1277e476
  .word 0xb13854f8
  .word 0xce048d9e
  .word 0xd3203592
  .word 0xe4c40aab
  .word 0x36f25808
  .word 0xb49dd42d
  .word 0xf7edb746
  .word 0x834cdda0
  .word 0xfa7e30aa
  .word 0xb8b37687
  .word 0x1f0aa1c7
  .word 0xda8ee6df
  .word 0x2ad49c1b
  .word 0x76c4cec0
  .word 0x1893250c
  .word 0x41182c08
  .word 0x93c22c5d
  .word 0xee06f667
  .word 0x45011cea
  .word 0x88a29e38
  .word 0x8da683f3
  .word 0x7a1220d6
  .word 0xcb8ba8ac
  .word 0xa645426b
  .word 0xa6054f64
  .word 0x3d16f1b9
  .word 0x577ee138
  .word 0x5ccc27cb
  .word 0xca2c7b46
  .word 0xcf74f994
  .word 0x520d15d8
  .word 0x2052e194
  .word 0xfaba390b
  .word 0xfa9c9b46
  .word 0x7bebacc3
  .word 0x137bb456
  .word 0xea8171f1
  .word 0x10788795
  .word 0x9dae77a7
  .word 0x51ed6015
  .word 0xb709ab19
  .word 0xe320b16a
  .word 0xd56119c6
  .word 0x16933a8c
  .word 0xd25fa069
  .word 0x97512f88
  .word 0x47b0c3b7
  .word 0x82aa97a1
  .word 0x5c8a200c
  .word 0xbe40bcb5
  .word 0xf58825b8
  .word 0x350b0b61
  .word 0x3950b84e
  .word 0xfd1da4b0
  .word 0x168f2439
  .word 0x7a02bb5a
  .word 0xe01768fd
  .word 0xaaad8d0c
  .word 0x25cb29cb
  .word 0x097524e4
  .word 0x7527ae32
  .word 0xb7b7986a
  .word 0x90532849
  .word 0x565aa99c
  .word 0x36132a92
  .word 0xb8026c90
  .word 0x58bb0512
  .word 0xc0e84d69
  .word 0x235c002a
  .word 0x79c80926
  .word 0xb66ab197
  .word 0xd30d79bc
  .word 0xb9033029
  .word 0x2b7b86b4
  .word 0x56c4046e
  .word 0x94355018
  .word 0x9d9c26aa
  .word 0xa19ac34f
  .word 0xbc3f36ec
  .word 0x4102c757
  .word 0x6b1d0b31
  .word 0xa5e89844
  .word 0xb187c456
  .word 0x9baa456e
  .word 0xa9a6b1b9
  .word 0x6f442abb
  .word 0xed09e36e
  .word 0x32551dec
  .word 0x94867a99
  .word 0xe391b9dd
  .word 0x95f877a6
  .word 0x34a95f88
  .word 0x7e21ea81
  .word 0x4b471cba
  .word 0x148881c4
  .word 0x2203dc7f
  .word 0xc3a5cc81
  .word 0x3e1c5b0d
  .word 0xbd3209d9
  .word 0x925548e1
  .word 0x4f225e9f
  .word 0x36753827
  .word 0x7c0c604b
  .word 0x1fd36b91
  .word 0xc4bbd766
  .word 0xe636c570
  .word 0x7fdae800
  .word 0x993bfb31
  .word 0x77e77345
  .word 0x6939c596
  .word 0x305e1a37
  .word 0x32a071c3
  .word 0xc226e450
  .word 0xee9edadb
  .word 0x656b9bd3
  .word 0x66803803
  .word 0x645ed305
  .word 0x91d059d5
  .word 0x51f72e0d
  .word 0x0033a8af
  .word 0xb55d902c
  .word 0x8109e05e
  .word 0x1111f275
  .word 0x9c6a2f82
  .word 0x97cbab1a
  .word 0x3b15cc71
  .word 0xd719b6b4
  .word 0x2382fa35
  .word 0x8b6af0d5
  .word 0xe308792b
  .word 0x827b8f2d
  .word 0xc988ac9d
  .word 0x2a74a4ca
  .word 0x4ba4a212
  .word 0xf72014c6
  .word 0xc3876bd2
  .word 0x6cc533c8
  .word 0x1bcc1ab5
  .word 0x649a8cd4
  .word 0x8e604f8b
  .word 0x8e37eb4f
  .word 0x3cb75465
  .word 0x9d7be3a8
  .word 0x446ba75f
  .word 0xf897031c
  .word 0xb239aac0
  .word 0x3cbc8a34
  .word 0xa6130d6d
  .word 0x2ad691bd
  .word 0x6051c643
  .word 0xbfd5df63
  .word 0x08f1f077
  .word 0x7b432442
  .word 0xa22ba847
  .word 0x6974b828
  .word 0x0689eed4
  .word 0xa7db34ec
  .word 0xa8d8686c
  .word 0x3cf38d22
  .word 0xbf803acf
  .word 0x53296b15
  .word 0x9f2631a5
  .word 0xa9eeb13c
  .word 0x934b0088
  .word 0x0afb3c10
  .word 0x682afdee
  .word 0x4afa016e
  .word 0x63a3e858
  .word 0xe3a1a89c
  .word 0xe257aef9

/* Modulus: KYBER_Q = 3329 */
.globl modulus
modulus:
  .word 0x00000d01
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

/* 1/Q mod 2^32 */
.globl qinv
qinv:
  .word 0x6ba8f301
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

.globl modulus_bn
modulus_bn:
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01
  .word 0x0d010d01

.globl modulus_over_2
modulus_over_2:
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681
  .word 0x06810681

.globl const_0x0fff
const_0x0fff:
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff
  .word 0x0fff0fff

.globl const_1290167
const_1290167:
  .word 0x0013afb7
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

.globl const_8
const_8:
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008
  .word 0x00080008

.globl const_toplant
const_toplant:
  .word 0x97f44fab
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

.globl cbd2_const
cbd2_const:
  /* const1 */
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  .word 0x55555555
  /* const2 */ 
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333
  .word 0x33333333

.globl cbd3_const
cbd3_const:
  /* const1 */
  .word 0x49249249
  .word 0x92492492
  .word 0x24924924
  .word 0x49249249
  .word 0x92492492
  .word 0x24924924
  .word 0x49249249
  .word 0x12492492
  /* const2 */
  .word 0xc71c71c7
  .word 0x71c71c71
  .word 0x1c71c71c
  .word 0xc71c71c7
  .word 0x71c71c71
  .word 0x1c71c71c
  .word 0xc71c71c7
  .word 0x71c71c71

.globl twiddles_ntt
twiddles_ntt:
  /* Layer 1--4 */
  .word 0x84f5c5b6, 0x00000000
  .word 0xc666e465, 0x00000000
  .word 0xfcec8b58, 0x00000000
  .word 0xcb2b72d0, 0x00000000
  .word 0x30726d5b, 0x00000000
  .word 0x91e11612, 0x00000000
  .word 0x41360f89, 0x00000000
  .word 0x51aaf2da, 0x00000000
  .word 0x93922fd5, 0x00000000
  .word 0x0ed77946, 0x00000000
  .word 0x3d4a0dff, 0x00000000
  .word 0xd63e49fb, 0x00000000
  .word 0xfab1a391, 0x00000000
  .word 0x2bc18ea7, 0x00000000
  .word 0x864470e4, 0x00000000
  /* Padding */
  .word 0x00000000, 0x00000000
  /* Layer 5 - 1 */
  .word 0x16c32c11, 0x00000000
  /* Layer 6 - 1 */
  .word 0x16395e0d, 0x00000000
  .word 0x19743224, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 1 */
  .word 0x014eab2e, 0x00000000
  .word 0xd4522112, 0x00000000
  .word 0x2cd52aae, 0x00000000
  .word 0xcbb540d4, 0x00000000
  /* Layer 5 - 2 */
  .word 0xbc2c9a1c, 0x00000000
  /* Layer 6 - 2 */
  .word 0xfa27d58e, 0x00000000
  .word 0x87094e0e, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 2 */
  .word 0x7de29fcd, 0x00000000
  .word 0x379942fb, 0x00000000
  .word 0xaff27732, 0x00000000
  .word 0x54970814, 0x00000000
  /* Layer 5 - 3 */
  .word 0x66f8144e, 0x00000000
  /* Layer 6 - 3 */
  .word 0x5c0c9c92, 0x00000000
  .word 0xb12d72a9, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 3 */
  .word 0x6c5a2074, 0x00000000
  .word 0xccb52d24, 0x00000000
  .word 0xfc4f0d9d, 0x00000000
  .word 0x11eaedee, 0x00000000
  /* Layer 5 - 4 */
  .word 0x71811d74, 0x00000000
  /* Layer 6 - 4 */
  .word 0xaf19ea51, 0x00000000
  .word 0x9e078945, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 4 */
  .word 0x3a22e9a0, 0x00000000
  .word 0xa5cbdca1, 0x00000000
  .word 0xe7da790b, 0x00000000
  .word 0xea8b7f1e, 0x00000000
  /* Layer 5 - 5 */
  .word 0xea3cc040, 0x00000000
  /* Layer 6 - 5 */
  .word 0x31fc27af, 0x00000000
  .word 0x9807ff63, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 5 */
  .word 0x82f5ed16, 0x00000000
  .word 0x7ef63bd5, 0x00000000
  .word 0xd6795921, 0x00000000
  .word 0x8992f4b3, 0x00000000
  /* Layer 5 - 6 */
  .word 0x044e701f, 0x00000000
  /* Layer 6 - 6 */
  .word 0xc13fe765, 0x00000000
  .word 0x3099ccc9, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 6 */
  .word 0x8e08c440, 0x00000000
  .word 0x4935720b, 0x00000000
  .word 0x7059d1b5, 0x00000000
  .word 0xcea1560e, 0x00000000
  /* Layer 5 - 7 */
  .word 0xac4184cf, 0x00000000
  /* Layer 6 - 7 */
  .word 0xdc518394, 0x00000000
  .word 0x0289a6a5, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 7 */
  .word 0x483585bb, 0x00000000
  .word 0xb17c3187, 0x00000000
  .word 0xbb67bcf2, 0x00000000
  .word 0xb7a31ad7, 0x00000000
  /* Layer 5 - 8 */
  .word 0x6681f601, 0x00000000
  /* Layer 6 - 8 */
  .word 0x658209b1, 0x00000000
  .word 0x934370f8, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 8 */
  .word 0x385e2025, 0x00000000
  .word 0xb3b7194d, 0x00000000
  .word 0x149bf401, 0x00000000
  .word 0x314afa3c, 0x00000000
  /* Layer 5 - 9 */
  .word 0x6da8cba2, 0x00000000
  /* Layer 6 - 9 */
  .word 0xb254be68, 0x00000000
  .word 0x6e59f915, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 9 */
  .word 0x79cf3ed4, 0x00000000
  .word 0xb0b7545c, 0x00000000
  .word 0x9ca52e5f, 0x00000000
  .word 0xf79e2ee9, 0x00000000
  /* Layer 5 - 10 */
  .word 0xa1074e36, 0x00000000
  /* Layer 6 - 10 */
  .word 0x3e0eeb29, 0x00000000
  .word 0x22c23fd4, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 10 */
  .word 0x1cd665aa, 0x00000000
  .word 0xc4049d2f, 0x00000000
  .word 0xa0b88f58, 0x00000000
  .word 0x7e801d88, 0x00000000
  /* Layer 5 - 11 */
  .word 0x2924384b, 0x00000000
  /* Layer 6 - 11 */
  .word 0x6e95083b, 0x00000000
  .word 0xdc8c92ba, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 11 */
  .word 0x51bea292, 0x00000000
  .word 0x1887f58b, 0x00000000
  .word 0xd53e5dab, 0x00000000
  .word 0x3a369957, 0x00000000
  /* Layer 5 - 12 */
  .word 0xdda02ec2, 0x00000000
  /* Layer 6 - 12 */
  .word 0x75f6ed02, 0x00000000
  .word 0xb8b6b6df, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 12 */
  .word 0xa169bccb, 0x00000000
  .word 0x2b2410ec, 0x00000000
  .word 0xbda2a4b9, 0x00000000
  .word 0xc77a806d, 0x00000000
  /* Layer 5 - 13 */
  .word 0xb805896c, 0x00000000
  /* Layer 6 - 13 */
  .word 0xcb8de165, 0x00000000
  .word 0xc93f49e7, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 13 */
  .word 0xd7a0a4e0, 0x00000000
  .word 0x53f98a58, 0x00000000
  .word 0x1efd9db9, 0x00000000
  .word 0x4ee63d0f, 0x00000000
  /* Layer 5 - 14 */
  .word 0xdd651f9c, 0x00000000
  /* Layer 6 - 14 */
  .word 0x71e38c09, 0x00000000
  .word 0x31d4c840, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 14 */
  .word 0x57e58be2, 0x00000000
  .word 0xa555be54, 0x00000000
  .word 0xd565bd19, 0x00000000
  .word 0x442224c3, 0x00000000
  /* Layer 5 - 15 */
  .word 0x97ccf03d, 0x00000000
  /* Layer 6 - 15 */
  .word 0xbe402274, 0x00000000
  .word 0xef28ae1a, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 15 */
  .word 0x846bf7b2, 0x00000000
  .word 0x5d33e851, 0x00000000
  .word 0x901c4c98, 0x00000000
  .word 0x4f214c36, 0x00000000
  /* Layer 5 - 16 */
  .word 0x3f228731, 0x00000000
  /* Layer 6 - 16 */
  .word 0x5e5b3410, 0x00000000
  .word 0x45fa9df4, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 16 */
  .word 0xa24249ac, 0x00000000
  .word 0xe1b38fba, 0x00000000
  .word 0x440e750b, 0x00000000
  .word 0xa5a47d32, 0x00000000

.globl twiddles_intt
twiddles_intt:
  /* Layer 7 - 1 */
  .word 0x5a5b82cf, 0x00000000
  .word 0xbbf18af6, 0x00000000
  .word 0x1e4c7047, 0x00000000
  .word 0x5dbdb655, 0x00000000
  /* Layer 6 - 1 */
  .word 0xba05620d, 0x00000000
  .word 0xa1a4cbf1, 0x00000000
  /* Layer 5 - 1 */
  .word 0xc0dd78d0, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 2 */
  .word 0xb0deb3cb, 0x00000000
  .word 0x6fe3b369, 0x00000000
  .word 0xa2cc17b0, 0x00000000
  .word 0x7b94084f, 0x00000000
  /* Layer 6 - 2 */
  .word 0x10d751e7, 0x00000000
  .word 0x41bfdd8d, 0x00000000
  /* Layer 5 - 2 */
  .word 0x68330fc4, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 3 */
  .word 0xbbdddb3e, 0x00000000
  .word 0x2a9a42e8, 0x00000000
  .word 0x5aaa41ad, 0x00000000
  .word 0xa81a741f, 0x00000000
  /* Layer 6 - 3 */
  .word 0xce2b37c1, 0x00000000
  .word 0x8e1c73f8, 0x00000000
  /* Layer 5 - 3 */
  .word 0x229ae065, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 4 */
  .word 0xb119c2f2, 0x00000000
  .word 0xe1026248, 0x00000000
  .word 0xac0675a9, 0x00000000
  .word 0x285f5b21, 0x00000000
  /* Layer 6 - 4 */
  .word 0x36c0b61a, 0x00000000
  .word 0x34721e9c, 0x00000000
  /* Layer 5 - 4 */
  .word 0x47fa7695, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 5 */
  .word 0x38857f94, 0x00000000
  .word 0x425d5b48, 0x00000000
  .word 0xd4dbef15, 0x00000000
  .word 0x5e964336, 0x00000000
  /* Layer 6 - 5 */
  .word 0x47494922, 0x00000000
  .word 0x8a0912ff, 0x00000000
  /* Layer 5 - 5 */
  .word 0x225fd13f, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 6 */
  .word 0xc5c966aa, 0x00000000
  .word 0x2ac1a256, 0x00000000
  .word 0xe7780a76, 0x00000000
  .word 0xae415d6f, 0x00000000
  /* Layer 6 - 6 */
  .word 0x23736d47, 0x00000000
  .word 0x916af7c6, 0x00000000
  /* Layer 5 - 6 */
  .word 0xd6dbc7b6, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 7 */
  .word 0x817fe279, 0x00000000
  .word 0x5f4770a9, 0x00000000
  .word 0x3bfb62d2, 0x00000000
  .word 0xe3299a57, 0x00000000
  /* Layer 6 - 7 */
  .word 0xdd3dc02d, 0x00000000
  .word 0xc1f114d8, 0x00000000
  /* Layer 5 - 7 */
  .word 0x5ef8b1cb, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 8 */
  .word 0x0861d118, 0x00000000
  .word 0x635ad1a2, 0x00000000
  .word 0x4f48aba5, 0x00000000
  .word 0x8630c12d, 0x00000000
  /* Layer 6 - 8 */
  .word 0x91a606ec, 0x00000000
  .word 0x4dab4199, 0x00000000
  /* Layer 5 - 8 */
  .word 0x9257345f, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 9 */
  .word 0xceb505c5, 0x00000000
  .word 0xeb640c00, 0x00000000
  .word 0x4c48e6b4, 0x00000000
  .word 0xc7a1dfdc, 0x00000000
  /* Layer 6 - 9 */
  .word 0x6cbc8f09, 0x00000000
  .word 0x9a7df650, 0x00000000
  /* Layer 5 - 9 */
  .word 0x997e0a00, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 10 */
  .word 0x485ce52a, 0x00000000
  .word 0x4498430f, 0x00000000
  .word 0x4e83ce7a, 0x00000000
  .word 0xb7ca7a46, 0x00000000
  /* Layer 6 - 10 */
  .word 0xfd76595c, 0x00000000
  .word 0x23ae7c6d, 0x00000000
  /* Layer 5 - 10 */
  .word 0x53be7b32, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 11 */
  .word 0x315ea9f3, 0x00000000
  .word 0x8fa62e4c, 0x00000000
  .word 0xb6ca8df6, 0x00000000
  .word 0x71f73bc1, 0x00000000
  /* Layer 6 - 11 */
  .word 0xcf663338, 0x00000000
  .word 0x3ec0189c, 0x00000000
  /* Layer 5 - 11 */
  .word 0xfbb18fe2, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 12 */
  .word 0x766d0b4e, 0x00000000
  .word 0x2986a6e0, 0x00000000
  .word 0x8109c42c, 0x00000000
  .word 0x7d0a12eb, 0x00000000
  /* Layer 6 - 12 */
  .word 0x67f8009e, 0x00000000
  .word 0xce03d852, 0x00000000
  /* Layer 5 - 12 */
  .word 0x15c33fc1, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 13 */
  .word 0x157480e3, 0x00000000
  .word 0x182586f6, 0x00000000
  .word 0x5a342360, 0x00000000
  .word 0xc5dd1661, 0x00000000
  /* Layer 6 - 13 */
  .word 0x61f876bc, 0x00000000
  .word 0x50e615b0, 0x00000000
  /* Layer 5 - 13 */
  .word 0x8e7ee28d, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 14 */
  .word 0xee151213, 0x00000000
  .word 0x03b0f264, 0x00000000
  .word 0x334ad2dd, 0x00000000
  .word 0x93a5df8d, 0x00000000
  /* Layer 6 - 14 */
  .word 0x4ed28d58, 0x00000000
  .word 0xa3f3636f, 0x00000000
  /* Layer 5 - 14 */
  .word 0x9907ebb3, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 15 */
  .word 0xab68f7ed, 0x00000000
  .word 0x500d88cf, 0x00000000
  .word 0xc866bd06, 0x00000000
  .word 0x821d6034, 0x00000000
  /* Layer 6 - 15 */
  .word 0x78f6b1f3, 0x00000000
  .word 0x05d82a73, 0x00000000
  /* Layer 5 - 15 */
  .word 0x43d365e5, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 7 - 16 */
  .word 0x344abf2d, 0x00000000
  .word 0xd32ad553, 0x00000000
  .word 0x2baddeef, 0x00000000
  .word 0xfeb154d3, 0x00000000
  /* Layer 6 - 16 */
  .word 0xe68bcddd, 0x00000000
  .word 0xe9c6a1f4, 0x00000000
  /* Layer 5 - 16 */
  .word 0xe93cd3f0, 0x00000000
  .word 0x00000000, 0x00000000
  /* Layer 4--1 */ 
  .word 0x79bb8f1d, 0x00000000
  .word 0xd43e715a, 0x00000000
  .word 0x054e5c70, 0x00000000
  .word 0x29c1b606, 0x00000000
  .word 0xc2b5f202, 0x00000000
  .word 0xf12886bb, 0x00000000
  .word 0x6c6dd02c, 0x00000000
  .word 0xae550d27, 0x00000000
  .word 0xbec9f078, 0x00000000
  .word 0x6e1ee9ef, 0x00000000
  .word 0xcf8d92a6, 0x00000000
  .word 0x34d48d31, 0x00000000
  .word 0x031374a9, 0x00000000
  .word 0x39991b9c, 0x00000000
  .word 0x6b6de3db, 0x00000000
  /* n_inv */ 
  .word 0x912fe8a0, 0x00000000

.globl context
context:
  .balign 32
  .zero 212

.globl rc
.balign 32
rc:
  .balign 32
  .dword 0x0000000000000001
  .balign 32
  .dword 0x0000000000008082
  .balign 32
  .dword 0x800000000000808a
  .balign 32
  .dword 0x8000000080008000
  .balign 32
  .dword 0x000000000000808b
  .balign 32
  .dword 0x0000000080000001
  .balign 32
  .dword 0x8000000080008081
  .balign 32
  .dword 0x8000000000008009
  .balign 32
  .dword 0x000000000000008a
  .balign 32
  .dword 0x0000000000000088
  .balign 32
  .dword 0x0000000080008009
  .balign 32
  .dword 0x000000008000000a
  .balign 32
  .dword 0x000000008000808b
  .balign 32
  .dword 0x800000000000008b
  .balign 32
  .dword 0x8000000000008089
  .balign 32
  .dword 0x8000000000008003
  .balign 32
  .dword 0x8000000000008002
  .balign 32
  .dword 0x8000000000000080
  .balign 32
  .dword 0x000000000000800a
  .balign 32
  .dword 0x800000008000000a
  .balign 32
  .dword 0x8000000080008081
  .balign 32
  .dword 0x8000000000008080
  .balign 32
  .dword 0x0000000080000001
  .balign 32
  .dword 0x8000000080008008