/* Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Name:        poly_compress
 *
 * Description: Compression and subsequent serialization of a polynomial
 *
 * Arguments:   - uint8_t r: output byte array (of length KYBER_POLYCOMPRESSEDBYTES)
 *              - poly a: input polynomial, n=256, q=3329
 *
 * @param[in]  x11: dptr_input, dmem pointer to input polynomial
 * @param[out] x12: dptr_output, dmem pointer to output byte array
 * @param[in]  w2: dptr_modulus_over_2
 * @param[in]  w5: const_1290167
 * @param[in]  w31: all-zero
 *
 * clobbered registers: x0-x30, w0-w31
 */

poly_compress:
  /* Multiply constant 80635 with 2**4 so we shift right 32 bits instead of 28.
   * This lets us return the high parts of 64-bit products within the multiply. */
  bn.subi w16, w5, 7 /* w16 = 80635 * 16 = 1290160 */
  LOOPI 4, 16
    LOOPI 4, 14
      bn.lid               x0, 0(x11++) /* Load input */
      bn.shv.16H           w0, w0 << 4 /* <= 4 */
      bn.addv.16H          w0, w0, w2 /* += 1665 */
      bn.trn1.16H          w1, w0, w31 /* Put even coeffs to 32-bit slots */
      bn.mulv.l.8S.even.hi w1, w1, sw0.0 /* >> 32 takes high parts of 64-bit products */
      bn.mulv.l.8S.odd.hi  w1, w1, sw0.0
      bn.trn2.16H          w0, w0, w31 /* Put odd coeffs to 32-bit slots */
      bn.mulv.l.8S.even.hi w0, w0, sw0.0
      bn.mulv.l.8S.odd.hi  w0, w0, sw0.0
      bn.trn1.16H          w1, w1, w0 /* Interleave results to original order */
      LOOPI 16, 2
        bn.rshi w4, w1, w4 >> 4
        bn.rshi w1, w31, w1 >> 16
      NOP
    bn.sid x4, 0(x12++)

  ret

/*
 * Name:        polyvec_compress
 *
 * Description: Compress and serialize vector of polynomials
 *
 * @param[in]  x10: dptr_input, dmem pointer to input polynomial
 * @param[out] x12: dptr_output, dmem pointer to output byte array
 * @param[in]  w2: modulus_over_2 = (0x681)^16
 * @param[in]  w5: const_1290167
 * @param[in]  w31: all-zero
 *
 * clobbered registers: x0-x30, w0-w31
 */
polyvec_compress:

  bn.shv.8S w3, w2 >> 16 /* w3 = (0x681)^8 */
  bn.mov    w16, w5 /* w16 = 1290167 */
  LOOPI 6, 61
    /* First WDR: 160 bits (16 coeffs) + (Reload) 90 bits (9 coeffs) + 6 bits */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 160 bits */
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 2nd batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 90 bits */
    LOOPI 9, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Pack 6 bits */
    bn.rshi w4, w1, w4 >> 6
    bn.sid  x4, 0(x12++)

    /* Second WDR: 4 bits + 60 bits (6 coeffs) + (Reload) 160 bits (16 coeffs) +
     * (Reload) 30 bits (3 coeffs) + 2 bits */
    /* Pack 4 + 60 bits */
    LOOPI 7, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 3rd batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 160 bits */
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 4th batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 30 bits */
    LOOPI 3, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Pack 2 bits */
    bn.rshi w4, w1, w4 >> 2
    bn.sid  x4, 0(x12++)

    /* Third WDR: 8 bits + 120 bits (12 coeffs) + (Reload) 120 bits (12 coeffs) + 8 bits */
    /* Pack 8 + 120 bits */
    LOOPI 13, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 5th batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 120 bits */
    LOOPI 12, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Pack 8 bits */
    bn.rshi w4, w1, w4 >> 8
    bn.sid  x4, 0(x12++)

    /* Fourth WDR: 2 bits + 30 bits (3 coeffs) + (Reload) 160 bits (16 coeffs) +
     * (Reload) 60 bits (6 coeffs) + 4 bits */
    /* Pack 2 + 30 bits */
    LOOPI 4, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 6th batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 160 bits */
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 7th batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 60 bits */
    LOOPI 6, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Pack 4 bits */
    bn.rshi w4, w1, w4 >> 4
    bn.sid  x4, 0(x12++)

    /* Fifth WDR: 6 bits + 90 bits (9 coeffs) + (Reload) 160 bits (16 coeffs) */
    /* Pack 6 + 90 bits */
    LOOPI 10, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    /* Load 8th batch */
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    /* Pack 160 bits */
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.sid  x4, 0(x12++)

  ret

/*
 * Name:        polyvec_compress_16
 *
 * Description: Subroutine for compressing 16 coefficients
 *
 * @param[in]   w0: input vector with 16 16-bit coefficients
 * @param[in]   w3: (0x681)^8
 * @param[in]  w16: const_1290167
 * @param[in]  w31: all-zero
 * @param[out]  w1: output vector with 16 compressed coefficients
 */
polyvec_compress_16:
  bn.trn1.16H          w1, w0, w31 /* Put even coeffs to 32-bit slots */
  bn.shv.8S            w1, w1 << 10 /* << 10 */
  bn.addv.8S           w1, w1, w3 /* +1665 */
  bn.mulv.l.8S.even.hi w1, w1, sw0.0 /* >> 32 takes high parts of 64-bit products */
  bn.mulv.l.8S.odd.hi  w1, w1, sw0.0
  bn.trn2.16H          w0, w0, w31 /* Put odd coeffs to 32-bit slots */
  bn.shv.8S            w0, w0 << 10 /* << 10 */
  bn.addv.8S           w0, w0, w3 /* +1665 */
  bn.mulv.l.8S.even.hi w0, w0, sw0.0
  bn.mulv.l.8S.odd.hi  w0, w0, sw0.0
  bn.trn1.16H          w1, w1, w0 /* Interleave results to original order */
  ret

/*
 * Name:        pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed vector of polynomials b and the compressed
 *              polynomial v
 *
 * @param[in]  x10: dptr_b, dmem pointer to first input polynomial
 * @param[in]  x11: dptr_v, dmem pointer to second input polynomial
 * @param[out] x12: dptr_output, dmem pointer to output byte array
 * @param[in]  x13: const_1290167
 * @param[in]  x15: dptr_modulus_over_2
 * @param[in]  w31: all-zero
 *
 * clobbered registers: x0-x30, w0-w31
 */

.globl pack_ciphertext
pack_ciphertext:
  /* Set up registers for input and output */
  li x4, 4
  li x5, 2
  li x6, 5

  /* Load const */
  bn.lid  x5, 0(x15) /* w2 = modulus_over_2 = (0x681)^16 */
  bn.lid  x6, 0(x13) /* w5 = const_1290167 */

  /* Zeroize w31 */
  bn.xor w31, w31, w31
  jal    x1, polyvec_compress
  jal    x1, poly_compress

  ret


/*
 * Name:        poly_decompress
 *
 * Description: De-serialization and subsequent decompression of a polynomial;
 *              approximate inverse of poly_compress
 *
 * @param[in]  x10: dptr_input, dmem pointer to input byte array
 * @param[out] x12: dptr_output, dmem pointer to output polynomial
 * @param[in]  w2: const_0x0fff
 * @param[in]  w31: all-zero
 *
 * clobbered registers: x0-x30, w0-w31
 */

poly_decompress:

  bn.shv.16H w2, w2 >> 8 /* 0xf */
  LOOPI 4, 11
    bn.lid x0, 0(x10++)
    LOOPI 4, 8
      LOOPI 16, 2
        bn.rshi w1, w0, w1 >> 16
        bn.rshi w0, w31, w0 >> 4
      bn.and           w1, w1, w2
      bn.mulv.l.16H.lo w1, w1, sw0.0
      bn.addv.16H      w1, w1, w5
      bn.shv.16H       w1, w1 >> 4
      bn.sid           x4, 0(x12++)
    NOP

  ret

/*
 * Name:        polyvec_decompress
 *
 * Description: De-serialize and decompress vector of polynomials;
 *              approximate inverse of polyvec_compress
 *
 * @param[in]  x10: dptr_input, dmem pointer to input byte array
 * @param[in]  w31: all-zero
 * @param[in]  w2: const_0x0fff
 * @param[in]  w3: (0x00008000)^8
 * @param[out] x12: dptr_output, dmem pointer to output polynomials
 *
 * clobbered registers: x0-x30, w0-w31
 */

polyvec_decompress:

  LOOPI 6, 69
    /* First WDR: 160 bits of w0 */
    bn.lid x0, 0(x10++)
    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16  /* Extract 10 bit from input to a 16-bit vector slot */
      bn.rshi w0, w31, w0 >> 10 /* Shift out used bits */
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Second WDR: 90 bits + 6 bits + (Reload) 4 bits + 60 bits */
    LOOPI 9, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 6 /* Move the final 6 bits of w0 to w1 */
    bn.lid  x0, 0(x10++) /* Load the second batch of input to w0 */
    bn.rshi w1, w0, w1 >> 10 /* Move the first 4 bits of w0 to w1 to form 10 bits */
    bn.rshi w0, w31, w0 >> 4 /* Shift out the used 4 bits */
    LOOPI 6, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Third WDR: 160 bits */
    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Fourth WDR: 30 bits + 2 bits + (Reload) 8 bits + 120 bits */
    LOOPI 3, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 2 /* Move the final 2 bits of w0 to w1 */
    bn.lid  x0, 0(x10++) /* Load the third batch of input */
    bn.rshi w1, w0, w1 >> 14 /* Move the first 8 bits of w0 to w1 to form 10 bits */
    bn.rshi w0, w31, w0 >> 8 /* Shift out used bits */
    LOOPI 12, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Fifth WDR: 120 bits + 8 bits + (Reload) 2 bits + 30 bits */
    LOOPI 12, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 8 /* Move the final 8 bits of w0 to w1 */
    bn.lid  x0, 0(x10++) /* Load the fourth batch of input to w0 */
    bn.rshi w1, w0, w1 >> 8 /* Move the first 2 bits of w0 to w1 to form 10 bits */
    bn.rshi w0, w31, w0 >> 2 /* Shift out used bits */
    LOOPI 3, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Sixth WDR: 160 bits */
    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Seventh WDR: 60 bits + 4 bits + (Reload) 6 bits + 90 bits */
    LOOPI 6, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi      w1, w0, w1 >> 4 /* Move the final 4 bits of w0 to w1 */
    bn.lid       x0, 0(x10++) /* Load the fifth batch of input to w0 */
    bn.rshi      w1, w0, w1 >> 12 /* Move the first 6 bits of w0 to w1 to form 10 bits */
    bn.rshi      w0, w31, w0 >> 6 /* Shift out used bits */
    LOOPI 9, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    /* Eigth WDR: 160 bits */
    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

  ret

/*
 * Name:        polyvec_decompress_16
 *
 * Description: Subroutine for decompressing 16 coefficients
 *
 * @param[inout]   w1: input/output vector with 16 16-bit coefficients
 * @param[in]     w3: (0x00008000)^8 (const added to ACC before multiply)
 * @param[in]    w16: KYBER_Q
 * @param[in]    w31: all-zero
 */
polyvec_decompress_16:

  bn.shv.16H           w1, w1 << 6 /* *(2**6) */
  bn.wsrw              0x3, w3 /* Write w3 to ACC */
  bn.wsrw              0xb, w3 /* Write w3 to ACCH */
  bn.mulv.l.16H.acc.hi w1, w1, sw0.0 /* *KYBER_Q + ACC */
  ret

/*
 * Name:        unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext
 *
 * @param[in]  x10: dptr_input, dmem pointer to first input byte array
 * @param[in]  x13: const_8
 * @param[in]  x14: modulus_bn
 * @param[in]  x15: const_0x0fff
 * @param[out] x12: dptr_output, dmem pointer to output ciphertext
 * @param[in]  w31: all-zero
 *
 * clobbered registers: x0-x30, w0-w31
 */

.globl unpack_ciphertext
unpack_ciphertext:
  /* Set up registers for input and output */
  li x4, 1
  li x5, 2

  /* Load const */
  bn.lid  x5++, 0(x15) /* w2 = const_0x0fff */
  bn.lid  x5, 0(x13) /* w3 = const_8 */

  /* For polyvec_decompress: w3 = 512 * (2**6) = 32768
   * For poly_decompress: w3 is overwritten */
  bn.mov    w5, w3 /* Save w3 */
  bn.shv.8S w3, w3 << 16 /* w3 = (0x00080000)^8 */
  bn.shv.8S w3, w3 >> 4  /* w3 = (0x00008000)^8 */

  /* KYBER_Q is in sw0.0 */
  bn.wsrr w16, 0x0

  /* Zeroize w31 */
  bn.xor     w31, w31, w31

  jal        x1, polyvec_decompress
  jal        x1, poly_decompress

  ret
