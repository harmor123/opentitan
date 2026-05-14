/* pack_ciphertext.s — exact port of mlkem_ver2_nold, KYBER_K=3. */
.text

poly_compress:
  bn.subi w16, w5, 7
  LOOPI 4, 16
    LOOPI 4, 14
      bn.lid               x0, 0(x11++)
      bn.shv.16H           w0, w0 << 4
      bn.addv.16H          w0, w0, w2
      bn.trn1.16H          w1, w0, w31
      bn.mulv.l.8S.even.hi w1, w1, sw0.0
      bn.mulv.l.8S.odd.hi  w1, w1, sw0.0
      bn.trn2.16H          w0, w0, w31
      bn.mulv.l.8S.even.hi w0, w0, sw0.0
      bn.mulv.l.8S.odd.hi  w0, w0, sw0.0
      bn.trn1.16H          w1, w1, w0
      LOOPI 16, 2
        bn.rshi w4, w1, w4 >> 4
        bn.rshi w1, w31, w1 >> 16
      NOP
    bn.sid x4, 0(x12++)
  ret

poly_compress_16:
  bn.trn1.16H          w1, w0, w31
  bn.shv.8S            w1, w1 << 5
  bn.addv.8S           w1, w1, w3
  bn.mulv.l.8S.even.hi w1, w1, sw0.0
  bn.mulv.l.8S.odd.hi  w1, w1, sw0.0
  bn.trn2.16H          w0, w0, w31
  bn.shv.8S            w0, w0 << 5
  bn.addv.8S           w0, w0, w3
  bn.mulv.l.8S.even.hi w0, w0, sw0.0
  bn.mulv.l.8S.odd.hi  w0, w0, sw0.0
  bn.trn1.16H          w1, w1, w0
  ret

polyvec_compress:
  bn.shv.8S w3, w2 >> 16
  bn.mov    w16, w5
  LOOPI 6, 61
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 9, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.rshi w4, w1, w4 >> 6
    bn.sid  x4, 0(x12++)

    LOOPI 7, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 3, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.rshi w4, w1, w4 >> 2
    bn.sid  x4, 0(x12++)

    LOOPI 13, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 12, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.rshi w4, w1, w4 >> 8
    bn.sid  x4, 0(x12++)

    LOOPI 4, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 6, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.rshi w4, w1, w4 >> 4
    bn.sid  x4, 0(x12++)

    LOOPI 10, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.lid x0, 0(x10++)
    jal    x1, polyvec_compress_16
    LOOPI 16, 2
      bn.rshi w4, w1, w4 >> 10
      bn.rshi w1, w31, w1 >> 16
    bn.sid  x4, 0(x12++)
  ret

polyvec_compress_16:
  bn.trn1.16H          w1, w0, w31
  bn.shv.8S            w1, w1 << 10
  bn.addv.8S           w1, w1, w3
  bn.mulv.l.8S.even.hi w1, w1, sw0.0
  bn.mulv.l.8S.odd.hi  w1, w1, sw0.0
  bn.trn2.16H          w0, w0, w31
  bn.shv.8S            w0, w0 << 10
  bn.addv.8S           w0, w0, w3
  bn.mulv.l.8S.even.hi w0, w0, sw0.0
  bn.mulv.l.8S.odd.hi  w0, w0, sw0.0
  bn.trn1.16H          w1, w1, w0
  ret

.globl pack_ciphertext
pack_ciphertext:
  li x4, 4
  li x5, 2
  li x6, 5

  bn.lid  x5, 0(x15) /* w2 = modulus_over_2 */
  bn.lid  x6, 0(x13) /* w5 = const_1290167 */

  bn.xor w31, w31, w31
  jal    x1, polyvec_compress
  jal    x1, poly_compress

  ret


poly_decompress:
  bn.shv.16H w2, w2 >> 8
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

polyvec_decompress:
  LOOPI 6, 69
    bn.lid x0, 0(x10++)
    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 9, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 6
    bn.lid  x0, 0(x10++)
    bn.rshi w1, w0, w1 >> 10
    bn.rshi w0, w31, w0 >> 4
    LOOPI 6, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 3, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 2
    bn.lid  x0, 0(x10++)
    bn.rshi w1, w0, w1 >> 14
    bn.rshi w0, w31, w0 >> 8
    LOOPI 12, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 12, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi w1, w0, w1 >> 8
    bn.lid  x0, 0(x10++)
    bn.rshi w1, w0, w1 >> 8
    bn.rshi w0, w31, w0 >> 2
    LOOPI 3, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 6, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    bn.rshi      w1, w0, w1 >> 4
    bn.lid       x0, 0(x10++)
    bn.rshi      w1, w0, w1 >> 12
    bn.rshi      w0, w31, w0 >> 6
    LOOPI 9, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)

    LOOPI 16, 2
      bn.rshi w1, w0, w1 >> 16
      bn.rshi w0, w31, w0 >> 10
    jal    x1, polyvec_decompress_16
    bn.sid x4, 0(x12++)
  ret

polyvec_decompress_16:
  bn.shv.16H           w1, w1 << 6
  bn.wsrw              0x3, w3
  bn.wsrw              0xb, w3
  bn.mulv.l.16H.acc.hi w1, w1, sw0.0
  ret

.globl unpack_ciphertext
unpack_ciphertext:
  li x4, 1
  li x5, 2

  bn.lid  x5++, 0(x15) /* w2 = const_0x0fff */
  bn.lid  x5, 0(x13) /* w3 = const_8 */

  bn.mov    w5, w3
  bn.shv.8S w3, w3 << 16
  bn.shv.8S w3, w3 >> 4

  bn.wsrr w16, 0x0

  bn.xor     w31, w31, w31

  jal        x1, polyvec_decompress
  jal        x1, poly_decompress

  ret
