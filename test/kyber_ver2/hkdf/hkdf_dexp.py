"""hkdf_dexp.py — HKDF-SHA3-256 test vector generator.
Outputs .dexp expect file AND auto-generated .word data for hkdf_test.s.
Edit the vectors below and re-run to regenerate everything."""

import hashlib
import hmac
import struct
import sys

# ============ Test vectors (edit here, re-run script) ============

# Hybrid KEM test vectors (from ML-KEM + P-256 KATs)
salt = bytes(32)  # all zeros

# P-256 pk_e X coordinate (x XOR y from p256_ecdh_shared_key_test.dexp)
ss_e = bytes.fromhex(
    "5f33d746a326640a739a9490ec15c103"
    "72869f3de675b2e85742271d18c9eb82")

# ML-KEM ss_m (from assets/output/mlkem768/test_000/encap.dexp, DMEM order)
ss_m = bytes.fromhex(
    "3750ac4a8e656327c3d181fab002554b"
    "f6d2be0475dd28d5f31bef9f835f86ac")

ctx  = b""
sid  = b""
role = sys.argv[2].encode() if len(sys.argv) > 2 else b"initiator"

okm_len = int(sys.argv[1]) if len(sys.argv) > 1 else 32

# ============ IKM construction (matches hkdf_sha3_256.s expectation) ============

def be16(val):
    return struct.pack('>H', val)

ikm  = be16(32) + ss_e
ikm += be16(32) + ss_m
ikm += ctx + sid + role

# ============ HKDF-SHA3-256 ============

prk = hmac.new(salt, ikm, 'sha3-256').digest()
okm = b''
T_prev = b''
for i in range(1, (okm_len + 31) // 32 + 1):
    T_i = hmac.new(prk, T_prev + bytes([i]), 'sha3-256').digest()
    okm += T_i
    T_prev = T_i
okm = okm[:okm_len]

# ============ Helpers ============

def bytes_to_words(data):
    """Convert bytes to .word assembly directives (LE, 4B aligned)."""
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    lines = []
    for i in range(0, len(padded), 4):
        word = struct.unpack('<I', padded[i:i+4])[0]
        lines.append(f"    .word 0x{word:08x}")
    return lines

def dmem_order(d):
    """Full byte reversal for DMEM order (match kmac_squeeze_32B output)."""
    return d[::-1]

# ============ Output ============

print(f"# HKDF-SHA3-256 (okm_len={okm_len}, ikm_len={len(ikm)})")
print(f"# salt = {salt.hex()}")
print(f"# ss_e = {ss_e.hex()}")
print(f"# ss_m = {ss_m.hex()}")
print(f"# ctx  = {ctx} ({len(ctx)}B)")
print(f"# sid  = {sid} ({len(sid)}B)")
print(f"# role = {role} ({len(role)}B)")
print()

print("# ---- .dexp file (copy to hkdf_test.dexp) ----")
print(f"output_okm: {dmem_order(okm).hex()}")
print()

print("# ---- .s data section (copy to hkdf_test.s) ----")
print()
print(".balign 32")
print(".globl input_salt")
print("input_salt:")
for line in bytes_to_words(salt):
    print(line)

print()
print(f".balign 32")
print(f".globl ikm_prebuilt")
print(f"ikm_prebuilt:")
for line in bytes_to_words(ikm):
    print(line)

print()
print(f".balign 32")
print(f".globl input_lengths")
print(f"input_lengths:")
print(f"    .word {len(ctx)}     /* ctx_len  at +0 */")
print(f"    .word {len(sid)}     /* sid_len  at +4 */")
print(f"    .word {len(role)}    /* role_len at +8 */")
print(f"    .word {okm_len}      /* okm_len  at +12 */")
print(f"    .zero 16              /* pad to 32B */")
