"""hkdf_kat.py — HKDF-SHA3-256 KAT generator for Hybrid KEM.
Adapted from test/kyber_ver2/hkdf/hkdf_dexp.py.

Generates expected OKM for initiator and responder roles.
Edit ss_e/ss_m at the top, re-run to update KAT values.
"""

import hashlib
import hmac
import struct
import sys

# ============ Test vectors (from ML-KEM + P-256 KATs) ============

salt = bytes(32)  # all zeros

# P-256: pk_e X coordinate (x XOR y from p256_ecdh_shared_key_test.dexp)
ss_e = bytes.fromhex(
    "5f33d746a326640a739a9490ec15c103"
    "72869f3de675b2e85742271d18c9eb82")

# ML-KEM ss_m from assets/output/mlkem768/test_000/encap.dexp
# DMEM byte order (same as OTBN output in test code)
ss_m = bytes.fromhex(
    "3750ac4a8e656327c3d181fab002554b"
    "f6d2be0475dd28d5f31bef9f835f86ac")

role_initiator = b"initiator"
role_responder = b"responder"

okm_len = int(sys.argv[1]) if len(sys.argv) > 1 else 32

# ============ IKM construction ============

def be16(val):
    return struct.pack('>H', val)

def build_ikm(ss_e, ss_m, role):
    ikm  = be16(32) + ss_e
    ikm += be16(32) + ss_m
    ikm += role
    return ikm

# ============ HKDF-SHA3-256 ============

def hkdf_sha3_256(ss_e, ss_m, role, L):
    ikm = build_ikm(ss_e, ss_m, role)
    prk = hmac.new(salt, ikm, 'sha3-256').digest()
    okm = b''
    T_prev = b''
    for i in range(1, (L + 31) // 32 + 1):
        T_i = hmac.new(prk, T_prev + bytes([i]), 'sha3-256').digest()
        okm += T_i
        T_prev = T_i
    return okm[:L]

okm_initiator = hkdf_sha3_256(ss_e, ss_m, role_initiator, okm_len)
okm_responder = hkdf_sha3_256(ss_e, ss_m, role_responder, okm_len)

# ============ Output ============

def dmem_order(d):
    return d[::-1]

def bytes_to_c(name, data):
    lines = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    return "\n".join(lines)

print(f"// HKDF-SHA3-256 (okm_len={okm_len})")
print(f"// ss_e = {ss_e.hex()}")
print(f"// ss_m = {ss_m.hex()}")
print(f"// initiator OKM: {okm_initiator.hex()}")
print(f"// responder OKM: {okm_responder.hex()}")
print(f"// verify: initiator != responder → {okm_initiator != okm_responder}")
print()
# C arrays: natural byte order (matches otbn_testutils_read_data output)
print(bytes_to_c("kExpectedOkmInitiator", okm_initiator))
print()
print(bytes_to_c("kExpectedOkmResponder", okm_responder))
print()
print(f"// .dexp initiator:  {dmem_order(okm_initiator).hex()}")
print(f"// .dexp responder:  {dmem_order(okm_responder).hex()}")
