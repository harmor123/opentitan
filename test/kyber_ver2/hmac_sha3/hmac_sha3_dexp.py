"""hmac_sha3_dexp.py — HMAC-SHA3-256 test vector generator."""

import hashlib
import hmac

key  = b"key"
msg  = b"message"
hmac_result = hmac.new(key, msg, 'sha3-256').digest()


print(f"# HMAC-SHA3-256 test vector")
print(f"# key = {key}")
print(f"# msg = {msg}")
print(f"# expected HMAC (BE) = {hmac_result.hex()}")
print(f"# expected HMAC (LE, DMEM order) = {hmac_result[::-1].hex()}")
print()
print(f"test_out: {hmac_result[::-1].hex()}")
