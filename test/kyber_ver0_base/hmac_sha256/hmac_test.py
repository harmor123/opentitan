import hmac
import hashlib

# RFC 4231 - Test Case 3
key = bytes([0x0b] * 160)          # 字节，全为 0x0b
#msg = b"what do "                # 8 字节
msg = b"Hi There"
hmac_sha3_256 = hmac.new(key, msg, hashlib.sha3_256)
print(hmac_sha3_256.hexdigest())  


import hashlib

def hmac_sha3_256(key, message):
    B = 136  # SHA3-256 block size (rate)
    L = 32   # output length
    
    # Step 1: Key preprocessing
    if len(key) > B:
        key = hashlib.sha3_256(key).digest()
    if len(key) < B:
        key = key + b'\x00' * (B - len(key))
    
    # Step 2: Derive ipad and opad
    ipad = bytes([k ^ 0x36 for k in key])
    opad = bytes([k ^ 0x5C for k in key])
    
    # Step 3: Inner hash
    inner = hashlib.sha3_256(ipad + message).digest()
    
    # Step 4: Outer hash
    outer = hashlib.sha3_256(opad + inner).digest()
    
    return outer

# 测试s
key = bytes([0x0b] * 160)
msg = b"Hi There"
result = hmac_sha3_256(key, msg)
print(result.hex())  # b37410ef3f276942400193a195c6e5796cf96b7efa93d2c782e51b0d2b4c61d3



