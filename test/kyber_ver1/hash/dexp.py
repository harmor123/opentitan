
"""
sha3_dexp.py
修改下方 msg 变量即可，输出各算法的硬件字节序摘要。 测试向量。
SHAKE / cSHAKE 按每 32 字节一块分行输出。
"""

import hashlib
import sys

try:
    from Crypto.Hash import cSHAKE128, cSHAKE256
    HAS_CSHAKE = True
except ImportError:
    HAS_CSHAKE = False

# ============ 算法 ============
ALGOS = {
    # "sha3_224": lambda m, n: hashlib.sha3_224(m).digest(),
    "sha3_256": lambda m, n: hashlib.sha3_256(m).digest(),
    # "sha3_384": lambda m, n: hashlib.sha3_384(m).digest(),
    "sha3_512": lambda m, n: hashlib.sha3_512(m).digest(),
    "shake128": lambda m, n: hashlib.shake_128(m).digest(n),
    "shake256": lambda m, n: hashlib.shake_256(m).digest(n),
}

if HAS_CSHAKE:
    ALGOS["cshake128"] = lambda m, n, c=b"KMAC": cSHAKE128.new(data=m, custom=c).read(n)
    ALGOS["cshake256"] = lambda m, n, c=b"KMAC": cSHAKE256.new(data=m, custom=c).read(n)

# ============ 硬件字节序 ============
def hw_order(d: bytes) -> bytes:
    return d[::-1]

def fmt(d: bytes) -> str:
    return d.hex()

# ============ ★ 在这里修改输入 ★ ============
msg = b"what do "          # 改这里！支持 b"字符串" 或 bytes.fromhex("deadbeef")
num_blocks = 3             # SHAKE / cSHAKE 输出块数，每块 32 字节
# ============================================

BLOCK_SIZE = 32  # 每块 32 字节 (256 bit = 1 WDR)

# ============ 输出 ============
for name, func in ALGOS.items():
    if name.startswith(("shake", "cshake")):
        total = num_blocks * BLOCK_SIZE
        digest = func(msg, total)
        digest_hw = hw_order(digest)
        print(f"{name}:  # {num_blocks} x {BLOCK_SIZE}B")
        for i in range(num_blocks):
            chunk = digest_hw[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
            print(f"  block{i}: {fmt(chunk)}")
    else:
        digest = func(msg, 0)
        print(f"{name}: {fmt(hw_order(digest))}")
