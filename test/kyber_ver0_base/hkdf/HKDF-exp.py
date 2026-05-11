import hmac
import hashlib
import struct

# def hmac_sha3_256(key, message):
#     """计算 HMAC-SHA3-256"""
#     return hmac.new(key, message, hashlib.sha3_256).digest()

def hmac_sha3_256(key, message):
    B = 136  # SHA3-256 block size (rate) = 200 - 2 * L, L = 32
    L = 32   # output L
    
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

def hkdf_expand(prk, info, L):
    """
    HKDF-Expand 基于 HMAC-SHA3-256
    prk  : 伪随机密钥（至少 32 字节）
    info : 上下文信息（bytes）
    L : 输出长度（字节）
    """
    hash_len = 32  # SHA3-256 输出长度
    if L > 255 * hash_len:
        raise ValueError("L too long")
    if info is None:
        info = b''
    N = (L + hash_len - 1) // hash_len
    t = b''
    okm = b''
    for i in range(1, N + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
    return okm[:L]

def compute_hybrid_shared_secret(K_cls, K_pqc, ctx, sid, role, salt, L):
    """
    计算混合共享密钥 K_hyb
    参数:
        K_cls : 经典密钥（32 字节）
        K_pqc : PQC 密钥（32 字节）
        ctx   : 上下文（bytes）
        sid   : 会话 ID（bytes）
        role  : 角色标识（bytes，例如 b"initiator" 或 b"responder"）
        salt  : 盐值（bytes，推荐 32 字节随机数）
        L     : 输出密钥长度（字节）
    返回:
        K_hyb : 共享密钥（长度为 L 字节）
    """
    # 1. 构造 IKM
    # 长度字段使用 2 字节大端整数
    len_cls = struct.pack('>H', len(K_cls))   # 32 通常 -> b'\x00\x20'
    len_pqc = struct.pack('>H', len(K_pqc))   # 32 -> b'\x00\x20'
    IKM = len_cls + K_cls + len_pqc + K_pqc + ctx + sid + role

    # 2. 提取 PRK
    PRK = hmac_sha3_256(salt, IKM)

    # 3. 扩展得到 K_hyb
    # 这里 info 可以留空，也可以根据应用添加额外标识（如 b"hybrid-key"）
    info = b""
    K_hyb = hkdf_expand(PRK, info, L)
    return K_hyb

# # ========== 示例用法 ==========
# if __name__ == "__main__":
#     # 示例数据（实际应用中应使用真实密钥和随机值）
#     K_cls = bytes([0x01] * 32)   # 示例经典密钥
#     K_pqc = bytes([0x02] * 32)   # 示例 PQC 密钥
#     ctx = b"Hybrid key exchange"
#     sid = b"session_123456"
#     role = b"initiator"
#     salt = bytes([0x0b] * 32)    # 盐值（应与对方一致）
#     L = 64                        # 需要派生 64 字节共享密钥

#     K_hyb = compute_hybrid_shared_secret(K_cls, K_pqc, ctx, sid, role, salt, L)
#     print("共享密钥 (hex):", K_hyb.hex())
#     # 0c5db1c9a990a9557bcc3693ad39f5bc4fbcdc6a1c3c1e2bdb1a4e5becc122ecedc49645725cfe690abc2f3c1ca42de0564bcab985c8f01f9025e4491a765e1b

import hmac
import hashlib

prk = bytes([0x0b] * 32)
info = bytes([0x0b] * 31)
L = 64

omk = hkdf_expand(prk, info, L)
# print(omk.hex())


def hkdf_extract(salt, ikm, hash_func=hashlib.sha3_256):
    """
    HKDF-Extract 步骤：从输入密钥材料 (IKM) 和可选的 salt 中提取伪随机密钥 (PRK)。

    参数:
        salt      : bytes, 可选盐值，推荐使用随机值，但也可为 None 或空字节串。
        ikm       : bytes, 输入密钥材料（如共享秘密、预共享密钥等）。
        hash_func : 哈希函数构造器，默认为 hashlib.sha3_256，需支持 new() 方法。

    返回:
        PRK       : bytes, 长度等于 hash_func().digest_size 的伪随机密钥。
    """
    hash_len = hash_func().digest_size

    # 若未提供 salt，则使用全零字节串（长度与哈希输出相同）
    if salt is None or len(salt) == 0:
        salt = b'\x00' * hash_len

    # PRK = HMAC-Hash(salt, IKM)
    # 这里直接使用标准库 hmac.new，也可替换为您自定义的 hmac_sha3_256 函数
    prk = hmac.new(salt, ikm, hash_func).digest()
    return prk


import hmac
import hashlib

def hkdf_sha3_256(salt, ikm, info, L):
    if not salt: salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    t = b''
    okm = b''
    for i in range(1, (L + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
    return okm[:L]

# --- 测试用例 1：标准情况 (触发 T_prev 拼接，L=64，多轮循环) ---
salt1 = bytes.fromhex("000102030405060708090a0b0c")
ikm1  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
info1 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9") # 10字节 (非4对齐，测试尾部掩码)
okm1  = hkdf_sha3_256(salt1, ikm1, info1, 64)
print(f"TC1_OKM: {okm1.hex()}")

# --- 测试用例 2：空 Salt (测试 bne x11, x0 分支) ---
salt2 = b""
ikm2  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
info2 = b""
okm2  = hkdf_sha3_256(salt2, ikm2, info2, 64)
print(f"TC2_OKM: {okm2.hex()}")

# --- 测试用例 3：空 Info，L=32 (测试只跑一轮，无 T_prev) ---
salt3 = bytes.fromhex("000102030405060708090a0b0c")
ikm3  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
info3 = b""
okm3  = hkdf_sha3_256(salt3, ikm3, info3, 32)
print(f"TC3_OKM: {okm3.hex()}")

