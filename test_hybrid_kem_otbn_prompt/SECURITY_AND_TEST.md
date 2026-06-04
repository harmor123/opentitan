# 安全审查与测试

## 一、安全设计

### 1. P-256 ECDH

| 防护 | 实现 |
|------|------|
| FI 防护 (on-curve) | `p256_isoncurve_proj` → `trigger_fault_if_fg0_z` |
| FI 防护 (点无穷远) | `proj_to_affine` → `bn.cmp w10,w31` → `trigger_fault_if_fg0_not_z` |
| SCA 防护 (标量) | `p256_masked_scalar_reblind` (320-bit 盲化) |
| SCA 防护 (掩码) | A2B Goubin 算法, 布尔掩码输出 |
| 常数时间 | double-and-add-always (321 次迭代恒定) |

### 2. ML-KEM-768

| 防护 | 实现 |
|------|------|
| 常数时间 | 所有循环固定次数, 无条件分支选择 |
| 掩码 | 算术份额 (keygen), 布尔份额 (decap) |
| 随机化 | URND 加密 coins + 盲化 |

### 3. HKDF-SHA3-256

| 防护 | 实现 |
|------|------|
| KEM 正确性 | IKM 不含 role, info="" → OKM Alice == Bob |
| 角色绑定 | 上层协议: 第二次 HKDF from OKM |
| 密钥擦除 | PRK/T(i) 使用后清零 |
| KMAC 管理 | 每次 HMAC 后 `kmac_done`, 每次前 `kmac_init` |

### 4. Ibex 调度

| 防护 | 实现 |
|------|------|
| OTBN Secure Wipe | 每次模块切换后 `kDifOtbnCmdSecWipeDmem` |
| DMEM 地址安全 | 全部通过 `OTBN_DECLARE_SYMBOL_ADDR` / `OTBN_ADDR_T_INIT` |
| 中间值保护 | ss_e/ss_m 使用后清零 |

## 二、测试状态

### ISS 测试 (全部通过)

| 测试 | 状态 | 验证方式 |
|------|------|------|
| `p256_ecdh_test` | ✅ | .dexp DMEM 比对 (x0, x1) |
| `hkdf_test` | ✅ | .dexp DMEM 比对 (output_okm) |
| `mlkem768_keypair_test` | ✅ | .dexp DMEM 比对 (ek, dk) |
| `mlkem768_encap_test` | ✅ | .dexp DMEM 比对 (ct, ss) |
| `mlkem768_decap_test` | ✅ | .dexp DMEM 比对 (ss) |

### Chip Sim 测试

| 测试 | 状态 |
|------|------|
| `test_p256_only` | ✅ |
| `test_p256_official` | ✅ |
| `test_mlkem_keypair_only` | ✅ |
| `test_mlkem_encap_only` | ✅ |
| `test_mlkem_decap_only` | ✅ |
| `test_hkdf_only` | ⬜ |
| `phase1_keygen_test` | ⬜ |
| `phase2_alice_encap_test` | ⬜ |
| `phase2_bob_decap_test` | ⬜ |

### 测试层次

| 层 | 内容 | 工具 |
|------|------|------|
| L1 | HMAC-SHA3-256 独立测试 | OTBN ISS |
| L2 | HKDF-SHA3-256 独立测试 | OTBN ISS |
| L3 | ML-KEM 各阶段独立测试 | OTBN ISS |
| L4 | P-256 ECDH 独立测试 | OTBN ISS |
| L5 | 单模块 chip sim | Verilator |
| L6 | Phase 1/2 集成 | Verilator / FPGA |
| L7 | Python 交叉验证 | ref/*.py |

## 三、Python 参考实现

```python
"""hybrid_kem_reference.py — HKDF-SHA3-256"""
import hashlib, hmac, struct

def build_ikm(ss_e, ss_m, ctx=b"", sid=b""):
    return struct.pack('>H', 32) + ss_e + struct.pack('>H', 32) + ss_m + ctx + sid

def hkdf_sha3_256(salt, ikm, info, L):
    if not salt: salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, 'sha3-256').digest()
    okm, T = b'', b''
    for i in range(1, (L + 31) // 32 + 1):
        T = hmac.new(prk, T + info + bytes([i]), 'sha3-256').digest()
        okm += T
    return prk, okm[:L]

# KEM: unified output (info="")
prk, okm = hkdf_sha3_256(salt, ikm, b"", 32)

assert okm_alice == okm_bob  # KEM 正确性

# Upper layer: role binding via second HKDF
okm_init = hkdf_sha3_256(b"", okm, b"initiator", 32)   # Alice
okm_resp = hkdf_sha3_256(b"", okm, b"responder", 32)   # Bob
```

## 四、已知风险

| 风险 | 等级 | 缓解 |
|------|------|------|
| P-256 布尔共享 unmask 在 Ibex 侧 | 中 | 生产代码应在 OTBN 内部 |
| 随机数使用 KAT 测试向量 | 高 | 生产需 TRNG |
| OTBN 指令计数阈值需实测 | 中 | 从 ISS 获取实际值 |
| P-256 RTL 示例点 P bug | 低 | 使用基点 G, 已提交 issue |
