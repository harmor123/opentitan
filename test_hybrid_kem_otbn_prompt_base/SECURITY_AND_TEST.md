# 安全审查清单与测试方案 (ver0_base — 纯软件基线)

## 一、安全审查清单

### 1. OTBN Secure Wipe
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| 每次模块运行后 DMEM wipe | PASS | `otbn_full_sec_wipe()` → `kDifOtbnCmdSecWipeDmem` |
| 每次模块运行后 IMEM wipe | PASS | `otbn_full_sec_wipe()` → `kDifOtbnCmdSecWipeImem` |
| Wipe 完成确认（轮询 IDLE） | PASS | `otbn_testutils_wait_for_done()` 轮询 BUSY→IDLE |
| 错误路径也执行 wipe | PASS | `hybrid_decaps()` 所有分支均执行完整 wipe |
| LOCKED 状态自动恢复 | PASS | `wait_for_done_resilient()` 检测 LOCKED 后 wipe 恢复 |

### 2. OTBN DMEM 工作区清零
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| HMAC ipad 区 sw 清零（34 words） | PASS | `hmac_sha3.s` 每次调用开头 LOOPI sw x0 |
| HMAC opad 区 sw 清零（34 words） | PASS | `hmac_sha3.s` 每次调用开头 LOOPI sw x0 |
| HKDF msg_buf / t_buf / prk_buf | PASS | `.zero` 初始化，每次 Extract+Expand 覆盖 |
| SHA3 context 区 | PASS | `sha3_init` 开头 `bn.sid` + `sw x0` 清零 |

### 3. Ibex 侧临时缓冲清零
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| ss_e/ss_m/salt_buf memwipe | PASS | `volatile uint8_t*` 逐字节清零 |
| P-256 布尔共享 XOR 临时变量清零 | PASS | `x0[8]`, `x1[8]` 使用后 memwipe |
| ek 临时缓冲 memwipe | PASS | `hybrid_encaps()` 中 ek 组装 ct_hyb 后清零 |
| write_and_verify readback 缓冲区清零 | PASS | `memwipe(readback, len_bytes)` |
| IKM 构造缓冲清零 | PASS | `hkdf_write_params()` 中 `volatile` 逐字节清零 |

### 4. 常数时间实现
| 检查项 | 状态 | 说明 |
|--------|------|------|
| P-256 ECDH 失败时继续 | PASS | 设置 dummy ss_e=0xAA，继续 ML-KEM + HKDF |
| ML-KEM Decap 失败时继续 | PASS | 设置 dummy ss_m=0xBB，继续 HKDF |
| HKDF 总是执行 | PASS | 无论前序步骤成功与否 |
| 无提前 return | PASS | 错误通过 `result` 变量延迟返回 |

### 5. 角色绑定
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| Alice = `"initiator"` | PASS | `phase_hkdf()` 写入 `HYBRID_KEM_ROLE_INITIATOR` |
| Bob = `"responder"` | PASS | `phase_hkdf()` 写入 `HYBRID_KEM_ROLE_RESPONDER` |
| 角色编码入 IKM | PASS | `hkdf_build_ikm()` 将 role 拼接到 IKM 尾部 |
| Alice/Bob OKM 必然不同 | PASS | 角色字符串不同 → IKM 不同 → OKM 不同 |

### 6. 构建完整性
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| 无硬编码 DMEM 偏移 | PASS | 全部通过 `OTBN_DECLARE_SYMBOL_ADDR` / `OTBN_ADDR_T_INIT` |
| DMEM 写入回读验证 | PASS | `write_and_verify()` 写入后回读比对 |
| LOCKED 状态显式处理 | PASS | `wait_for_done_resilient()` 检测并恢复 |

### 7. 纯软件基线特有安全考量

| 检查项 | 状态 | 说明 |
|--------|------|------|
| 无 KMAC 硬件依赖 | PASS | 全部 SHA3 使用软件 Keccak-f，无硬件 CSR 访问 |
| 软件 Keccak-f 常数时间 | PASS | 24 轮完整执行，无数据相关分支 |
| SHA3 context 不跨调用泄漏 | PASS | 每次 sha3_init 清零 200B 状态 |
| 无 BN 向量扩展依赖 | PASS | 仅使用基线 OTBN 指令 |

---

## 二、测试方案

### 2.1 测试层次

| 层级 | 内容 | 方法 | 工具 |
|------|------|------|------|
| L1 | `hmac_sha3_256` 软件版测试 | OTBN 仿真器 | `otbn_sim` |
| L2 | `hkdf_sha3_256` 软件版测试（RFC 5869 向量适配 SHA3-256） | OTBN 仿真器 | `otbn_sim` |
| L3 | ML-KEM-768 各阶段独立测试 | OTBN 仿真器 | 已有 kyber_ver0_base test |
| L4 | `hybrid_encaps` → `hybrid_decaps` 往返 | OTBN 仿真 + Ibex ISS | Bazel `opentitan_test` |
| L5 | 完整 KeyGen → Encaps → Decaps | FPGA / Verilator | `opentitan_fpga_test` |
| L6 | 与 KMAC 加速版交叉验证 | 对比 OKM | 两版本相同输入应得相同 OKM |

### 2.2 Python 参考实现

```python
#!/usr/bin/env python3
"""hybrid_kem_reference.py — 纯软件基线测试向量生成"""

import hashlib
import hmac
import struct

def hkdf_sha3_256(salt: bytes, ikm: bytes, info: bytes, L: int) -> bytes:
    """HKDF-SHA3-256 per RFC 5869 (SHA3-256 替代 SHA-256)."""
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, 'sha3-256').digest()
    N = (L + 31) // 32
    okm = b''
    T_prev = b''
    for i in range(1, N + 1):
        T_i = hmac.new(prk, T_prev + info + bytes([i]), 'sha3-256').digest()
        okm += T_i
        T_prev = T_i
    return okm[:L]

def construct_ikm(ss_e: bytes, ss_m: bytes,
                  ctx: bytes, sid: bytes, role: str) -> bytes:
    """按混合 KEM 协议规范构造 IKM."""
    ikm  = struct.pack('>H', 32)   # len_cls = 0x0020 BE
    ikm += ss_e
    ikm += struct.pack('>H', 32)   # len_pqc = 0x0020 BE
    ikm += ss_m
    ikm += ctx
    ikm += sid
    ikm += role.encode('utf-8')
    return ikm

def compute_okm(ss_e, ss_m, salt, ctx, sid, role, okm_len):
    ikm = construct_ikm(ss_e, ss_m, ctx, sid, role)
    return hkdf_sha3_256(salt, ikm, b'', okm_len)

# ---- 测试向量 1: 空 ctx/sid ----
ss_e = bytes.fromhex(
    "6b17d1f2e12c4247f8bce6e563a440f2"
    "77037d812deb33a0f4a13945d898c296")
ss_m = bytes.fromhex(
    "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    "112233445566778899aabbccddeeff00")
salt = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")

okm_init   = compute_okm(ss_e, ss_m, salt, b'', b'', "initiator", 32)
okm_resp   = compute_okm(ss_e, ss_m, salt, b'', b'', "responder", 32)
assert okm_init != okm_resp, "角色绑定失败！"
print(f"TV1 initiator OKM:  {okm_init.hex()}")
print(f"TV1 responder OKM:  {okm_resp.hex()}")

# ---- 测试向量 2: 含 ctx/sid, 64B OKM ----
ctx = b"myapp-v1"
sid = b"session-001"
okm64 = compute_okm(ss_e, ss_m, salt, ctx, sid, "initiator", 64)
print(f"TV2 OKM (64B):      {okm64.hex()}")
```

### 2.3 C 语言往返测试桩

```c
static void test_encaps_decaps_roundtrip(dif_otbn_t *otbn) {
  uint8_t pk_hyb[HYBRID_KEM_PK_HYB_BYTES];   // 1248B
  uint8_t sk_hyb[HYBRID_KEM_SK_HYB_BYTES];   // 2432B
  uint8_t ct_hyb[HYBRID_KEM_CT_HYB_BYTES];   // 1152B
  uint8_t okm_a[32], okm_b[32];
  const uint8_t salt[32] = {0};
  const char *ctx = "test";
  const char *sid = "001";

  CHECK_STATUS_OK(hybrid_keygen(otbn, pk_hyb, sk_hyb));
  CHECK_STATUS_OK(hybrid_encaps(otbn, pk_hyb, salt,
      (const uint8_t *)ctx, strlen(ctx),
      (const uint8_t *)sid, strlen(sid),
      ct_hyb, okm_a, 32));
  CHECK_STATUS_OK(hybrid_decaps(otbn, sk_hyb, ct_hyb, salt,
      (const uint8_t *)ctx, strlen(ctx),
      (const uint8_t *)sid, strlen(sid),
      okm_b, 32));
  CHECK(memcmp(okm_a, okm_b, 32) == 0,
        "Alice/Bob OKM mismatch!");
}
```

---

## 三、已知风险与缓解

| 风险 | 等级 | 缓解措施 |
|------|------|----------|
| P-256 布尔共享 unmask 在 Ibex 侧 | 中 | 生产代码应在 OTBN 内部完成 unmask |
| 随机数使用测试向量 | 高 | 生产代码必须从 TRNG 获取（`dif_entropy_src`） |
| 指令计数阈值未实测 | 中 | 从 OTBN 仿真器获取实际计数值填入 `HYBRID_KEM_INSNS_*` |
| 软件 SHA3 性能较慢 | 低 | 这正是基线版的目标——量化性能差距 |
| SHA3 软件实现的侧信道 | 低 | Keccak-f 24 轮无数据相关分支，天然常数时间 |

---

## 四、测试状态

### OTBN 仿真测试 (otbn_sim_test) — 7/7 通过

| 测试 | 状态 | 说明 |
|------|------|------|
| `sha3_shake_test` | PASS | SHA3-224/256/384/512 + SHAKE128/256 + 边缘测试 |
| `hmac_test` | PASS | HMAC-SHA3-256 纯软件 (key="key", msg="message") |
| `hkdf_test` | PASS | HKDF-SHA3-256 Extract+Expand (64B OKM) |
| `mlkem768_keypair_test` | PASS | ML-KEM-768 密钥生成 |
| `mlkem768_encap_test` | PASS | ML-KEM-768 封装 |
| `mlkem768_decap_test` | PASS | ML-KEM-768 解封装 |
| `p256_ecdh_test` | PASS | P-256 ECDH 共享密钥 |

### Ibex 集成测试 (Verilator)

| 测试 | 状态 | 说明 |
|------|------|------|
| `hybrid_kem_test` | COMPILE OK | Alert 48 (OTBN DMEM ECC) — 待排查 |

### 与 KMAC 加速版交叉验证

```bash
# 1. 运行基线版，记录 OKM
bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_test

# 2. 运行 KMAC 加速版（相同测试向量），记录 OKM
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_test

# 3. 对比两份 OKM：应完全一致（相同算法、相同输入）
# 4. 对比性能报告：计算硬件加速倍数
```
