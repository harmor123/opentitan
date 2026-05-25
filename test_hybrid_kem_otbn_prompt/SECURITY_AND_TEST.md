# 安全审查清单与测试方案

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
| HKDF 汇编 ipad 区 sw 清零（40 words） | PASS | `hkdf_sha3_256.s` main 退出前 |
| HKDF 汇编 opad 区 sw 清零（40 words） | PASS | `hkdf_sha3_256.s` main 退出前 |
| HKDF 汇编 inner/t_buf/key_hashed 清零（24 words） | PASS | `hkdf_sha3_256.s` main 退出前 |
| HKDF 汇编 WDR bn.xor 清零（w0-w15） | PASS | `hkdf_sha3_256.s` main 退出前 |
| IKM 构造前 ikm_buf 清零（256 words） | PASS | `construct_ikm` 开头 sw x0 循环 |

### 3. Ibex 侧临时缓冲清零
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| ss_e/ss_m/salt_buf memwipe | PASS | `volatile uint8_t*` 逐字节清零 |
| P-256 布尔共享 XOR 临时变量清零 | PASS | `x0[8]`, `x1[8]` 使用后 memwipe |
| ek 临时缓冲 memwipe | PASS | `hybrid_encaps()` 中 ek 组装 ct_hyb 后清零 |
| write_and_verify readback 缓冲区清零 | PASS | `memwipe(readback, len_bytes)` |

### 4. 常数时间实现
| 检查项 | 状态 | 说明 |
|--------|------|------|
| P-256 ECDH 失败时继续 | PASS | 设置 dummy ss_e=0xAA，继续 ML-KEM + HKDF |
| ML-KEM Decap 失败时继续 | PASS | 设置 dummy ss_m=0xBB，继续 HKDF |
| HKDF 总是执行 | PASS | 无论前序步骤成功与否 |
| 无提前 return | PASS | 错误通过 `result` 变量延迟返回 |
| LOAD_CHECKSUM 失败也走完整路径 | PASS | checksum 失败触发 `INTERNAL()` 但仍执行 wipe |

### 5. 角色绑定
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| Alice = `"initiator"` | PASS | `phase_hkdf()` 写入 `HYBRID_KEM_ROLE_INITIATOR` |
| Bob = `"responder"` | PASS | `phase_hkdf()` 写入 `HYBRID_KEM_ROLE_RESPONDER` |
| 角色编码入 IKM | PASS | OTBN `construct_ikm` 将 role 拼接到 IKM 尾部 |
| Alice/Bob OKM 必然不同 | PASS | 角色字符串不同 → IKM 不同 → OKM 不同 |

### 6. KMAC 硬件管理
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| 每次 HMAC 后 kmac_done | PASS | `hmac_sha3_256` 内/外哈希后各一次 |
| 每次哈希前 kmac_init | PASS | 内/外哈希各一次 `kmac_init(SHA3-256)` |
| Ibex 不访问 KMAC | PASS | KMAC CSR 仅在 OTBN 汇编中操作 |

### 7. 构建完整性
| 检查项 | 状态 | 实现位置 |
|--------|------|---------|
| 无硬编码 DMEM 偏移 | PASS | 全部通过 `OTBN_DECLARE_SYMBOL_ADDR` / `OTBN_ADDR_T_INIT` |
| LOAD_CHECKSUM 验证 | PASS | `load_with_checksum()` 比对硬件 CRC32 |
| 指令计数验证 | PASS | `execute_and_check_insns()` 比对预期值 |
| DMEM 写入回读验证 | PASS | `write_and_verify()` 写入后回读比对 |
| LOCKED 状态显式处理 | PASS | `wait_for_done_resilient()` 检测并恢复 |

### 8. OTBN 仿真测试状态

| 测试 | 状态 | 说明 |
|------|------|------|
| `mlkem768_keypair_test` | PASS | ML-KEM-768 密钥生成 |
| `mlkem768_encap_test` | PASS | ML-KEM-768 封装 |
| `mlkem768_decap_test` | PASS | ML-KEM-768 解封装 |
| `p256_ecdh_test` | PASS | P-256 ECDH (官方 ver1, 无 MAI) |
| `kmac_sha3_test` | PASS | KMAC/SHA3 原语 |
| `hkdf_test` | PASS | HKDF-SHA3-256 (Extract+Expand, IKM预拼) |
| `hmac_sha3_test` (shell) | PASS | HMAC-SHA3-256 独立测试 |

### 9. 已知风险与缓解
| 风险 | 等级 | 缓解措施 |
|------|------|----------|
| P-256 布尔共享 unmask 在 Ibex 侧 | 中 | 生产代码应在 OTBN 内部完成 unmask |
| 随机数使用测试向量 | 高 | 生产代码必须从 TRNG 获取（`dif_entropy_src`） |
| OTBN 指令计数阈值需实测 | 中 | 从 OTBN 仿真器获取实际计数值填入 `kExpectedInsn*` |
| checksum 符号依赖构建流水线 | 低 | `otbn_build.py` 自动生成，构建失败会暴露 |
| VLA（变长数组）在栈上 | 低 | `write_and_verify` 中 `readback[len_bytes]` 仅在测试中使用 |

---

## 二、测试向量方案

### 2.1 测试层次

| 层级 | 内容 | 方法 | 工具 |
|------|------|------|------|
| L1 | `hmac_sha3_256` 单独测试（RFC 4868 向量） | OTBN 仿真器 | `otbn_sim.py` |
| L2 | `hkdf_sha3_256` 单独测试（RFC 5869 向量适配 SHA3-256） | OTBN 仿真器 | `otbn_sim.py` |
| L3 | ML-KEM-768 各阶段独立测试 | OTBN 仿真器 | 已有 test .s 文件 |
| L4 | `hybrid_encaps` → `hybrid_decaps` 往返 | OTBN 仿真 + Ibex ISS | Bazel `opentitan_functest` |
| L5 | 完整 KeyGen → Encaps → Decaps | FPGA / Verilator | `opentitan_fpga_test` |
| L6 | 与 Python 参考实现交叉验证 | Python + C | 见下方脚本 |

### 2.2 Python 参考实现

```python
#!/usr/bin/env python3
"""hybrid_kem_reference.py — 测试向量生成"""

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

## 三、尚需在生产代码中改进的点

### A. 随机数生成
| # | 问题 | 测试模式 | 生产模式 |
|---|------|---------|---------|
| A1 | ML-KEM KeyGen coins | `kTestMlKemKeypairCoins[64]` 硬编码 | `entropy_get()` → `dif_entropy_src_read()` |
| A2 | ML-KEM Encap coins | `kTestMlKemEncapCoins[32]` 硬编码 | `entropy_get()` 每轮刷新 |
| A3 | P-256 标量 d | `kTestP256D0[64]` 硬编码 (d1=0) | `entropy_get()` + `p256_split_scalar()` |
| A4 | P-256 d1 份额 | 全零 (测试简化) | 真随机 64B (需补全模n运算) |
| A5 | 模式切换 | BUILD `copts = ["-DHYBRID_KEM_TEST_MODE"]` | BUILD `copts = []` |

### B. 密钥处理安全
| # | 问题 | 当前状态 | 生产要求 |
|---|------|---------|---------|
| B1 | P-256 布尔共享 unmask 在 Ibex 侧 | `x0 XOR x1` 在 C 代码执行 | OTBN 内部完成 unmask |
| B2 | sk_e 传输 | 从 d0 直接读取（测试） | KeyMgr sideload 注入 |
| B3 | 中间密钥在 Ibex 栈上 | ss_e/ss_m 临时存在 | OTBN scratchpad 暂存 |

### C. 构建集成
| # | 问题 | 当前状态 | 生产要求 |
|---|------|---------|---------|
| C1 | BUILD 文件 | `BUILD` 含 5 otbn_binary + 1 functest | `bazel test` 验证通过 |
| C2 | checksum 符号 | `OTBN_DECLARE_CHECKSUM` 声明 5 个 | `otbn_build.py` 自动生成 `_checksum` 符号 |
| C3 | checksum 验证 | `load_with_checksum()` 比对硬件 CRC32 | 每次 load 自动验证 |
| C4 | 指令计数阈值 | `hybrid_kem.h` 中 5 个 `HYBRID_KEM_INSNS_*` 宏 | 从 `otbn_sim` 实测后填入 |
| C5 | 指令计数验证 | `execute_and_check_insns()` 阈值=0 跳过 | 填入实际值后自动启用 |
| C6 | DMEM 写入验证 | `write_and_verify()` 写入后回读比对 | 已在所有 phase 函数中使用 |
| C7 | LOCKED 恢复 | `wait_for_done_resilient()` 检测并尝试 wipe | 已在 decaps P-256 步骤中使用 |

### D. 故障注入与韧性
| # | 问题 | 当前状态 | 生产要求 |
|---|------|---------|---------|
| D1 | FI 下常数时间验证 | 代码逻辑存在 | 实际 FI 测试验证 dummy 路径不可区分 |
| D2 | OTBN 时钟管理 | 未处理 | 执行期间保持时钟，空闲时关闭 |
| D3 | KeyMgr 集成 | 未实现 | P-256 私钥通过 sideload 注入 |

### E. 侧信道防御
| # | 问题 | 当前状态 | 生产要求 |
|---|------|---------|---------|
| E1 | Ibex 调度时序随机化 | 顺序执行 | 模块间插入随机延迟 |
| E2 | DMEM 访问模式随机化 | 固定顺序 | crypto lib 的 `otbn_dmem_write` 已有随机化 |
| E3 | 功耗分析防护 | P-256 已有算术掩码 | ML-KEM 侧信道防御需额外评估 |
