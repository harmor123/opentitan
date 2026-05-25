# API 接口说明 (ver0_base — 纯软件基线)

## 〇、运行模式

通过 BUILD 文件的 `defines` 控制，**不在头文件中手动 #define**：

```python
opentitan_test(name = "hybrid_kem_test",
    defines = ["HYBRID_KEM_TEST_MODE"], ...)  # 测试模式
opentitan_test(name = "hybrid_kem_prod",
    defines = [], ...)                         # 生产模式
```

---

## 一、与参考版 (KMAC硬件加速版) 的关键差异

| 项目 | 参考版 (test_hybrid_kem_otbn_prompt) | 基线版 (ver0_base) |
|------|--------------------------------------|---------------------|
| SHA-3 实现 | KMAC 硬件 (CSR/WSR) | 纯软件 Keccak-f[1600] (`sha3_shake.s`) |
| ML-KEM 指令集 | BN 向量扩展 (`bnmulv_version_id=2`) | 基线 OTBN 指令 |
| HKDF 内部 | `kmac_init` / `keccak_send_message` / `kmac_squeeze_32B` | `sha3_init` / `sha3_update` / `sha3_final` |
| RTL 修改 | 需要 bnmulv_ver2 宏 + 7 个 RTL 文件 | **无** |
| 适用场景 | 硬件加速性能评估 | 纯软件性能基线对比 |

---

## 二、常量定义

| 常量 | 值 | 说明 |
|------|----|------|
| `HYBRID_KEM_PK_M_BYTES` | 1184 | ML-KEM-768 公钥 |
| `HYBRID_KEM_SK_M_BYTES` | 2400 | ML-KEM-768 私钥 |
| `HYBRID_KEM_CT_M_BYTES` | 1088 | ML-KEM-768 密文 |
| `HYBRID_KEM_SS_M_BYTES` | 32 | ML-KEM-768 共享密钥 |
| `HYBRID_KEM_PK_E_BYTES` | 64 | P-256 公钥 (未压缩) |
| `HYBRID_KEM_SK_E_BYTES` | 32 | P-256 私钥 (标量 d) |
| `HYBRID_KEM_SS_E_BYTES` | 32 | P-256 ECDH 共享密钥 |
| `HYBRID_KEM_PK_HYB_BYTES` | 1248 | 混合公钥 = pk_m + pk_e |
| `HYBRID_KEM_SK_HYB_BYTES` | 2432 | 混合私钥 = sk_m + sk_e |
| `HYBRID_KEM_CT_HYB_BYTES` | 1152 | 混合密文 = ek + ct_m |
| `HYBRID_KEM_SALT_BYTES` | 32 | HKDF salt |
| `HYBRID_KEM_OKM_MAX` | 256 | OKM 最大长度 |

---

## 三、C API (Ibex 侧)

```c
status_t hybrid_kem_init(void);
status_t hybrid_keygen(dif_otbn_t *otbn, uint8_t *pk_hyb, uint8_t *sk_hyb);
status_t hybrid_encaps(dif_otbn_t *otbn, const uint8_t *pk_hyb, const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *ct_hyb, uint8_t *okm, size_t okm_len);
status_t hybrid_decaps(dif_otbn_t *otbn, const uint8_t *sk_hyb, const uint8_t *ct_hyb,
                       const uint8_t *salt,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t *okm, size_t okm_len);
```

### 辅助 API (hkdf_integration)

```c
// 构造 IKM 缓冲区
void hkdf_build_ikm(uint8_t *ikm_buf, size_t *ikm_len,
                    const uint8_t *ss_e, const uint8_t *ss_m,
                    const uint8_t *ctx, size_t ctx_len,
                    const uint8_t *sid, size_t sid_len,
                    const uint8_t *role, size_t role_len);

// 写入 input_lengths 结构体到 OTBN DMEM
status_t hkdf_write_input_lengths(dif_otbn_t *otbn, otbn_addr_t lengths_addr,
                                  size_t ctx_len, size_t sid_len,
                                  size_t role_len, size_t okm_len);

// 一次性打包所有 HKDF 参数并写入 DMEM
status_t hkdf_write_params(dif_otbn_t *otbn,
                           otbn_addr_t salt_addr, otbn_addr_t ikm_addr,
                           otbn_addr_t lengths_addr,
                           const uint8_t *salt,
                           const uint8_t *ss_e, const uint8_t *ss_m,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sid, size_t sid_len,
                           const uint8_t *role, size_t role_len,
                           size_t okm_len);
```

### 性能测量宏 (otbn_utils.h)

```c
// 读取 Ibex mcycle CSR
static inline uint64_t read_mcycle(void);

// 测量代码块周期数
MCYCLE_BENCH(elapsed) { /* 被测代码 */ }
```

---

## 四、OTBN 汇编接口 — HMAC-SHA3-256

### `hmac_sha3.s` — 纯软件 SHA3 版

| 子程序 | 功能 | 接口 |
|--------|------|------|
| `hmac` | HMAC-SHA3-256 | x10=key_ptr, x11=key_len, x12=msg_ptr, x13=msg_len, x14=out_ptr(32B) |

**内部调用链**：`hmac` → `sha3_init` / `sha3_update` / `sha3_final`（纯软件 Keccak-f）

**DMEM 工作区标签**：

| 标签 | 大小 | 对齐 | 说明 |
|------|------|------|------|
| `hmac_ipad` | 160B | 32B | ipad 工作区 |
| `hmac_opad` | 160B | 32B | opad 工作区 |
| `hmac_inner` | 32B | 32B | 内部哈希输出 H(ipad \|\| msg) |
| `hmac_key_hashed` | 32B | 32B | 超长密钥哈希后暂存 |

---

## 五、OTBN 汇编接口 — HKDF-SHA3-256

### `hkdf_sha3_256.s` — DMEM 接口 + 纯软件 SHA3

| 子程序 | 功能 | 接口 |
|--------|------|------|
| `hkdf_extract` | PRK = HMAC-SHA3-256(salt, IKM) | 从 DMEM label 读取, PRK→prk_buf |
| `hkdf_expand` | OKM = HKDF-Expand(PRK, L) | 从 DMEM label 读取, OKM→output_okm |

**DMEM 标签**：

| 标签 | 大小 | 对齐 | 说明 |
|------|------|------|------|
| `input_salt` | 32B | 32B | HKDF salt |
| `ikm_prebuilt` | 384B | 32B | 预拼接 IKM（Ibex 写入） |
| `input_lengths` | 32B | 32B | 长度结构体 (+0=ctx_len, +4=sid_len, +8=role_len, +12=okm_len) |
| `output_okm` | 256B | 32B | OKM 输出 |

### IKM 格式

```
len_cls(2B BE=0x0020) || ss_e(32B) || len_pqc(2B BE=0x0020) || ss_m(32B) || ctx || sid || role
```

固定头部 68 字节。IKM 总长度 = 68 + ctx_len + sid_len + role_len。

### input_lengths 结构体 (32B)

| 偏移 | 字段 | 类型 |
|------|------|------|
| +0 | ctx_len | u32 LE |
| +4 | sid_len | u32 LE |
| +8 | role_len | u32 LE |
| +12 | okm_len | u32 LE |
| +16 | padding | 16B (全零) |

---

## 六、OTBN 汇编接口 — ML-KEM-768

所有标签与参考版一致（纯软件 SHA3 版）：

| 标签 | 所属 | 说明 | 方向 |
|------|------|------|------|
| `coins` | keypair | 64B 随机数 | Ibex→OTBN |
| `ek` | keypair | 1184B 公钥 | OTBN→Ibex |
| `dk` | keypair | 2400B 私钥 | OTBN→Ibex |
| `ek` | encap | 1184B 公钥 (输入) | Ibex→OTBN |
| `coins` | encap | 32B 随机数 | Ibex→OTBN |
| `ct` | encap | 1088B 密文 | OTBN→Ibex |
| `ss` | encap | 32B 共享密钥 | OTBN→Ibex |
| `dk` | decap | 2400B 私钥 | Ibex→OTBN |
| `ct` | decap | 1088B 密文 | Ibex→OTBN |
| `ss` | decap | 32B 共享密钥 | OTBN→Ibex |

**内部实现差异**：
- 使用 `sha3_init`/`sha3_update`/`sha3_final`（纯软件 Keccak-f）替代 KMAC 硬件
- 使用基线 OTBN 指令（无 `bn.addvm.16H`、`bn.subvm.16H` 等 BN 向量扩展）
- MOD 寄存器设置为 KYBER_Q = 3329（无 Montgomery 域 MOD = R|Q）

---

## 七、OTBN 汇编接口 — P-256 ECDH

与参考版完全一致（P-256 本身不依赖 KMAC 硬件）：

| 标签 | 说明 | 方向 |
|------|------|------|
| `d0` | 64B 标量算术份额 0 | Ibex→OTBN |
| `d1` | 64B 标量算术份额 1 | Ibex→OTBN |
| `x` | 32B 输入点 x / 输出布尔份额 x0 | 双向 |
| `y` | 32B 输入点 y / 输出布尔份额 x1 | 双向 |

**输出**：`dmem[x]` = x0, `dmem[y]` = x1。Ibex 侧 XOR 还原：`ss_e = x0 ^ x1`。

---

## 八、性能度量输出格式

本基线版内嵌 `mcycle` 性能测量，输出格式：

```
===== Hybrid KEM (ver0_base) Performance Report =====
[Phase 1: KeyGen]
  Total Cycles: 1234567
  OTBN ML-KEM Cycles: 800000
  OTBN P-256 Cycles: 400000
  OTBN Wipe Cycles: 34567
  OTBN Call Count: 2
  DMEM Write (Bytes): 3584
  DMEM Read (Bytes): 3648
[Phase 2.1: Encaps]
  ...
=====================================================
```

---

## 九、OTBN 二进制命名

| 二进制 | Bazel target |
|--------|-------------|
| `mlkem768_keypair_ver0` | `//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_keypair_ver0` |
| `mlkem768_encap_ver0` | `//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_encap_ver0` |
| `mlkem768_decap_ver0` | `//test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_decap_ver0` |
| `p256_ecdh_ver0` | `//test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_ecdh_ver0` |
| `hkdf_sha3_256_ver0` | `//test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0` |
