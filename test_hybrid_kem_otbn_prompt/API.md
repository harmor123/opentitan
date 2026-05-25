# 接口说明

## 〇、运行模式

通过 BUILD 文件的 `defines` 控制，**不在头文件中手动 #define**：

```python
opentitan_test(name = "hybrid_kem_test",
    defines = ["HYBRID_KEM_TEST_MODE"], ...)  # 测试模式
opentitan_test(name = "hybrid_kem_prod",
    defines = [], ...)                         # 生产模式
```

---

## 一、常量定义

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

## 二、C API (Ibex 侧)

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

---

## 三、OTBN 汇编接口 — HMAC-SHA3-256

### `hmac_sha3.s` — 纯函数库 (无数据段)

| 子程序 | 功能 | 接口 |
|--------|------|------|
| `hmac_sha3_256` | HMAC-SHA3-256 | x10=key_ptr, x11=key_len, x12=msg_ptr, x13=msg_len, x14=out_ptr(32B) |

**调用者需提供的 label：**

| 标签 | 大小 | 对齐 | 说明 |
|------|------|------|------|
| `hmac_ipad` | 160B | 32B | ipad 工作区 |
| `hmac_opad` | 160B | 32B | opad 工作区 |
| `hmac_inner` | 32B | 32B | 内部哈希输出 |
| `hmac_key_hashed` | 32B | 32B | 超长密钥哈希后暂存 |
| `const_0x36` | 160B | 32B | 全 0x36 常量 |
| `const_0x5c` | 160B | 32B | 全 0x5C 常量 |

---

## 四、OTBN 汇编接口 — HKDF-SHA3-256

### `hkdf_sha3_256.s` — 纯函数库 (无数据段)

| 子程序 | 功能 | 接口 |
|--------|------|------|
| `hkdf_extract` | PRK = HMAC-SHA3-256(salt, IKM) | 从 DMEM label 读取, PRK→hmac_key_hashed |
| `hkdf_expand` | OKM = HKDF-Expand(PRK, L), info="" | 从 DMEM label 读取, OKM→output_okm |

**调用者需提供的 label：**

| 标签 | 大小 | 对齐 | 说明 |
|------|------|------|------|
| `input_salt` | 32B | 32B | HKDF salt |
| `ikm_prebuilt` | 可变 | 32B | 预拼接 IKM (测试用) |
| `input_lengths` | 32B | 32B | 长度结构体 (+0=ctx_len, +4=sid_len, +8=role_len, +12=okm_len) |
| `output_okm` | 256B | 32B | OKM 输出 |
| `t_buf` | 32B | 32B | T(i) 暂存 (Expand 循环) |
| `ikm_buf` | 1024B | 32B | Expand 临时消息缓冲 |
| `hmac_key_hashed` | 32B | 32B | PRK 暂存 (Extract→Expand 传递) |
| `hmac_inner` | 32B | 32B | HMAC 内部哈希输出 |
| 以及所有 HMAC 工作区标签 (见上节) |

### IKM 格式

```
len_cls(2B BE=0x0020) || ss_e(32B) || len_pqc(2B BE=0x0020) || ss_m(32B) || ctx || sid || role
```

### input_lengths 结构体 (32B)

| 偏移 | 字段 | 类型 |
|------|------|------|
| +0 | ctx_len | u32 LE |
| +4 | sid_len | u32 LE |
| +8 | role_len | u32 LE |
| +12 | okm_len | u32 LE |
| +16 | padding | 16B |

---

## 五、OTBN 汇编接口 — ML-KEM-768

| 标签 | 所属 | 说明 | 方向 |
|------|------|------|------|
| `coins` | keypair | 64B 随机数 | Ibex→OTBN |
| `ek` | keypair | 1184B 公钥 | OTBN→Ibex |
| `dk` | keypair | 2400B 私钥 | OTBN→Ibex |
| `ek` | encap | 1184B 公钥 | Ibex→OTBN |
| `coins` | encap | 32B 随机数 | Ibex→OTBN |
| `ct` | encap | 1088B 密文 | OTBN→Ibex |
| `ss` | encap | 32B 共享密钥 | OTBN→Ibex |
| `dk` | decap | 2400B 私钥 | Ibex→OTBN |
| `ct` | decap | 1088B 密文 | Ibex→OTBN |
| `ss` | decap | 32B 共享密钥 | OTBN→Ibex |

---

## 六、OTBN 汇编接口 — P-256 ECDH

| 标签 | 说明 | 方向 |
|------|------|------|
| `d0` | 64B 标量算术份额 0 | Ibex→OTBN |
| `d1` | 64B 标量算术份额 1 | Ibex→OTBN |
| `x` | 32B 输入点 x / 输出布尔份额 0 | 双向 |
| `y` | 32B 输入点 y / 输出布尔份额 1 | 双向 |

---

## 七、测试向量格式

| 类型 | 扩展名 | 格式 | BUILD 属性 |
|------|--------|------|-----------|
| 寄存器期望 | `.exp` | 文本 `name = 0xVAL` | `exp = "foo.exp"` |
| DMEM 期望 | `.dexp` | 文本 `label: hex` | `dexp = "foo.dexp"` |

- `.dexp` hex 为 DMEM 原始字节序 (`kmac_squeeze_32B` 输出整体反转)
- 生成: `python3 hkdf_dexp.py` 自动输出 `.dexp` 行和 `.word` 数据段
- 改测试向量只需改 Python 变量后重新运行
