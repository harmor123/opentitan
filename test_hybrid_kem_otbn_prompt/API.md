# 接口说明

## 〇、运行模式

项目通过 BUILD 文件的 `copts` 控制编译模式，**不在头文件中手动 #define**：

```python
# 功能测试模式: 硬编码测试向量, 确定性输出
opentitan_functest(name = "hybrid_kem_test",
    copts = ["-DHYBRID_KEM_TEST_MODE"], ...)

# 生产安全模式: TRNG 熵源, 真随机数
opentitan_functest(name = "hybrid_kem_prod",
    copts = [], ...)
```

| 宏状态 | 模式 | 随机数来源 | P-256 d1 | 用途 |
|--------|------|-----------|---------|------|
| `-DHYBRID_KEM_TEST_MODE` | 功能测试 | 硬编码测试向量 | 全零 (简化) | CI / 验证 |
| (未定义) | 生产安全 | `dif_entropy_src` | 真随机拆分 | 安全部署 |

---

## 一、常量定义

### 1.1 密钥和密文大小

```c
#define HYBRID_KEM_PK_M_BYTES   1184   // ML-KEM-768 公钥
#define HYBRID_KEM_SK_M_BYTES   2400   // ML-KEM-768 私钥
#define HYBRID_KEM_CT_M_BYTES   1088   // ML-KEM-768 密文
#define HYBRID_KEM_SS_M_BYTES   32     // ML-KEM-768 共享密钥

#define HYBRID_KEM_PK_E_BYTES   64     // P-256 公钥（未压缩格式 x||y）
#define HYBRID_KEM_SK_E_BYTES   32     // P-256 私钥（标量 d）
#define HYBRID_KEM_SS_E_BYTES   32     // P-256 ECDH 共享密钥

#define HYBRID_KEM_PK_HYB_BYTES 1248   // 混合公钥 = pk_m || pk_e
#define HYBRID_KEM_SK_HYB_BYTES 2432   // 混合私钥 = sk_m || sk_e
#define HYBRID_KEM_CT_HYB_BYTES 1152   // 混合密文 = ek || ct_m

#define HYBRID_KEM_SALT_BYTES   32     // HKDF salt 长度
#define HYBRID_KEM_OKM_MAX      256    // OKM 最大输出长度
```

### 1.2 字符串长度上限

```c
#define HYBRID_KEM_CTX_MAX      128    // ctx 最大字节数
#define HYBRID_KEM_SID_MAX      128    // sid 最大字节数
#define HYBRID_KEM_ROLE_MAX     16     // role 最大字节数

#define HYBRID_KEM_ROLE_INITIATOR       "initiator"
#define HYBRID_KEM_ROLE_RESPONDER       "responder"
#define HYBRID_KEM_ROLE_INITIATOR_LEN   10
#define HYBRID_KEM_ROLE_RESPONDER_LEN   10
```

---

## 二、公开 API

### 2.1 `hybrid_keygen()` — 混合密钥生成

```c
status_t hybrid_keygen(
    dif_otbn_t *otbn,
    uint8_t    *pk_hyb,   // [out] 1248 bytes
    uint8_t    *sk_hyb    // [out] 2432 bytes
);
```

**功能**：生成 ML-KEM-768 + P-256 混合密钥对。

**OTBN 执行序列**：
1. 加载 `mlkem768_keypair` → 写入随机数 → 执行 → 读取 pk_m, sk_m → Wipe
2. 加载 `p256_ecdh` → 写入标量 d + 基点 G → 执行 → 读取 pk_e, sk_e → Wipe

**输出格式**：
```
pk_hyb[0..1183]   = pk_m    (ML-KEM-768 公钥)
pk_hyb[1184..1247] = pk_e   (P-256 公钥，x坐标32B + 填充32B)

sk_hyb[0..2399]   = sk_m    (ML-KEM-768 私钥)
sk_hyb[2400..2431] = sk_e   (P-256 私钥，标量 32B)
```

**返回值**：
- `OK_STATUS()` — 成功
- `INVALID_ARGUMENT()` — 空指针参数
- `INTERNAL()` — OTBN 执行失败、checksum 不匹配、指令计数异常

**安全擦除**：函数内部在两次 OTBN 操作之间执行完整的 DMEM+IMEM wipe。

---

### 2.2 `hybrid_encaps()` — 混合封装

```c
status_t hybrid_encaps(
    dif_otbn_t       *otbn,
    const uint8_t    *pk_hyb,     // [in]  1248 bytes (Bob 的公钥)
    const uint8_t    *salt,       // [in]  32 bytes (可为 NULL)
    const uint8_t    *ctx,        // [in]  可变长度
    size_t            ctx_len,    // [in]  ctx 字节数 (≤128)
    const uint8_t    *sid,        // [in]  可变长度
    size_t            sid_len,    // [in]  sid 字节数 (≤128)
    uint8_t          *ct_hyb,     // [out] 1152 bytes
    uint8_t          *okm,        // [out] L bytes
    size_t            okm_len     // [in]  期望的 OKM 长度 (≤256)
);
```

**功能**：Alice 端——使用 Bob 的混合公钥进行封装，生成密文和派生密钥。

**OTBN 执行序列**：
1. 加载 `p256_ecdh`（d*G）→ 执行 → 读取 ek（临时公钥） → Wipe
2. 加载 `p256_ecdh`（d*pk_e_bob）→ 执行 → 读取 ss_e → Wipe
3. 加载 `mlkem768_encap` → 写入 pk_m + 随机数 → 执行 → 读取 ct_m, ss_m → Wipe
4. 加载 `hkdf_sha3_256` → 写入 salt, ss_e, ss_m, ctx, sid, `"initiator"` → 执行 → 读取 OKM → Wipe

**输出格式**：
```
ct_hyb[0..63]      = ek     (Alice 临时 P-256 公钥)
ct_hyb[64..1151]   = ct_m   (ML-KEM-768 密文)

okm[0..okm_len-1]  = 派生密钥材料
```

**参数约束**：
- `salt` 为 NULL 时自动使用 32 字节全零 salt（符合 RFC 5869）
- `okm_len` 范围为 [1, HYBRID_KEM_OKM_MAX]（即 1..256）
- `ctx_len` ≤ HYBRID_KEM_CTX_MAX（128）
- `sid_len` ≤ HYBRID_KEM_SID_MAX（128）

---

### 2.3 `hybrid_decaps()` — 混合解封装

```c
status_t hybrid_decaps(
    dif_otbn_t       *otbn,
    const uint8_t    *sk_hyb,     // [in]  2432 bytes (Bob 的私钥)
    const uint8_t    *ct_hyb,     // [in]  1152 bytes (收到的密文)
    const uint8_t    *salt,       // [in]  32 bytes (可为 NULL)
    const uint8_t    *ctx,        // [in]  可变长度
    size_t            ctx_len,    // [in]  ctx 字节数 (≤128)
    const uint8_t    *sid,        // [in]  可变长度
    size_t            sid_len,    // [in]  sid 字节数 (≤128)
    uint8_t          *okm,        // [out] L bytes
    size_t            okm_len     // [in]  期望的 OKM 长度 (≤256)
);
```

**功能**：Bob 端——使用自己的混合私钥和收到的混合密文进行解封装，派生密钥。

**OTBN 执行序列**：
1. 加载 `p256_ecdh` → 写入 sk_e（算术份额）+ ek → 执行 → 读取 ss_e → Wipe
2. 加载 `mlkem768_decap` → 写入 sk_m + ct_m → 执行 → 读取 ss_m → Wipe
3. 加载 `hkdf_sha3_256` → 写入 salt, ss_e, ss_m, ctx, sid, `"responder"` → 执行 → 读取 OKM → Wipe

**常数时间保证**：
- P-256 ECDH 失败 → 使用 dummy `ss_e = 0xAA...AA`，继续执行
- ML-KEM Decap 失败 → 使用 dummy `ss_m = 0xBB...BB`，继续执行
- HKDF **一定执行**（无论前序步骤成功与否）
- 攻击者无法通过时序/功耗区分成功与失败

**返回值**：
- `OK_STATUS()` — 成功（注意：即使 ML-KEM 隐式拒绝也返回 OK）
- 其他错误码 — 硬件故障

---

## 三、内部 Phase 函数

以下函数为 `static` 内部函数，仅供 `hybrid_keygen/encaps/decaps` 调用，也可单独用于单元测试。

### 3.1 `phase_mlkem_keypair()`

```c
static status_t phase_mlkem_keypair(
    dif_otbn_t *otbn,
    uint8_t    *pk_m,    // [out] 1184 bytes
    uint8_t    *sk_m     // [out] 2400 bytes
);
```

加载 `mlkem768_keypair`，写入 64B 测试随机数，执行，读取 pk_m 和 sk_m。**不执行 wipe**（由调用者决定 wipe 策略）。

### 3.2 `phase_mlkem_encap()`

```c
static status_t phase_mlkem_encap(
    dif_otbn_t    *otbn,
    const uint8_t *pk_m,     // [in]  1184 bytes
    uint8_t       *ct_m,     // [out] 1088 bytes
    uint8_t       *ss_m      // [out] 32 bytes
);
```

加载 `mlkem768_encap`，写入 Bob 的公钥和 32B 测试随机数，执行，读取 ct_m 和 ss_m。

### 3.3 `phase_mlkem_decap()`

```c
static status_t phase_mlkem_decap(
    dif_otbn_t    *otbn,
    const uint8_t *sk_m,     // [in]  2400 bytes
    const uint8_t *ct_m,     // [in]  1088 bytes
    uint8_t       *ss_m      // [out] 32 bytes
);
```

加载 `mlkem768_decap`，写入私钥和密文，执行，读取 ss_m。

### 3.4 `phase_p256_scalar_mult()`

```c
static status_t phase_p256_scalar_mult(
    dif_otbn_t    *otbn,
    const uint8_t *d0,        // [in]  64 bytes (算术份额 0)
    const uint8_t *d1,        // [in]  64 bytes (算术份额 1)
    const uint8_t *point_x,   // [in]  32 bytes (点 P 的 x 坐标)
    const uint8_t *point_y,   // [in]  32 bytes (点 P 的 y 坐标)
    uint8_t       *result_x   // [out] 32 bytes (d*P 的 x 坐标)
);
```

加载 `p256_ecdh`，写入标量算术份额 d0、d1 和点坐标，执行，读取布尔份额 x0、x1，在 Ibex 侧 XOR 得到结果。

**keygen 模式**：d = 随机标量，P = 基点 G
**ECDH 模式**：d = 静态私钥，P = 对方公钥

### 3.5 `phase_hkdf()`

```c
static status_t phase_hkdf(
    dif_otbn_t    *otbn,
    const uint8_t *salt,       // [in]  32 bytes
    const uint8_t *ss_e,       // [in]  32 bytes (P-256 共享密钥)
    const uint8_t *ss_m,       // [in]  32 bytes (ML-KEM 共享密钥)
    const uint8_t *ctx,        // [in]  可变长度
    size_t         ctx_len,    // [in]  ctx 字节数
    const uint8_t *sid,        // [in]  可变长度
    size_t         sid_len,    // [in]  sid 字节数
    const uint8_t *role,       // [in]  可变长度（"initiator"/"responder"）
    size_t         role_len,   // [in]  role 字节数
    uint8_t       *okm,        // [out] L bytes
    size_t         okm_len     // [in]  OKM 长度
);
```

加载 `hkdf_sha3_256`，写入全部输入参数，执行，读取 OKM。

---

## 四、内部安全辅助函数

### 4.1 `load_with_checksum()`

```c
static status_t load_with_checksum(
    dif_otbn_t       *otbn,
    const otbn_app_t  app,
    uint32_t          expected_checksum
);
```

加载 OTBN 应用后，读取硬件 LOAD_CHECKSUM 寄存器并与 `expected_checksum` 比对。不匹配返回 `INTERNAL()`。

### 4.2 `execute_and_check_insns()`

```c
static status_t execute_and_check_insns(
    dif_otbn_t *otbn,
    uint32_t    expected_insns
);
```

执行 OTBN 并等待完成，读取指令计数器与 `expected_insns` 比对。`expected_insns=0` 跳过检查。

### 4.3 `write_and_verify()`

```c
static status_t write_and_verify(
    dif_otbn_t    *otbn,
    size_t         len_bytes,
    const void    *src,
    otbn_addr_t    dest
);
```

写入 DMEM 后立即回读并逐字节比对。不匹配返回 `INTERNAL()`。使用后清零回读缓冲区。

### 4.4 `wait_for_done_resilient()`

```c
static status_t wait_for_done_resilient(
    dif_otbn_t          *otbn,
    dif_otbn_err_bits_t  expected_err_bits
);
```

轮询 OTBN 状态。检测到 LOCKED 状态时尝试通过 DMEM+IMEM wipe 恢复，并返回 `INTERNAL()`。正常完成时验证错误位是否符合预期。

### 4.5 `otbn_full_sec_wipe()`

```c
static status_t otbn_full_sec_wipe(dif_otbn_t *otbn);
```

依次发出 DMEM 和 IMEM 安全擦除命令，各自等待 IDLE。

### 4.6 `memwipe()`

```c
static void memwipe(void *p, size_t n);
```

通过 `volatile uint8_t*` 逐字节清零，编译器不可优化。用于清除栈上的敏感密钥材料。

---

## 五、OTBN 汇编接口（hkdf_sha3_256.s）

### 5.1 全局入口

| 标签 | 类型 | 说明 |
|------|------|------|
| `main` | 入口点 | 读取 DMEM 输入参数 → construct_ikm → HMAC(salt, IKM) → HKDF-Expand → 写入 OKM → 安全擦除 → ecall |
| `hmac_sha3_256` | 子程序 | HMAC-SHA3-256(key_ptr, key_len, msg_ptr, msg_len, out_ptr) |
| `construct_ikm` | 子程序 | 将 ss_e, ss_m, ctx, sid, role 及长度前缀拼接为 IKM |
| `memcpy_bytes` | 子程序 | 字节级内存拷贝（支持非对齐地址） |

### 5.2 DMEM 输入符号（由 Ibex 写入）

| 符号 | DMEM 偏移 | 大小 | 说明 |
|------|----------|------|------|
| `input_salt` | 0x000 | 32B | HKDF salt |
| `input_ss_e` | 0x020 | 32B | P-256 共享密钥 |
| `input_ss_m` | 0x040 | 32B | ML-KEM 共享密钥 |
| `input_ctx_len` | 0x060 | 4B | ctx 长度（u32 LE） |
| `input_sid_len` | 0x064 | 4B | sid 长度 |
| `input_role_len` | 0x068 | 4B | role 长度 |
| `input_okm_len` | 0x06C | 4B | OKM 输出长度 |
| `input_ctx` | 0x070 | 128B | ctx 字节 |
| `input_sid` | 0x0F0 | 128B | sid 字节 |
| `input_role` | 0x170 | 16B | role 字符串 |

### 5.3 DMEM 输出符号（由 Ibex 读取）

| 符号 | DMEM 偏移 | 大小 | 说明 |
|------|----------|------|------|
| `output_okm` | 0x720 | 256B | 派生密钥材料（实际有效长度为 okm_len） |

---

## 六、OTBN 汇编接口（ML-KEM 模块）

### 6.1 mlkem768 (合并目录, 三阶段共享)

所有 ML-KEM-768 汇编文件位于 `otbn/mlkem768/`。三阶段共用 `basemul.s`, `cbd.s`, `intt.s`, `kmac_sha3_template.s`, `ntt.s`, `pack_keys.s`, `poly.s`, `poly_gen_matrix.s` 共 8 个库文件。`pack_ciphertext.s` 使用 encap 的 SIMD 向量版（性能更优，decap 也使用此版）。

| 符号 | 所属文件 | 说明 | 方向 |
|------|---------|------|------|
| `coins` | mlkem_base_keypair_test.s | 64B 随机数 | Ibex→OTBN |
| `ek` | mlkem_base_keypair_test.s | 1184B 公钥 | OTBN→Ibex |
| `dk` | mlkem_base_keypair_test.s | 2400B 私钥 | OTBN→Ibex |

**encap 阶段:**
| 符号 | 所属文件 | 说明 | 方向 |
|------|---------|------|------|
| `ek` | mlkem_base_encap_test.s | 1184B 公钥 | Ibex→OTBN |
| `coins` | mlkem_base_encap_test.s | 32B 随机数 | Ibex→OTBN |
| `ct` | mlkem_base_encap_test.s | 1088B 密文 | OTBN→Ibex |
| `ss` | mlkem_base_encap_test.s | 32B 共享密钥 | OTBN→Ibex |

**decap 阶段:**
| 符号 | 所属文件 | 说明 | 方向 |
|------|---------|------|------|
| `dk` | mlkem_base_decap_test.s | 2400B 私钥 | Ibex→OTBN |
| `ct` | mlkem_base_decap_test.s | 1088B 密文 | Ibex→OTBN |
| `ss` | mlkem_base_decap_test.s | 32B 共享密钥 | OTBN→Ibex |

### 6.2 p256_ecdh

| 符号 | 说明 | 方向 |
|------|------|------|
| `d0` | 64B 标量算术份额 0 | Ibex → OTBN |
| `d1` | 64B 标量算术份额 1 | Ibex → OTBN |
| `x` | 32B 输入点 x / 输出布尔份额 0 | 双向 |
| `y` | 32B 输入点 y / 输出布尔份额 1 | 双向 |

---

## 七、构建系统符号命名规则

构建流水线（`util/otbn_build.py`）自动为每个 `.globl` 标签生成 Ibex 侧符号：

```
OTBN 汇编标签:    coins  (在 mlkem768_keypair 应用中)
Ibex 侧地址符号:  _otbn_remote_app_mlkem768_keypair_coins
Ibex 侧指针符号:  _otbn_local_app_mlkem768_keypair_coins
checksum 符号:    _otbn_remote_app_mlkem768_keypair_checksum
```

C 代码中使用宏简化：
```c
OTBN_DECLARE_SYMBOL_ADDR(mlkem768_keypair, coins);
static const otbn_addr_t kAddr = OTBN_ADDR_T_INIT(mlkem768_keypair, coins);
// kAddr 的值 = OTBN DMEM 中 coins 标签的地址
```

**所有 DMEM 地址均通过此机制获取，代码中不存在硬编码数值偏移。**
