#  OpenTitan OTBN 混合密钥协商
你是一个资深的硬件安全与密码学工程专家，精通：
- **OpenTitan 架构**：Ibex RV32IMC 主核、OTBN 大数协处理器
- **OTBN 汇编**：256-bit 宽寄存器、CSR/WSR 访问硬件、DMEM/IMEM 管理
- **密码学算法**：ML-KEM-768、P-256、HMAC-SHA3-256、HKDF-SHA3-256
- **安全工程**：侧信道防御、安全擦除、常数时间实现
你的任务是为我设计并实现基于 OTBN 的 ML-KEM-768 + P-256 混合密钥协商系统。所有密码学运算（包括 KMAC/SHA3）均在 OTBN 内部完成，Ibex 仅负责调度和数据搬移。
---
## 1. 项目背景与硬件架构
### 1.1 核心架构
```text
┌─────────────────────────────────────────────────────────┐
│                    OpenTitan SoC                        │
│                                                         │
│  ┌───────────┐         ┌─────────────────────────────┐ │
│  │   Ibex    │  DIF    │          OTBN               │ │
│  │  (RV32)   │◄───────►│                             │ │
│  │           │         │  ML-KEM-768 汇编             │ │
│  │ 调度/搬移 │         │  P-256 汇编                 │ │
│  │ 数据组装  │         │  KMAC/SHA3 汇编 (已有)       │ │
│  │ 结果验证  │         │  HKDF 汇编 (待实现)         │ │
│  └───────────┘         │         │                    │ │
│                        │         ▼                    │ │
│                        │  KMAC 硬件 (OTBN内部CSR访问) │ │
│                        └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```
**关键**：KMAC 硬件已集成到 OTBN 内部，通过 CSR/WSR 寄存器访问，**Ibex 不直接访问 KMAC**。

### 1.2 已有 OTBN 汇编模块
```text
kyber_ver2/
├── mlkem768_keypair_ver2/       # ML-KEM-768 密钥生成 → pk_m(1184B), sk_m(2400B)
├── mlkem768_encap_ver2/         # ML-KEM-768 封装   ← pk_m → ct_m(1088B), ss_m(32B)
├── mlkem768_decap_ver2/         # ML-KEM-768 解封装 ← sk_m, ct_m → ss_m(32B)
├── p256_shared_keys/            # P-256 ECDH       ← sk_e(32B), pk_peer(64B) → ss_e(32B)
└── hash/                        # (已弃用，SHA3已集成到ML-KEM内部)
hmac+hkdf
```
### 1.3 KMAC 汇编接口
KMAC 操作子程序已在 `kmac_sha3_template.s` 中实现，提供以下接口：
| 子程序                | 功能                       | 接口                                                      |
| :-------------------- | :------------------------- | :-------------------------------------------------------- |
| `kmac_init`           | 初始化 KMAC，进入 Absorb   | x10=mode (0=SHA3-256, 1=SHA3-512, 2=SHAKE128, 3=SHAKE256) |
| `keccak_send_message` | 发送可变长度消息           | x10=msg_ptr, x11=byte_len                                 |
| `kmac_process`        | 结束 Absorb，执行 Keccak-f | 无输入                                                    |
| `kmac_squeeze_32B`    | 挤出 32B 摘要到 DMEM       | x10=out_ptr                                               |
| `kmac_run`            | SHAKE 额外轮次             | 无输入                                                    |
| `kmac_done`           | 释放 KMAC 引擎             | 无输入                                                    |
> **详细寄存器定义、CSR 地址、命令编码、实现细节请直接阅读 `kmac_sha3_template.s` 源码。**
### 1.4 硬件约束
- OTBN DMEM ~127KB，**需要合理配置**
- 每次模块运行结束后 **必须** Secure Wipe
- Ibex 通过 `dif_otbn_t` 控制 OTBN 生命周期
---
## 2. 系统阶段划分与完整数据流
### 2.1 阶段一：混合密钥生成（Bob 离线执行）
```text
┌──────────────────────────────────────────────────────────────────┐
│                    Bob: Hybrid KeyGen                            │
│                                                                  │
│  Step 1: ML-KEM-768 KeyGen                                      │
│  ┌─────────────────────────┐                                     │
│  │ Ibex → OTBN:            │                                     │
│  │   load mlkem768_keypair │                                     │
│  │   call                  │                                     │
│  │   get pk_m (1184B)      │                                     │
│  │   get sk_m (2400B)      │                                     │
│  │   secure wipe           │                                     │
│  └─────────────────────────┘                                     │
│           ↓                                                      │
│  Step 2: P-256 KeyGen                                           │
│  ┌─────────────────────────────────────────┐                     │
│  │ Ibex → OTBN:                            │                     │
│  │   load p256_shared_keys                  │                     │
│  │   call (KEYGEN mode)                     │                     │
│  │   get pk_e (64B)                         │                     │
│  │   get sk_e (32B)                         │                     │
│  │   secure wipe                            │                     │
│  └─────────────────────────────────────────┘                     │
│           ↓                                                      │
│  Step 3: 组合输出                                                │
│    PK_Hyb = pk_m || pk_e    (1184 + 64 = 1248 bytes)            │
│    SK_Hyb = sk_m || sk_e    (2400 + 32 = 2432 bytes)            │
│    PK_Hyb → 公开发布；SK_Hyb → 安全存储                         │
└──────────────────────────────────────────────────────────────────┘
```
### 2.2 阶段二：混合密钥协商
#### 2.2.1 Alice — 混合封装 (Encapsulation)
```text
┌──────────────────────────────────────────────────────────────────┐
│                 Alice: Hybrid Encaps                             │
│                                                                  │
│  输入: PK_Hyb (Bob混合公钥), salt, ctx, sid                    │
│                                                                  │
│  Step 1: P-256 ECDH                                             │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load p256_shared_keys             │                     │
│  │ 输入: sk_ee(临时私钥), pk_e_bob(Bob公钥) │                     │
│  │ 输出: ss_e(32B), ek(临时公钥64B)         │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│           ↓                                                      │
│  Step 2: ML-KEM-768 Encaps                                      │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load mlkem768_encap_ver2          │                     │
│  │ 输入: pk_m_bob(Bob公钥, 1184B)           │                     │
│  │ 输出: ct_m(1088B), ss_m(32B)             │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│           ↓                                                      │
│  Step 3: 发送密文                                                │
│    CT_Hyb = ek || ct_m  (64 + 1088 = 1152B) → 发给 Bob          │
│           ↓                                                      │
│  Step 4: HKDF 密钥派生 (OTBN 内部执行)                          │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load hkdf_sha3_256                │                     │
│  │ DMEM输入: ss_e, ss_m, salt, ctx, sid,    │                     │
│  │          role="initiator", 各长度字段     │                     │
│  │ DMEM输出: okm (L字节)                    │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│                                                                  │
│  输出: CT_Hyb(1152B), OKM(L字节)                                │
└──────────────────────────────────────────────────────────────────┘
```
#### 2.2.2 Bob — 混合解封装 (Decapsulation)
```text
┌──────────────────────────────────────────────────────────────────┐
│                 Bob: Hybrid Decaps                               │
│                                                                  │
│  输入: SK_Hyb(Bob混合私钥), CT_Hyb(收到的混合密文),             │
│        salt, ctx, sid                                            │
│                                                                  │
│  Step 1: 拆分输入 (Ibex 侧)                                     │
│    ek   = CT_Hyb[0..63]       (64B, Alice临时P-256公钥)          │
│    ct_m = CT_Hyb[64..1151]    (1088B, ML-KEM密文)               │
│    sk_e = SK_Hyb[2400..2431]  (32B, Bob的P-256私钥)             │
│    sk_m = SK_Hyb[0..2399]     (2400B, Bob的ML-KEM私钥)          │
│           ↓                                                      │
│  Step 2: P-256 ECDH                                             │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load p256_shared_keys             │                     │
│  │ 输入: sk_e(Bob私钥), ek(Alice公钥)       │                     │
│  │ 输出: ss_e(32B)                          │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│           ↓                                                      │
│  Step 3: ML-KEM-768 Decaps                                      │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load mlkem768_decap_ver2          │                     │
│  │ 输入: sk_m(2400B), ct_m(1088B)           │                     │
│  │ 输出: ss_m(32B)                          │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│           ↓                                                      │
│  Step 4: HKDF 密钥派生 (OTBN 内部执行)                          │
│  ┌─────────────────────────────────────────┐                     │
│  │ OTBN ← load hkdf_sha3_256                │                     │
│  │ DMEM输入: ss_e, ss_m, salt, ctx, sid,    │                     │
│  │          role="responder", 各长度字段     │                     │
│  │ DMEM输出: okm (L字节)                    │                     │
│  │ secure wipe                              │                     │
│  └─────────────────────────────────────────┘                     │
│                                                                  │
│  ✓ Alice 和 Bob 得到完全一致的 OKM                              │
└──────────────────────────────────────────────────────────────────┘
```
---
## 3. 密钥派生拼接规范
### 3.1 IKM 构造规则
IKM 必须严格按以下格式构造，长度字段使用 **2 字节大端序**：
```text
┌──────────┬────────────┬──────────┬────────────┬─────┬─────┬──────┐
│ len_cls  │   ss_e     │ len_pqc  │   ss_m     │ ctx │ sid │ role │
│ (2 bytes)│ (32 bytes) │ (2 bytes)│ (32 bytes) │ var │ var │ var  │
│ 大端序    │            │ 大端序    │            │     │     │      │
│ 0x0020   │            │ 0x0020   │            │     │     │      │
└──────────┴────────────┴──────────┴────────────┴─────┴─────┴──────┘
```
| 字段      | 长度 | 值                            | 说明              |
| :-------- | :--- | :---------------------------- | :---------------- |
| `len_cls` | 2B   | `0x0020`                      | ss_e 长度，大端序 |
| `ss_e`    | 32B  | P-256 输出                    | 经典共享密钥      |
| `len_pqc` | 2B   | `0x0020`                      | ss_m 长度，大端序 |
| `ss_m`    | 32B  | ML-KEM 输出                   | 后量子共享密钥    |
| `ctx`     | 可变 | 应用层定义                    | 上下文绑定        |
| `sid`     | 可变 | 协议层生成                    | 会话ID，防重放    |
| `role`    | 可变 | `"initiator"` / `"responder"` | 角色绑定，防反射  |
### 3.2 HKDF-SHA3-256 流程
```text
Step 1: 构造 IKM = len_cls || ss_e || len_pqc || ss_m || ctx || sid || role
Step 2: PRK = HMAC-SHA3-256(salt, IKM)        // 若 salt 为空则 salt = 0x00*32
Step 3: OKM = HKDF-Expand(PRK, info=b"", L)    // info 为空，绑定已编码在 IKM 中
```
HMAC-SHA3-256 标准：B=136, ipad=0x36, opad=0x5C。
---
## 4. OTBN 上下文切换规范
### 4.1 Ibex 调度 OTBN 的生命周期
```text
1. dif_otbn_load_app(otbn, app)          // 加载到 IMEM/DMEM
2. dif_otbn_write_args(otbn, ...)        // 写入输入参数
3. dif_otbn_start(otbn)                  // 启动执行
4. dif_otbn_wait_for_done(otbn)          // 等待完成
5. dif_otbn_get_data(otbn, offset, ...)  // 读出结果
6. dif_otbn_zero_secure_wipe(otbn)       // 安全擦除（每次必须！）
```
### 4.2 各阶段 OTBN 加载序列
| 阶段       | OTBN 加载序列（严格顺序，每次切换间必须 wipe）               |
| :--------- | :----------------------------------------------------------- |
| **KeyGen** | `mlkem768_keypair` → wipe → `p256_keygen` → wipe             |
| **Encaps** | `p256_ecdh` → wipe → `mlkem768_encap` → wipe → `hkdf_sha3_256` → wipe |
| **Decaps** | `p256_ecdh` → wipe → `mlkem768_decap` → wipe → `hkdf_sha3_256` → wipe |
---
## 6. 具体任务要求
### 6.1 编写 Ibex 端 C 语言调度框架
基于 `dif_otbn_t` 接口（**不使用 dif_kmac_t**），实现：
```c
otbn_status_t hybrid_keygen(dif_otbn_t *otbn,
                            uint8_t *pk_hyb,  // 输出 1248B
                            uint8_t *sk_hyb); // 输出 2432B
otbn_status_t hybrid_encaps(dif_otbn_t *otbn,
                            const uint8_t *pk_hyb,    // 输入 1248B
                            const uint8_t *salt,       // 输入 32B
                            const uint8_t *ctx, size_t ctx_len,
                            const uint8_t *sid, size_t sid_len,
                            uint8_t *ct_hyb,           // 输出 1152B
                            uint8_t *okm, size_t okm_len);
otbn_status_t hybrid_decaps(dif_otbn_t *otbn,
                            const uint8_t *sk_hyb,     // 输入 2432B
                            const uint8_t *ct_hyb,     // 输入 1152B
                            const uint8_t *salt,       // 输入 32B
                            const uint8_t *ctx, size_t ctx_len,
                            const uint8_t *sid, size_t sid_len,
                            uint8_t *okm, size_t okm_len);
```
### 6.2 安全要求
| 安全项           | 要求                                                 |
| :--------------- | :--------------------------------------------------- |
| OTBN Secure Wipe | 每次模块运行后 **必须** 调用                         |
| OTBN DMEM 清零   | HKDF 汇编中 IKM/PRK 等工作区返回前用 `bn.xor` 清零   |
| Ibex 栈清零      | ss_e, ss_m 等临时缓冲使用后 `memwipe`                |
| 常数时间         | 解封装失败时仍须执行完整 HKDF 虚假计算               |
| 角色绑定         | Alice=`"initiator"`, Bob=`"responder"`               |
| KMAC 释放        | 每次 HMAC 完成后必须 `kmac_done`，再重新 `kmac_init` |
