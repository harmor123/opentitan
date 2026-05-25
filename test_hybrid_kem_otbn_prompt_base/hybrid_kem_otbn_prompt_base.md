# OpenTitan 混合 KEM 纯软件基线实现 (ver0_base)

## 项目定位

本目录 (`test_hybrid_kem_otbn_prompt_base`) 是混合 KEM (ML-KEM-768 + P-256 ECDH + HKDF-SHA3-256) 的**纯软件基线版本**。

与参考实现 `test_hybrid_kem_otbn_prompt`（使用 KMAC 硬件 + BN 向量扩展）不同，本版本：

- 使用**纯软件 Keccak-f[1600]** 实现全部 SHA-3 运算
- 使用**基线 OTBN 指令集**（无 BN 向量扩展）
- **无需任何 RTL 修改**
- **作为硬件加速版本的性能对比基准**

---

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│                    OpenTitan SoC                        │
│                                                         │
│  ┌───────────┐         ┌─────────────────────────────┐ │
│  │   Ibex    │  DIF    │          OTBN               │ │
│  │  (RV32)   │◄───────►│                             │ │
│  │           │         │  ML-KEM-768 (纯软件 SHA3)    │ │
│  │ 调度/搬移 │         │  P-256 ECDH                 │ │
│  │ 数据组装  │         │  HKDF-SHA3-256 (软件 HMAC)  │ │
│  │ 性能测量  │         │                             │ │
│  └───────────┘         │  [KMAC 硬件: 不使用]        │ │
│                        └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## 密码学组件

| 组件 | 实现方式 | 来源 |
|------|---------|------|
| ML-KEM-768 KeyGen | 纯软件 SHA3 + 基线 OTBN 指令 | `kyber_ver0_base/mlkem768_keypair_ver0` |
| ML-KEM-768 Encap | 纯软件 SHA3 + 基线 OTBN 指令 | `kyber_ver0_base/mlkem768_encap_ver0` |
| ML-KEM-768 Decap | 纯软件 SHA3 + 基线 OTBN 指令 | `kyber_ver0_base/mlkem768_decap_ver0` |
| P-256 ECDH | OTBN 官方实现 | `kyber_ver0_base/p256_shared_keys` |
| HMAC-SHA3-256 | 软件 `sha3_init`/`update`/`final` | 本目录新增 |
| HKDF-SHA3-256 | DMEM 接口 + 软件 HMAC | 本目录新增 |
| Keccak-f[1600] | 256-bit WDR 向量化 | `kyber_ver0_base/hash/sha3_shake.s` |

---

## 数据流

### Phase 1: KeyGen (Bob 离线)

```
ML-KEM-768 KeyGen → pk_m(1184B), sk_m(2400B)
    ↓ wipe
P-256 KeyGen (d*G) → pk_e(64B), sk_e(32B)
    ↓ wipe
PK_Hyb = pk_m || pk_e  (1248B)
SK_Hyb = sk_m || sk_e  (2432B)
```

### Phase 2.1: Encaps (Alice)

```
P-256 ECDH (d_eph * G) → ek(64B)
    ↓ wipe
P-256 ECDH (d_eph * pk_e_bob) → ss_e(32B)
    ↓ wipe
ML-KEM-768 Encap(pk_m_bob) → ct_m(1088B), ss_m(32B)
    ↓ wipe
CT_Hyb = ek || ct_m  (1152B)
    ↓
HKDF-Extract(salt, IKM) → PRK
HKDF-Expand(PRK, L) → OKM  (role="initiator")
    ↓ wipe
```

### Phase 2.2: Decaps (Bob)

```
拆分: ek = CT_Hyb[0:64], ct_m = CT_Hyb[64:1152]
      sk_e = SK_Hyb[2400:2432], sk_m = SK_Hyb[0:2400]
    ↓
P-256 ECDH (sk_e * ek) → ss_e(32B)
    ↓ wipe
ML-KEM-768 Decap(sk_m, ct_m) → ss_m(32B)
    ↓ wipe
HKDF-Extract(salt, IKM) → PRK
HKDF-Expand(PRK, L) → OKM  (role="responder")
    ↓ wipe
```

---

## IKM 构造规范

```
len_cls(2B BE) || ss_e(32B) || len_pqc(2B BE) || ss_m(32B) || ctx || sid || role
```

- `len_cls` = 0x0020 (32 大端)
- `len_pqc` = 0x0020 (32 大端)
- `role` = "initiator" (Alice) 或 "responder" (Bob)

---

## 性能度量

基线版内置 `mcycle` 性能计数器，每次执行输出：

| 度量项 | 说明 |
|--------|------|
| Total Cycles | 阶段总周期数 |
| OTBN ML-KEM Cycles | ML-KEM 运算周期 |
| OTBN P-256 Cycles | P-256 ECDH 周期 |
| OTBN HKDF Cycles | HKDF 派生周期 |
| OTBN Wipe Cycles | 安全擦除开销 |
| OTBN Call Count | `otbn_execute()` 调用次数 |
| DMEM Write Bytes | 写入 OTBN DMEM 总字节数 |
| DMEM Read Bytes | 从 OTBN DMEM 读取总字节数 |
| OTBN Wipe Count | 安全擦除执行次数 |

---

## 使用

```bash
# 构建所有 OTBN 二进制
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/...

# 功能测试
bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_test_sim_verilator

# 生产模式
bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_prod_sim_verilator
```

详见 [USAGE.md](USAGE.md)、[API.md](API.md)。
