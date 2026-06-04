# Hybrid KEM — Phase 1 & 2 详细流程图

## 〇、密钥角色说明

```
Phase 1 (Bob 离线): 生成长期密钥对
  P-256:   d_bob (长期私钥) → Q_bob = d_bob * G (长期公钥)
  ML-KEM:  pk_m, sk_m (长期密钥对)
  公开发布: pk_m, Q_bob

Phase 2 (Alice → Bob 在线): 密钥协商
  Alice 生成: d_alice (临时私钥, 本会话一次性使用)
  Alice 用 Bob 公钥 + 自己临时私钥 → ss_e → OKM
  Alice 发送: Q_alice (临时公钥), ct_m

  Bob 用自己的长期私钥 + Alice 临时公钥 → ss_e → OKM

  会话结束后 Alice 丢弃 d_alice → 前向安全性
```

> **为什么 Phase 2 还要生成密钥？**
> Phase 1 生成的是 Bob 的**长期密钥**（可多次使用），Phase 2 Alice 生成的是**临时密钥**（ephemeral，仅本会话使用一次）。
> 这是 ECDH 的标准设计——Alice 每会话生成一次性密钥对，提供**前向安全性 (Forward Secrecy)**：
> 即使 Bob 长期私钥事后泄露，历史会话密钥也无法恢复（因为 Alice 的临时私钥会话结束后已丢弃）。
> 当前测试用 `d_alice = d_bob + 1` 仅为 KAT 确定性，生产代码使用真随机数。

## Phase 1: 密钥生成 (Bob 离线执行)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Phase 1: Hybrid KeyGen (Bob)                         │
│                                                                             │
│  Step 1: P-256 ECDH                                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: p256_ecdh_shared_key                                     │  │
│  │                                                                        │  │
│  │ Ibex → OTBN (DMEM write):                                             │  │
│  │   d0[64B]  = kInputD0       ← Bob 私钥 (320-bit 份额, 上64位=0)       │  │
│  │   d1[64B]  = {0}            ← 第二份额 (全零=无掩码)                   │  │
│  │   x[32B]   = kInputGx       ← P-256 基点 G.x                          │  │
│  │   y[32B]   = kInputGy       ← P-256 基点 G.y                          │  │
│  │                                                                        │  │
│  │ OTBN 执行:                                                             │  │
│  │   p256_shared_key(d, G)                                                │  │
│  │     → scalar_mult_int(d, G)  标量乘 (321次 double-and-add)             │  │
│  │     → proj_to_affine         投影→仿射                                 │  │
│  │     → A2B 掩码转换           算术→布尔掩码 (Goubin)                     │  │
│  │                                                                        │  │
│  │ OTBN → Ibex (DMEM read):                                              │  │
│  │   x[32B]   ← x0              布尔份额 0                                │  │
│  │   y[32B]   ← x1              布尔份额 1                                │  │
│  │                                                                        │  │
│  │ Ibex: ss_e = x0 XOR x1  (32B) ← 共享密钥 = Q.x = d*G.x                │  │
│  │                                                                        │  │
│  │ CHECK: ss_e == kExpectedSsE    (0x4a67a980...)                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 2: ML-KEM-768 KeyGen                                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: mlkem768_keypair                                          │  │
│  │                                                                        │  │
│  │ Ibex → OTBN:                                                           │  │
│  │   coins[64B] = kInputCoinsKp  ← 随机数种子                             │  │
│  │                                                                        │  │
│  │ OTBN → Ibex:                                                           │  │
│  │   ek[1184B] ← pk_m             ML-KEM 公钥                             │  │
│  │   dk[2400B] ← sk_m             ML-KEM 私钥                             │  │
│  │                                                                        │  │
│  │ CHECK: pk_m == kExpectedPkM   (1184B)                                  │  │
│  │ CHECK: sk_m == kExpectedSkM   (2400B)                                  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 3: 组合输出                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ PK_Hyb = pk_m[1184B] || ss_e[32B]  = 1216B   (混合公钥)               │  │
│  │ SK_Hyb = sk_m[2400B] || d0[32B]    = 2432B   (混合私钥)               │  │
│  │                                                                        │  │
│  │ kInputD0[0:32] = 0x71,0x10,0x6d,0xfe,...0x41,0xfc,0x20,0x14           │  │
│  │   d = 0x1420fc41742102631b76ebe83fdfa3799590ef5db0b2c78121d0a016fe6d1071│  │
│  │                                                                        │  │
│  │ Q = d*G = (Q.x, Q.y)                                                   │  │
│  │   Q.x = 0x815215ad7dd27f336b35843cbe064de299504edd0c7d87dd1147ea5680a9674a│  │
│  │   Q.y = 0xa6d026ab03f4ff9f3d9f02fbe4e034ccefbebedfd059e3e809a8644b4999bc84│  │
│  │                                                                        │  │
│  │ ss_e = Q.x  (共享密钥 = 公钥 X 坐标)                                   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1 数据流汇总

| 步骤 | OTBN 二进制 | 输入 | 输出 | 验证 |
|------|------|------|------|------|
| P-256 ECDH | `p256_ecdh_shared_key` | d0[64], d1[64], Gx[32], Gy[32] | x0[32], x1[32] | `ss_e = x0^x1 == kExpectedSsE` |
| ML-KEM KeyGen | `mlkem768_keypair` | coins[64] | pk_m[1184], sk_m[2400] | `== kExpectedPkM`, `== kExpectedSkM` |
| 组合 | — | pk_m, ss_e | PK_Hyb[1216], SK_Hyb[2432] | — |

---

## Phase 2: 密钥协商 (Alice ↔ Bob)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Phase 2: Hybrid Encaps (Alice)                            │
│                                                                             │
│  Step 1: ML-KEM-768 Encap                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: mlkem768_encap                                            │  │
│  │                                                                        │  │
│  │ Ibex → OTBN:                                                           │  │
│  │   coins[32B] = kAliceCoins    ← Alice 随机数                           │  │
│  │   ek[1184B]  = kPkM_Bob       ← Bob ML-KEM 公钥 (Phase 1 输出)        │  │
│  │                                                                        │  │
│  │ OTBN → Ibex:                                                           │  │
│  │   ct[1088B]  ← ct_m            ML-KEM 密文                             │  │
│  │   ss[32B]    ← ss_m            ML-KEM 共享密钥                         │  │
│  │                                                                        │  │
│  │ CHECK: ct_m == kExpectedCtM   (1088B)                                  │  │
│  │ CHECK: ss_m == kExpectedSsM   (32B)                                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 2: P-256 ECDH                                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: p256_ecdh_shared_key                                     │  │
│  │                                                                        │  │
│  │ Ibex → OTBN:                                                           │  │
│  │   d0[64B] = kSkE_Alice_D0    ← Alice 临时私钥 d_alice                  │  │
│  │   d1[64B] = {0}                                                        │  │
│  │   x[32B]  = kPkE_Bob_X       ← Bob P-256公钥.x (Phase 1输出)          │  │
│  │   y[32B]  = kPkE_Bob_Y       ← Bob P-256公钥.y                        │  │
│  │                                                                        │  │
│  │ OTBN 执行:                                                             │  │
│  │   p256_shared_key(d_alice, Q_bob) → d_alice * Q_bob                    │  │
│  │                                                                        │  │
│  │ OTBN → Ibex:                                                           │  │
│  │   x[32B] ← x0, y[32B] ← x1                                            │  │
│  │                                                                        │  │
│  │ Ibex: ss_e = x0 XOR x1  (32B)                                          │  │
│  │ CHECK: ss_e == kExpectedSsE    (0x064cf1e6...)                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 3: HKDF-SHA3-256                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: hkdf_sha3_256                                             │  │
│  │                                                                        │  │
│  │ IKM = be16(32) || ss_e(32B) || be16(32) || ss_m(32B)                  │  │
│  │      = 0x0020 || ss_e || 0x0020 || ss_m    (68B, ctx=sid="")          │  │
│  │                                                                        │  │
│  │ Extract:  PRK = HMAC-SHA3-256(salt=0x00*32, IKM)                      │  │
│  │ Expand:   OKM = HKDF-Expand(PRK, info="", L=32)                       │  │
│  │                                                                        │  │
│  │ OKM = 0x1960caa28eabc2d553d8edaf9d7b8c6f...                            │  │
│  │                                                                        │  │
│  │ CHECK: OKM == kExpectedOkm    (32B)                                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  输出: ct_m[1088B], OKM[32B]  (Alice 发送 ct_m 给 Bob)                     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                     Phase 2: Hybrid Decaps (Bob)                             │
│                                                                             │
│  Step 1: ML-KEM-768 Decap                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: mlkem768_decap                                            │  │
│  │                                                                        │  │
│  │ Ibex → OTBN:                                                           │  │
│  │   ct[1088B] = kCtM             ← Alice 发来的密文                       │  │
│  │   dk[2400B] = kSkM_Bob         ← Bob ML-KEM 私钥 (Phase 1 输出)        │  │
│  │                                                                        │  │
│  │ OTBN → Ibex:                                                           │  │
│  │   ss[32B] ← ss_m                ML-KEM 共享密钥                         │  │
│  │                                                                        │  │
│  │ CHECK: ss_m == kExpectedSsM    (32B, 应与 Alice ss_m 一致)             │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 2: P-256 ECDH                                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: p256_ecdh_shared_key                                     │  │
│  │                                                                        │  │
│  │ Ibex → OTBN:                                                           │  │
│  │   d0[64B] = kSkE_Bob_D0       ← Bob 私钥 d_bob (Phase 1)              │  │
│  │   d1[64B] = {0}                                                        │  │
│  │   x[32B]  = kEk_Alice_X       ← Alice 临时公钥.x                       │  │
│  │   y[32B]  = kEk_Alice_Y       ← Alice 临时公钥.y                       │  │
│  │                                                                        │  │
│  │ OTBN 执行:                                                             │  │
│  │   p256_shared_key(d_bob, Q_alice) → d_bob * Q_alice                    │  │
│  │                                                                        │  │
│  │ Ibex: ss_e = x0 XOR x1  (32B)                                          │  │
│  │ CHECK: ss_e == kExpectedSsE    (0x064cf1e6..., 与 Alice 一致)          │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ↓                                              │
│  Step 3: HKDF-SHA3-256                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ OTBN binary: hkdf_sha3_256                                             │  │
│  │                                                                        │  │
│  │ IKM = be16(32) || ss_e(32B) || be16(32) || ss_m(32B)  (与 Alice 相同) │  │
│  │                                                                        │  │
│  │ Extract:  PRK = HMAC-SHA3-256(salt=0x00*32, IKM)                      │  │
│  │ Expand:   OKM = HKDF-Expand(PRK, info="", L=32)                       │  │
│  │                                                                        │  │
│  │ CHECK: OKM == kExpectedOkm     (32B, 应与 Alice OKM 一致)              │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  KEM 正确性:                                                                │
│    ss_e(Alice) == ss_e(Bob)  ✅  (d_alice*Q_bob == d_bob*Q_alice)          │
│    ss_m(Alice) == ss_m(Bob)  ✅  (ML-KEM decap 恢复正确)                    │
│    OKM(Alice)  == OKM(Bob)   ✅  (相同 IKM, info="")                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 2 数据流汇总

| 步骤 | Alice 二进制 | Alice 输入 → 输出 | Bob 二进制 | Bob 输入 → 输出 |
|------|------|------|------|------|
| ML-KEM | `mlkem768_encap` | coins[32] + pk_m[1184] → ct_m[1088], ss_m[32] | `mlkem768_decap` | ct_m[1088] + sk_m[2400] → ss_m[32] |
| P-256 | `p256_ecdh_shared_key` | d_alice[64] + Q_bob[64] → ss_e[32] | `p256_ecdh_shared_key` | d_bob[64] + Q_alice[64] → ss_e[32] |
| HKDF | `hkdf_sha3_256` | ss_e[32] + ss_m[32] + info="" → OKM[32] | `hkdf_sha3_256` | ss_e[32] + ss_m[32] + info="" → OKM[32] |

### 密钥关系

```
Bob 密钥对:
  d_bob  = 0x1420fc41...6d1071
  Q_bob  = d_bob * G  = (0x815215ad..., 0xa6d026ab...)

Alice 临时密钥对:
  d_alice = 0x1420fc41...6d1072  (= d_bob + 1)
  Q_alice = d_alice * G = (0xae2e89b1..., 0x0e5279a1...)

ECDH:
  Alice: d_alice * Q_bob = (0x26991c9a..., ...) → ss_e = 0x26991c9a... (x坐标)
  Bob:   d_bob * Q_alice = (0x26991c9a..., ...) → ss_e = 0x26991c9a... (x坐标)
  ✓ 一致

HKDF:
  IKM = 0020 || ss_e || 0020 || ss_m  (68B)
  PRK = 0xc8c68efff8c6de2f1b3f18136cf329ba0c55cf4b38fb46b1f378d268513bd331
  OKM = 0x1960caa28eabc2d553d8edaf9d7b8c6f54d428107badeb69c61dd8d12fd677a5
  Alice == Bob ✓
```
