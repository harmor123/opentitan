# 使用文档

## 零、构建

### ISS

```bash
bazel test //test_hybrid_kem_paper/otbn/test:p256_ecdh_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:hkdf_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_keypair_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_encap_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_decap_test --test_output=errors
```

### Chip Sim

```bash
# 通用参数
CHIP_SIM_OPTS="--test_timeout=2000 --cache_test_results=no \
    --sandbox_writable_path=/run/user/1000/ccache-tmp --test_output=streamed"

# 单模块
bazel test //test_hybrid_kem_paper:test_p256_only_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
bazel test //test_hybrid_kem_paper:test_hkdf_only_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
bazel test //test_hybrid_kem_paper:test_mlkem_keypair_only_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
bazel test //test_hybrid_kem_paper:test_mlkem_encap_only_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
bazel test //test_hybrid_kem_paper:test_mlkem_decap_only_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"

# Phase 1
bazel test //test_hybrid_kem_paper:phase1_keygen_test_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"

# Phase 2
bazel test //test_hybrid_kem_paper:phase2_alice_encap_test_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
bazel test //test_hybrid_kem_paper:phase2_bob_decap_test_sim_verilator $CHIP_SIM_OPTS 2>&1 | grep -E "(I000|CHECK|PASS|FAIL|ERROR)"
```

---

## 一、Phase 1: 密钥生成 (Bob 离线)

源码: `ibex/phase1_keygen/phase1_keygen_test.c`

### Step 1: P-256 ECDH — 共享密钥

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/p256:p256_ecdh_shared_key` |
| 函数 | `p256_shared_key(d, G)` |
| 输入 `d0[64]` | Bob 私钥 `kInputD0`, 320-bit 份额, 上 64 位 = 0 |
| 输入 `d1[64]` | `{0}`, 第二份额 (无掩码) |
| 输入 `x[32]` | P-256 基点 G.x: `kInputGx` |
| 输入 `y[32]` | P-256 基点 G.y: `kInputGy` |
| OTBN 执行 | 标量乘 d*G → A2B 掩码转换 |
| 输出 `x[32]` | 布尔份额 x0 |
| 输出 `y[32]` | 布尔份额 x1 |
| **Ibex 后处理** | `ss_e = x0 XOR x1` (32B) |
| 验证 | `CHECK_ARRAYS_EQ(ss_e, kExpectedSsE)` |

### Step 2: ML-KEM-768 KeyGen — 密钥对

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/mlkem768:mlkem768_keypair` |
| 输入 `coins[64]` | `kInputCoinsKp`, 随机种子 |
| 输出 `ek[1184]` | `pk_m`, ML-KEM 公钥 |
| 输出 `dk[2400]` | `sk_m`, ML-KEM 私钥 |
| 验证 | `CHECK_ARRAYS_EQ(pk_m, kExpectedPkM)` |
| 验证 | `CHECK_ARRAYS_EQ(sk_m, kExpectedSkM)` |

### 输出

```
PK_Hyb = pk_m[1184] || ss_e[32]    (混合公钥, 1216B)
SK_Hyb = sk_m[2400] || d0[32]      (混合私钥, 2432B)
```

> **注意**: 每个 OTBN 二进制加载前执行 `SecWipeDmem + wait`，清除前序模块的 KMAC/大数 ALU 状态。Phase 1/2 每步之间都按此模式。

---

## 二、Phase 2: 密钥协商 (Alice ↔ Bob 在线)

源码: `ibex/phase2_encap_decap/`

### 2.1 Alice — 封装 (`phase2_alice_encap.c`)

#### Step 1: P-256 ECDH → ss_e

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/p256:p256_ecdh_shared_key` |
| 函数 | `p256_shared_key(d_alice, Q_bob)` |
| 输入 `d0[64]` | Alice **临时**私钥 `kSkE_Alice_D0` (ephemeral, 前向安全性) |
| 输入 `d1[64]` | `{0}` |
| 输入 `x[32]` | Bob P-256 公钥.x: `kPkE_Bob_X` (Phase 1 产出) |
| 输入 `y[32]` | Bob P-256 公钥.y: `kPkE_Bob_Y` |
| 输出 `x0, x1` | 布尔份额 |
| **Ibex** | `ss_e = x0 XOR x1` (32B) |
| 验证 | `CHECK_ARRAYS_EQ(ss_e, kExpectedSsE)` |

#### Step 2: ML-KEM-768 Encap → ct_m, ss_m

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/mlkem768:mlkem768_encap` |
| 输入 `coins[32]` | `kAliceCoins`, Alice 随机数 |
| 输入 `ek[1184]` | `kPkM_Bob`, Bob ML-KEM 公钥 (Phase 1 产出) |
| 输出 `ct[1088]` | `ct_m`, ML-KEM 密文 |
| 输出 `ss[32]` | `ss_m`, ML-KEM 共享密钥 |
| 验证 | `CHECK_ARRAYS_EQ(ct_m, kExpectedCtM)` |
| 验证 | `CHECK_ARRAYS_EQ(ss_m, kExpectedSsM)` |

#### Step 3: HKDF-SHA3-256 → OKM

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/hkdf:hkdf_sha3_256` |
| 输入 `input_salt[32]` | `kSalt` (全零) |
| 输入 `ikm_prebuilt` | IKM = `be16(32) \|\| ss_e \|\| be16(32) \|\| ss_m \|\| kCtx \|\| kSid` (132B) |
| 输入 `input_info[16]` | `kInfo` (全零, info="") |
| 输入 `input_lengths` | `{32, 32, 16, 32}` = `sizeof(kCtx), sizeof(kSid), sizeof(kInfo), sizeof(kExpectedOkm)` |
| Extract | PRK = HMAC-SHA3-256(salt, IKM) |
| Expand | OKM = HKDF-Expand(PRK, info="", 32) |
| 输出 `output_okm[32]` | OKM |
| 验证 | `CHECK_ARRAYS_EQ(okm, kExpectedOkm)` |

#### Alice 输出

```
ct_m[1088]  → 发送给 Bob
OKM[32]     → 共享密钥 (KEM 输出)
```

---

### 2.2 Bob — 解封装 (`phase2_bob_decap.c`)

#### Step 1: ML-KEM-768 Decap → ss_m

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/mlkem768:mlkem768_decap` |
| 输入 `ct[1088]` | `kCtM`, Alice 发来的密文 |
| 输入 `dk[2400]` | `kSkM_Bob`, Bob ML-KEM 私钥 (Phase 1 产出) |
| 输出 `ss[32]` | `ss_m` |
| 验证 | `CHECK_ARRAYS_EQ(ss_m, kExpectedSsM)` |

#### Step 2: P-256 ECDH → ss_e

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/p256:p256_ecdh_shared_key` |
| 函数 | `p256_shared_key(d_bob, Q_alice)` |
| 输入 `d0[64]` | Bob **长期**私钥 `kSkE_Bob_D0` (Phase 1) |
| 输入 `d1[64]` | `{0}` |
| 输入 `x[32]` | Alice 临时公钥.x: `kEk_Alice_X` |
| 输入 `y[32]` | Alice 临时公钥.y: `kEk_Alice_Y` |
| 输出 `x0, x1` | 布尔份额 |
| **Ibex** | `ss_e = x0 XOR x1` (32B) |
| 验证 | `CHECK_ARRAYS_EQ(ss_e, kExpectedSsE)` |

#### Step 3: HKDF-SHA3-256 → OKM

| 项目 | 说明 |
|------|------|
| OTBN 二进制 | `//test_hybrid_kem_paper/otbn/hkdf:hkdf_sha3_256` |
| IKM | 与 Alice 完全相同 (相同 ss_e, ss_m, ctx, sid) |
| info | 与 Alice 完全相同 (info="") |
| 验证 | `CHECK_ARRAYS_EQ(okm, kExpectedOkm)` (应与 Alice OKM 相同) |

#### KEM 正确性

```
ss_e_alice == ss_e_bob  (d_alice * Q_bob == d_bob * Q_alice)
ss_m_alice == ss_m_bob  (ML-KEM 正确性)
OKM_alice == OKM_bob    (相同 IKM + info)
```

---

## 三、KAT 生成

```bash
# Phase 1
python3 ref/phase1/p256_kat.py        # P-256: d → Q.x/Q.y + ss_e
python3 ref/phase1/gen_kat.py         # ML-KEM keypair: .dexp → C 数组

# Phase 2
python3 ref/phase2/hkdf_kat_alice.py 32  # Alice HKDF: ss_e+ss_m → OKM
python3 ref/phase2/hkdf_kat_bob.py 32    # Bob HKDF:   ss_e+ss_m → OKM (== Alice)

# 通用工具
python3 ref/hkdf_kat.py 32    # HKDF: 通用 C 数组 (可自定义参数)
python3 ref/hkdf_dexp.py 32   # HKDF: .dexp + .s 数据段
```

## 四、HKDF 参数

| 参数 | 测试值 | sizeof | 说明 |
|------|------|------|------|
| salt | `{0}*32` | 32B | 全零 |
| IKM | `be16(32)\|\|ss_e\|\|be16(32)\|\|ss_m\|\|ctx\|\|sid` | 132B | role 不放入 |
| info | `{0}*16` | 16B | KEM 层 info="" |
| ctx | `{0}*32` | 32B | 上层上下文 |
| sid | `{0}*32` | 32B | 会话 ID |
| OKM | — | 32B | KEM 统一输出 |
