# Hybrid KEM Implementation — ML-KEM-768 + P-256 ECDH + HKDF-SHA3-256

基于 OpenTitan Earl Grey 平台，OTBN 协处理器完成全部密码运算，Ibex 负责调度和数据搬移。

## 1. 目录结构

```
test_hybrid_kem_paper/
├── BUILD                          # Ibex 测试目标 (Bazel)
├── README.md                      # 快速参考
├── HYBRID_KEM_FLOW.md             # 验证流程与 KAT 对照
├── HYBRID_KEM_IMPLEMENTATION.md   # 本文档
├── ibex/
│   ├── test_p256_official.c       # P-256 公钥生成 (官方 run_p256)
│   ├── test_p256_only.c           # P-256 ECDH 共享密钥
│   ├── test_mlkem_keypair_only.c  # ML-KEM-768 KeyGen
│   ├── test_mlkem_encap_only.c    # ML-KEM-768 Encap
│   ├── test_mlkem_decap_only.c    # ML-KEM-768 Decap
│   ├── test_hkdf_only.c           # HKDF-SHA3-256
│   ├── hybrid_kem_test.c          # FPGA 端到端测试
│   ├── phase1_keygen/
│   │   └── phase1_keygen_test.c   # Phase 1: P-256 + ML-KEM 密钥生成
│   └── phase2_encap_decap/
│       ├── phase2_alice_encap.c   # Phase 2 Alice: 封装
│       └── phase2_bob_decap.c     # Phase 2 Bob: 解封装
├── otbn/
│   ├── p256/                      # P-256 ECDH 汇编
│   │   ├── BUILD
│   │   ├── p256_base.s            # 标量乘/点加/仿射转换
│   │   ├── p256_isoncurve.s       # 仿射 on-curve 检查
│   │   ├── p256_isoncurve_proj.s  # 投影 on-curve 检查
│   │   ├── p256_shared_key.s      # ECDH 共享密钥 (含 A2B)
│   │   └── mai_hw_driver.s        # MAI 硬件加速器 (保留)
│   ├── mlkem768/                  # ML-KEM-768 汇编 (12 files)
│   ├── hkdf/                      # HKDF-SHA3-256 汇编
│   │   ├── BUILD
│   │   ├── hkdf_sha3_256.s        # Extract + Expand (支持 info)
│   │   ├── hmac_sha3.s            # HMAC-SHA3-256
│   │   └── kmac_sha3_template.s   # KMAC 硬件驱动
│   └── test/                      # ISS 测试 wrapper + .dexp
│       ├── BUILD
│       ├── p256_ecdh_shared_key_test.s
│       ├── p256.dexp
│       ├── hkdf_test.s
│       ├── hkdf_test.dexp
│       └── ... (mlkem test wrappers)
└── ref/                           # Python 参考实现
    ├── p256_kat.py                # P-256 KAT 生成
    ├── hkdf_kat.py                # HKDF KAT 生成 (C数组)
    ├── hkdf_dexp.py               # HKDF .dexp+.s 生成
    └── gen_kat.py                 # ML-KEM .dexp→C数组
```

## 2. 算法流程

### 2.1 Phase 1: 密钥生成 (Bob)

```
1. P-256 ECDH: p256_shared_key(d, G) → ss_e (= Q.x = d*G.x)
   测试: test_p256_only.c  |  输入: kInputD0[64] + Gx/Gy[32]
                            |  输出: ss_e = x0 ^ x1 (32B)
                            |  验证: CHECK_ARRAYS_EQ(ss_e, kExpectedSsE)

2. ML-KEM-768 KeyGen: mlkem768_keypair(coins) → pk_m, sk_m
   测试: test_mlkem_keypair_only.c  |  输入: kInputCoinsKp[64]
                                     |  输出: pk_m[1184], sk_m[2400]
                                     |  验证: CHECK_ARRAYS_EQ

3. 组合: PK_Hyb = pk_m || ss_e (共享密钥即公钥X坐标)
         SK_Hyb = sk_m || d
```

### 2.2 Phase 2: 密钥协商 (Alice ↔ Bob)

```
Alice (Encaps):                          Bob (Decaps):
1. P-256 ephemeral → ECDH → ss_e        1. ML-KEM Decap → ss_m
2. ML-KEM Encap(pk_m) → ct_m, ss_m      2. P-256 ECDH → ss_e
3. HKDF(info="") → OKM                  3. HKDF(info="") → OKM

验证:
  ss_e_alice == ss_e_bob  (ECDH 正确性)
  ss_m_alice == ss_m_bob  (ML-KEM 正确性)
  OKM_alice == OKM_bob    (标准 KEM 正确性)
  Role binding: upper layer (second HKDF from OKM)
```

## 3. 密钥派生规范

### 3.1 IKM 构造

```
IKM = be16(32) || ss_e(32B) || be16(32) || ss_m(32B) || ctx || sid

(role 不放入 IKM, 角色绑定通过 HKDF-Expand 的 info 实现)
```

### 3.2 HKDF-SHA3-256

```
Extract:  PRK = HMAC-SHA3-256(salt=0x00*32, IKM)
Expand:   OKM = HKDF-Expand(PRK, info="", L)    (Alice == Bob, standard KEM)

Role binding is upper-layer: OKM → second HKDF with info="initiator"/"responder".
```

## 4. 测试状态

| 组件 | ISS | Chip Sim | 验证方式 |
|------|-----|------|------|
| P-256 ECDH (test_p256_only) | ✅ | ✅ | x0 ^ x1 == ss_e |
| P-256 KeyGen (test_p256_official) | ✅ | ✅ | pk_x, pk_y |
| ML-KEM KeyGen | ✅ | ✅ | pk_m[1184], sk_m[2400] |
| ML-KEM Encap | ✅ | ✅ | ct_m[1088], ss_m[32] |
| ML-KEM Decap | ✅ | ✅ | ss_m[32] |
| HKDF-SHA3-256 | ✅ | 待测 | OKM[32] |
| Phase 1 KeyGen | ⬜ | 待测 | P-256 + ML-KEM 联合 |
| Phase 2 Alice Encap | ⬜ | 待测 | ECDH + Encap + HKDF |
| Phase 2 Bob Decap | ⬜ | 待测 | Decap + ECDH + HKDF |

### 4.1 已知问题

- P-256 原始示例点 P 在 RTL chip sim 中触发 `scalar_mult_int` z=0 bug（Alert 48）
- 切换为基点 G 后通过，GitHub issue 已提交
- P-256 汇编源码与官方 MD5 一致，bug 为 RTL 点坐标依赖的计算偏差

## 5. KAT 测试向量

### 5.1 P-256

| 参数 | 值 |
|------|------|
| 标量 d | `0x1420fc41742102631b76ebe83fdfa3799590ef5db0b2c78121d0a016fe6d1071` |
| 基点 G.x | `0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296` |
| 共享密钥 Q.x | `0x815215ad7dd27f336b35843cbe064de299504edd0c7d87dd1147ea5680a9674a` |

### 5.2 HKDF (当前测试向量)

| 参数 | 值 |
|------|------|
| ss_e | `5f33d746a326640a739a9490ec15c10372869f3de675b2e85742271d18c9eb82` |
| ss_m | `3750ac4a8e656327c3d181fab002554bf6d2be0475dd28d5f31bef9f835f86ac` |
| PRK | `8f004baa31d327a738fc785cef01eea1086a61f3e41f9627e1c3106166273abd` |
| OKM (info="") | `0ce68c4ca08718d2b3d85cf7a184c4faec50fbb30a5af755c3b3e956f695f4e9` |

### 5.3 重新生成 KAT

```bash
# P-256
python3 ref/p256_kat.py

# HKDF (C数组 + .dexp + .s)
python3 ref/hkdf_kat.py 32
python3 ref/hkdf_dexp.py 32

# ML-KEM
python3 ref/gen_kat.py
```

## 6. 构建与运行

```bash
# ISS 测试
bazel test //test_hybrid_kem_paper/otbn/test:p256_ecdh_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:hkdf_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_keypair_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_encap_test --test_output=errors
bazel test //test_hybrid_kem_paper/otbn/test:mlkem768_decap_test --test_output=errors

# Chip sim 单模块
bazel test //test_hybrid_kem_paper:test_p256_only_sim_verilator ...
bazel test //test_hybrid_kem_paper:test_hkdf_only_sim_verilator ...
bazel test //test_hybrid_kem_paper:test_mlkem_keypair_only_sim_verilator ...
bazel test //test_hybrid_kem_paper:test_mlkem_encap_only_sim_verilator ...
bazel test //test_hybrid_kem_paper:test_mlkem_decap_only_sim_verilator ...

# Phase 1/2
bazel test //test_hybrid_kem_paper:phase1_keygen_test_sim_verilator ...
bazel test //test_hybrid_kem_paper:phase2_alice_encap_test_sim_verilator ...
bazel test //test_hybrid_kem_paper:phase2_bob_decap_test_sim_verilator ...
```

## 7. 安全设计要点

| 项目 | 实现 |
|------|------|
| P-256 FI 防护 | `trigger_fault_if_fg0_z` / `trigger_fault_if_fg0_not_z` |
| ML-KEM 侧信道 | 常数时间 double-and-add-always |
| A2B 掩码 | Goubin 算法 (软件) + MAI 硬件 (保留) |
| HKDF 角色绑定 | info 字段 ("initiator" / "responder") |
| KEM 正确性 | 统一 IKM (无 role) → PRK_alice == PRK_bob |
| OTBN Secure Wipe | 每个二进制加载前 SecWipeDmem+wait (防 Alert 47: KMAC 状态冲突) |
