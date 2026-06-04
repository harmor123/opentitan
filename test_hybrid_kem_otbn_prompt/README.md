# Hybrid KEM Test

ML-KEM-768 + P-256 ECDH + HKDF-SHA3-256 混合密钥协商系统。
全部密码运算在 OTBN 内部完成，Ibex 负责调度和数据搬移。

## Directory Structure

```
test_hybrid_kem_paper/
├── BUILD                              # Bazel 测试目标
├── README.md                          # 本文档
├── HYBRID_KEM_FLOW.md                 # 验证流程
├── HYBRID_KEM_IMPLEMENTATION.md       # 实现详解
├── ibex/
│   ├── test_p256_official.c           # P-256 公钥 (官方 run_p256)
│   ├── test_p256_only.c               # P-256 ECDH 共享密钥
│   ├── test_mlkem_keypair_only.c      # ML-KEM KeyGen
│   ├── test_mlkem_encap_only.c        # ML-KEM Encap
│   ├── test_mlkem_decap_only.c        # ML-KEM Decap
│   ├── test_hkdf_only.c               # HKDF-SHA3-256
│   ├── hybrid_kem_test.c              # FPGA 端到端
│   ├── phase1_keygen/                 # Phase 1: 密钥生成
│   └── phase2_encap_decap/            # Phase 2: 封装/解封装
├── otbn/
│   ├── p256/                          # P-256 ECDH 汇编
│   ├── mlkem768/                      # ML-KEM-768 汇编
│   ├── hkdf/                          # HKDF-SHA3-256 汇编
│   └── test/                          # ISS 测试 wrapper + .dexp
└── ref/                               # Python 参考实现
    ├── p256_kat.py                    # P-256 KAT
    ├── hkdf_kat.py                    # HKDF C数组
    ├── hkdf_dexp.py                   # HKDF .dexp+.s 生成
    └── gen_kat.py                     # ML-KEM .dexp→C数组
```

## Verification Flow

```
Phase 1 (KeyGen): P-256 ECDH + ML-KEM KeyGen → ss_e, pk_m, sk_m
Phase 2 (Encaps/Decaps):
  Alice: ECDH → Encap → HKDF(info="initiator") → OKM
  Bob:   Decap → ECDH → HKDF(info="responder") → OKM

KEM correctness:  ss_e == ss_e',  ss_m == ss_m'  (OKM_alice == OKM_bob)
Role binding:     upper layer (second HKDF from OKM)
```

## Status

| Component | ISS | Chip Sim | Verify |
|------|------|------|------|
| P-256 ECDH | ✅ | ✅ | x0 ^ x1 == ss_e |
| P-256 KeyGen | ✅ | ✅ | pk_x, pk_y |
| ML-KEM keypair | ✅ | ✅ | pk_m[1184], sk_m[2400] |
| ML-KEM encap | ✅ | ✅ | ct_m[1088], ss_m[32] |
| ML-KEM decap | ✅ | ✅ | ss_m[32] |
| HKDF | ✅ | ⬜ | OKM[32] (info=16B 支持已修复) |
| Phase 1 KeyGen | ⬜ | ⬜ | P-256 + ML-KEM |
| Phase 2 Alice/Bob | ⬜ | ⬜ | ECDH+Encap+HKDF |

> P-256 使用基点 G。原示例点 P 在 RTL 中触发 `scalar_mult_int` bug (Alert 48, 已定位)。

## Usage

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
bazel test //test_hybrid_kem_paper:test_p256_only_sim_verilator --test_timeout=2000 ...
bazel test //test_hybrid_kem_paper:test_hkdf_only_sim_verilator --test_timeout=2000 ...
# Phase 1/2
bazel test //test_hybrid_kem_paper:phase1_keygen_test_sim_verilator ...
bazel test //test_hybrid_kem_paper:phase2_alice_encap_test_sim_verilator ...
bazel test //test_hybrid_kem_paper:phase2_bob_decap_test_sim_verilator ...
```

### KAT Generation

```bash
python3 ref/p256_kat.py              # P-256: 公钥 + 共享密钥
python3 ref/hkdf_kat.py 32           # HKDF: Alice + Bob OKM
python3 ref/hkdf_dexp.py 32          # HKDF: .dexp + .s 数据段
python3 ref/gen_kat.py               # ML-KEM: .dexp → C 数组
```

## Key Conventions

| Rule | Reason |
|------|------|
| LOG_INFO 不用 "PASS" | chip sim exit-success 正则误杀 |
| IKM 不含 role | KEM PRK 相同 → OKM 相同 |
| OKM Alice == Bob | 标准 KEM 正确性 |
| 测试向量基点 G | 示例点 P 触发 RTL bug |
