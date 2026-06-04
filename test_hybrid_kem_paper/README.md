# Hybrid KEM Test — follows otbn_mlkem_test.c pattern

Based on "Improving ML-KEM & ML-DSA on OpenTitan" (eprint 2025/2028).

## Directory Structure

```
test_hybrid_kem_paper/
├── BUILD                              # Ibex FPGA test target
├── run_all_iss.sh                     # OTBN ISS 一键测试
├── run_fpga.sh                        # FPGA 运行脚本
├── HYBRID_KEM_FLOW.md                 # 正确验证流程（OKM_init ≠ OKM_resp）
├── README.md
├── ibex/
│   └── hybrid_kem_test.c              # Ibex 测试（KAT→OTBN→CHECK_ARRAYS_EQ）
├── ref/
│   ├── hybrid_kem_ref.h               # C 参考 API
│   ├── hybrid_kem_ref.c               # ISS 验证的 KAT 常量
│   ├── gen_kat.py                     # .dexp → C 数组生成器
│   └── hkdf_kat.py                    # HKDF KAT 生成器
├── otbn/
│   ├── BUILD                          # otbn_binary + otbn_sim_test 规则
│   ├── mlkem768/                      # ML-KEM-768 ver2 汇编 (12 files)
│   │   ├── *_test_wrapper.s           # ISS 测试包装器
│   │   └── *.dexp                     # KAT 期望值
│   ├── p256/                          # P-256 ECDH 汇编 (3 files)
│   │   ├── p256_test_wrapper.s
│   │   └── p256.dexp
│   └── hkdf/                          # HKDF-SHA3-256 汇编 (4 files)
│       ├── hkdf_test.s / .dexp        # ISS 验证通过 ✅
│       └── (hmac_sha3, kmac_sha3_template)
└── (复用 test_hybrid_kem_otbn_prompt 的 OTBN 二进制)
```

## Verification Flow

```
1. OTBN ISS (self-contained)
   bash run_all_iss.sh
   → All 5 tests PASS

2. Ibex test (FPGA)
   KAT → OTBN load/exec → CHECK_ARRAYS_EQ
   → Verify round-trip correctness

3. Role binding
   OKM_initiator ≠ OKM_responder  (security feature)
   ss_e == ss_e'  &&  ss_m == ss_m'  (correctness proof)
```

## Status

| Component | Status |
|------|------|
| OTBN ISS tests (5) | ✅ All PASS |
| P-256 KAT | ✅ ISS-verified |
| ML-KEM keypair KAT | ✅ ISS-verified |
| ML-KEM encap KAT | ✅ ISS-verified |
| ML-KEM decap KAT | ✅ ISS-verified |
| HKDF KAT (initiator) | ✅ ISS-verified (`1ed09693`) |
| HKDF KAT (responder) | ✅ ISS-verified (`4ff4dc0c`) |
| Ibex test code | ✅ Complete |
| BUILD (FPGA) | ✅ Complete |
| FPGA bitstream | ⬜ Pending synthesis |

## Usage

### OTBN ISS

```bash
# All 5 tests
bash run_all_iss.sh

# Individual
bazel test //test_hybrid_kem_paper/otbn:mlkem768_keypair_test
bazel test //test_hybrid_kem_paper/otbn:mlkem768_encap_test
bazel test //test_hybrid_kem_paper/otbn:mlkem768_decap_test
bazel test //test_hybrid_kem_paper/otbn:p256_ecdh_test
bazel test //test_hybrid_kem_paper/otbn:hkdf_test
```

### KAT Generation (after code changes)

```bash
# ML-KEM + P-256
python3 ref/gen_kat.py

# HKDF (initiator + responder)
python3 ref/hkdf_kat.py 32 initiator
python3 ref/hkdf_kat.py 32 responder
```

### FPGA

```bash
bazel build //test_hybrid_kem_paper:hybrid_kem_test
bash run_fpga.sh
```

## Key Conventions

| Rule | Reason |
|------|------|
| LOG_INFO 不用 "PASS" | chip sim exit-success 正则误杀 |
| KAT 数组 DMEM 字节序 | 匹配 OTBN 输出，直接 CHECK_ARRAYS_EQ |
| OKM_init ≠ OKM_resp | 角色绑定安全特性 |
| Wipe 之间 | FPGA/ISS 不需要，Chip sim 参考官方模式 |

## Verilator Chip Sim

Known Alert 48 (PC=0x0050, rf_indirect_err) in multi-binary builds.
Use OTBN ISS for development, FPGA for final verification.
