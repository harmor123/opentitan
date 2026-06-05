# Hybrid KEM — ver1 (SW ML-KEM + KMAC Hash)

ML-KEM-768 (纯软件基线指令) + P-256 ECDH + HKDF-SHA3-256 (KMAC 硬件加速)。

与 ver0 的区别：SHA3/HMAC/HKDF 使用 KMAC 硬件，不依赖软件 Keccak-f。ML-KEM 和 P-256 与 ver0 完全相同。

## 快速命令

```bash
cd ~/pqc/opentitan

# === ISS (软件模拟) ===
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:all --cache_test_results=no

# 单独跑
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:sha3_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:hmac_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:hkdf_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:mlkem768_keypair_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:mlkem768_encap_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:mlkem768_decap_test
bazel test //test_hybrid_kem_otbn_prompt_ver1/otbn/test:p256_ecdh_test

# === OTBN 二进制 ===
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/hkdf:sha3_test_bin
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/hkdf:hmac_sha3_256
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/hkdf:hkdf_sha3_256
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/p256:p256_ecdh_shared_key
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/mlkem768:mlkem768_keypair
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/mlkem768:mlkem768_encap
bazel build //test_hybrid_kem_otbn_prompt_ver1/otbn/mlkem768:mlkem768_decap

# === OTBN co-sim (RTL vs ISS) ===
chmod +x test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/*.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_sha3_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_hmac_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_hkdf_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_p256_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_mlkem_keypair_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_mlkem_encap_co_sim.sh
bash test_hybrid_kem_otbn_prompt_ver1/otbn/co_sim/run_mlkem_decap_co_sim.sh

# === Chip Sim ===
CHIP="--test_timeout=2000 --cache_test_results=no --sandbox_writable_path=/run/user/1000/ccache-tmp --test_output=streamed"

bazel test //test_hybrid_kem_otbn_prompt_ver1:test_p256_only_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:test_mlkem_keypair_only_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:test_mlkem_encap_only_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:test_mlkem_decap_only_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:test_hkdf_only_sim_verilator $CHIP

bazel test //test_hybrid_kem_otbn_prompt_ver1:phase1_keygen_test_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:phase2_alice_encap_test_sim_verilator $CHIP
bazel test //test_hybrid_kem_otbn_prompt_ver1:phase2_bob_decap_test_sim_verilator $CHIP
```

## 三版本对比

| | ver0 (纯软件) | ver1 (混合) | ver2 (硬件加速) |
|------|------|------|------|
| ML-KEM | 基线指令 | 基线指令 | BNMULV_VER2 |
| SHA3/HMAC | 软件 Keccak-f | **KMAC 硬件** | KMAC 硬件 |
| HKDF | 软件 HMAC | **KMAC 硬件** | KMAC 硬件 |
| P-256 | 软件 | 软件（同 ver0） | 软件（同 ver0） |
| co_sim | 需要 | 需要 | 需要 |

## 目录

```
├── BUILD               # chip sim 测试目标
├── README.md
├── ibex/               # Ibex C 测试代码
├── otbn/
│   ├── p256/           # P-256 (同 ver0)
│   ├── mlkem768/       # ML-KEM ver0 纯软件
│   ├── hkdf/           # KMAC-based SHA3/HMAC/HKDF (同 ver2)
│   ├── test/           # ISS 测试 + dexp
│   └── co_sim/         # RTL+ISS co-sim 脚本
└── ref/                # Python KAT 生成器
```
