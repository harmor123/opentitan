# 修订记录

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-05-23 | hkdf_sha3_256.s 初版: construct_ikm + hmac_sha3_256 + hkdf_sha3_256 |
| v1.1 | 2026-05-23 | DMEM 对齐修复: balign32→balign4(ctx/sid/role), ipad/opad 160B 对齐 |
| v2.0 | 2026-05-23 | 测试/生产双模式 (BUILD defines), checksum+指令计数验证 |
| v2.1 | 2026-05-23 | mlkem768 三目录合并, pack_ciphertext 统一使用 encap SIMD 版 |
| v2.2 | 2026-05-23 | 子目录独立 BUILD + otbn/test/ 仿真测试目录 |
| v2.3 | 2026-05-23 | otbn_as.py: --bnmulv_version_id CLI; rules/otbn.bzl: copts + BNMULV_VER |
| v2.4 | 2026-05-23 | reg_dump.py: {line:!r}→{line!r}; hkdf_sha3_256.s: blt/bge/not/mv 替换 |
| v2.5 | 2026-05-23 | P-256 回归 kyber_ver1 官方 (移除 MAI), 5 test 全部通过 |
| v3.0 | 2026-05-24 | HMAC-SHA3-256 独立库 + 合并优化 (bn.lid/bn.sid, 合并 ipad/opad 循环) |
| v3.1 | 2026-05-24 | HKDF 重构: hkdf_extract + hkdf_expand 分离, PRK 存 hmac_key_hashed |
| v3.2 | 2026-05-24 | IKM 预拼接 96B (移除 \x00), input_lengths 32B 结构体, tests/dexp 自动生成 |
| v3.3 | 2026-05-24 | Ibex 集成: OTTF test_main 入口, 5 个 OTBN app 符号声明, checksum 验证, 编译通过 |
| v3.4 | 2026-05-24 | RTL+ISS 联调: run_otbn_co_sim.sh, otbn_kmac.sv KMAC_DEBUG ifdef 化, IKM 4B 对齐修复 |
| v4.0 | 2026-06-02 | Combined 二进制: hybrid_entry.s 5-mode 分发, otbn/combined/BUILD, DMEM 瘦身 |
| v4.1 | 2026-06-02 | TOWARDS_BASE RTL 修复: otbn_alu_bignum.sv is_modulo_i 标量 bn.addm/subm 回退 |
| v4.2 | 2026-06-02 | hybrid_entry.s MOD 初始化 + 函数参数; Mode 1 KeyGen chip sim 通过 |
| v4.3 | 2026-06-02 | otbn_controller.sv $display DEBUG; combined mode 0 待定位 err_bit |

---

## 当前测试状态 (2026-06-02)

| 测试 | 级别 | 结果 |
|------|------|------|
| standalone P-256 (`p256_only`) | chip sim | **PASS** |
| standalone ML-KEM (`mlkem_only`) | chip sim | **PASS** |
| standalone KeyGen 2-app | chip sim | **PASS** |
| combined Mode 1 (KeyGen) | chip sim | **PASS** — 输出匹配 dexp |
| combined Mode 0 (P-256) | co-sim `--flag=bnmulv_ver2` | **PASS** — w18==w19 |
| **combined Mode 0 (P-256)** | chip sim | **FAIL — Alert 48** |

### Mode 0 问题排查

已验证非根因：
- RTL `is_modulo_i` 修复 ✅
- DMEM 地址 ✅（读回验证）
- Call stack ✅（最深 4 级）
- 入口路径 ✅（等价于 standalone）
- MOD 初始化 ✅（p256 `setup_modp` 自初始化）
- p256_p DMEM 完整性 ✅（读回验证）

待定位：OTBN err_bits 具体值（illegal_insn / call_stack / bad_data / loop）

### Debug 方法

`hw/ip/otbn/rtl/otbn_controller.sv:633` — 当 software error 触发时 $display：
- PC、err_bits、具体错误位、DMEM 地址

## 修改的系统文件

| 文件 | 修改内容 |
|------|---------|
| `rules/otbn.bzl` | copts + BNMULV_VER |
| `hw/ip/otbn/util/otbn_as.py` | --bnmulv_version_id CLI |
| `hw/ip/otbn/util/shared/reg_dump.py` | f-string 语法修复 |
| `hw/ip/otbn/rtl/otbn_alu_bignum.sv` | TOWARDS_BASE is_modulo_i 修复 |
| `hw/ip/otbn/rtl/otbn_controller.sv` | $display DEBUG (v4.3) |

## 测试命令速查

```bash
# === 独立测试 (已验证全部 PASS) ===
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_p256_only_sim_verilator --test_timeout=2000
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_mlkem_only_sim_verilator --test_timeout=2000
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_keygen_sim_verilator --test_timeout=2000

# === Combined KeyGen chip sim (带 debug 输出) ===
bazel clean --expunge
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_combined_sim_verilator \
    --test_timeout=2000 --cache_test_results=no \
    --sandbox_writable_path=/run/user/1000/ccache-tmp --test_output=all \
    2>&1 | grep -A10 "OTBN SW ERROR"

# === Combined co-sim (OTBN level) ===
fusesoc --cores-root=. run --target=sim --setup --build \
    --flag=bnmulv_ver2 lowrisc:ip:otbn_top_sim --make_options="-j$(nproc)"
bazel build //test_hybrid_kem_otbn_prompt/otbn/combined:hybrid_kem_all
./build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim \
    --load-elf=bazel-bin/test_hybrid_kem_otbn_prompt/otbn/combined/hybrid_kem_all.elf
```
