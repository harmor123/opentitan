# 修订记录 (ver0_base — 纯软件基线)

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v0.1 | 2026-05-25 | 初始创建：目录结构、Ibex C 调度框架、OTBN 汇编包装器 |
| v0.2 | 2026-05-25 | HKDF/HMAC 纯软件实现（sha3_init/update/final 替代 KMAC 硬件） |
| v0.3 | 2026-05-25 | ML-KEM 三阶段包装器：keypair/encap/decap 独立 OTBN 二进制 |
| v0.4 | 2026-05-25 | P-256 ECDH 包装器集成 |
| v0.5 | 2026-05-25 | Ibex 侧性能测量 (mcycle CSR)：周期数/DMEM读写/调用次数统计 |
| v0.6 | 2026-05-25 | 顶层 BUILD：test + prod 双模式（HYBRID_KEM_TEST_MODE） |
| v0.7 | 2026-05-25 | 文档完善：API/USAGE/REVISION/SECURITY_AND_TEST/RTL |
| v1.0 | 2026-05-25 | 重构 HMAC/HKDF 为纯函数库（仿参考版模式）：hmac_sha3_256 入口，bn.lid/bn.sid 常量加载，const_0x36/const_0x5c 外部提供 |
| v1.1 | 2026-05-25 | HKDF 二进制包装器 hkdf_wrapper.s：定义所有 DMEM 标签 + main 入口 |
| v1.2 | 2026-05-25 | 移除 hkdf_integration.{c,h}：HKDF IKM 构建内联到 hybrid_kem.c 的 phase_hkdf() |
| v1.3 | 2026-05-25 | SHA3 测试替换为 kyber_ver0_base/hash/sha3_shake_test（dexp 格式） |
| v1.4 | 2026-05-25 | ML-KEM 统一使用 symmetric.s（sha3_shake.s 移除，避免重复符号）|
| v1.5 | 2026-05-25 | otbn/test/ 完整测试套件：7 个 otbn_sim_test 全部通过 |

---

## 与参考版 (test_hybrid_kem_otbn_prompt) 的差异总结

### 不需要的修改（纯软件基线特有无需）

| 项目 | 参考版修改 | 基线版状态 |
|------|-----------|-----------|
| `rules/otbn.bzl` | copts + BNMULV_VER 支持 | **无需修改** |
| `hw/ip/otbn/util/otbn_as.py` | --bnmulv_version_id CLI 参数 | **无需修改** |
| `hw/ip/otbn/rtl/otbn_decoder.sv` | BN.SHV/TRN/ADDVM 解码 | **无需修改** |
| `hw/ip/otbn/rtl/otbn_predecode.sv` | 16H 向量预解码 | **无需修改** |
| `hw/ip/otbn/rtl/otbn_alu_bignum.sv` | buffer_bit 16H 加法器 | **无需修改** |
| `hw/ip/otbn/rtl/otbn_controller.sv` | vector_type/vector_sel 穿透 | **无需修改** |
| `hw/ip/otbn/rtl/otbn_vec_transposer.sv` | 16H 转置器 | **无需修改** |

### 新增文件（基线版特有）

| 文件 | 说明 |
|------|------|
| `otbn/hkdf/hmac_sha3.s` | 纯函数库 HMAC-SHA3-256（sha3_init/update/final，无 KMAC，无数据段） |
| `otbn/hkdf/hkdf_sha3_256.s` | 纯函数库 HKDF（hkdf_extract / hkdf_expand，无数据段） |
| `otbn/hkdf/hkdf_wrapper.s` | HKDF 二进制包装器（定义所有 DMEM 标签 + main 入口） |
| `otbn/hkdf/sha3_shake.s` | Keccak-f[1600] 纯软件实现（来自 kyber_ver0_base） |
| `otbn/mlkem768/mlkem_keypair_test.s` | Keypair 二进制包装器 → crypto_kem_keypair |
| `otbn/mlkem768/mlkem_encap_test.s` | Encap 二进制包装器 → crypto_kem_enc |
| `otbn/mlkem768/mlkem_decap_test.s` | Decap 二进制包装器 → crypto_kem_dec |
| `otbn/p256_ecdh/p256_ecdh_test.s` | P-256 二进制包装器 → p256_shared_key |
| `otbn/test/` | 7 个 otbn_sim_test：sha3_shake / hmac / hkdf / mlkem×3 / p256 |
| `ibex/otbn_utils.h` | MCYCLE 读取 + 性能测量宏 |

### 复用文件（来自 kyber_ver0_base）

| 文件 | 来源 |
|------|------|
| `sha3_shake.s` | `test/kyber_ver0_base/hash/sha3_shake.s`（仅 otbn/hkdf/） |
| `mlkem_keypair_kp.s` | `test/kyber_ver0_base/mlkem768_keypair_ver0/mlkem_keypair.s` |
| `mlkem_encap.s` | `test/kyber_ver0_base/mlkem768_encap_ver0/mlkem_encap.s` |
| `mlkem_decap.s` | `test/kyber_ver0_base/mlkem768_decap_ver0/mlkem_decap.s` |
| `mlkem_decap_encap.s` | `test/kyber_ver0_base/mlkem768_decap_ver0/mlkem_encap.s` |
| `{basemul,cbd,intt,ntt,symmetric}.s` | `test/kyber_ver0_base/mlkem768_keypair_ver0/`（symmetric.s 提供 SHA3） |
| `{pack_keys,poly,poly_gen_matrix}.s` | `test/kyber_ver0_base/mlkem768_keypair_ver0/` |
| `pack_ciphertext.s` | `test/kyber_ver0_base/mlkem768_encap_ver0/` |
| `p256_{shared_key,base,isoncurve_proj}.s` | `test/kyber_ver0_base/p256_shared_keys/` |
| `sha3_shake_test.s / .exp` | `test/kyber_ver0_base/hash/` |

---

## 已知限制

| 项目 | 说明 |
|------|------|
| 指令计数阈值 | `HYBRID_KEM_INSNS_*` 当前全部为 0（跳过验证），需 OTBN 仿真器实测后填入 |
| P-256 unmask | 布尔共享 XOR 还原在 Ibex 侧执行，生产代码应移入 OTBN 内部 |
| checksum 验证 | 当前未启用 CRC32 checksum 验证（纯软件基线可后续添加） |
| 模 n 拆分 | P-256 标量算术份额拆分简化实现（高位填零），需完整模 n 运算 |
| Verilator 集成测试 | OTBN DMEM ECC 错误 (Alert 48) — 纯软件基线待修复 |
