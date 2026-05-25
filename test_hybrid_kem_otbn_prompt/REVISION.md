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

---

## 修改的 OpenTitan 系统文件

| 文件 | 修改内容 |
|------|---------|
| `rules/otbn.bzl` | copts 属性 + per-file 编译 + BNMULV_VER 环境变量 + test script export |
| `hw/ip/otbn/util/otbn_as.py` | --bnmulv_version_id CLI 参数 (兼容 ENV) |
| `hw/ip/otbn/util/shared/reg_dump.py` | {line:!r}→{line!r} (Python f-string 语法修复) |

## hkdf_sha3_256.s OTBN 精简指令集适配

| 伪指令 | 替换 |
|--------|------|
| `blt a, b, L` | `sub x30,a,b; srli x30,x30,31; bne x30,x0,L` |
| `bge a, b, L` | `sub x30,a,b; srli x30,x30,31; beq x30,x0,L` |
| `not rd, rs` | `xori rd, rs, -1` |
| `mv rd, rs` | `addi rd, rs, 0` |

## HKDF 关键 bug 修复

| Bug | 症状 | 修复 |
|-----|------|------|
| HMAC key_len 判断反向 | key≤136 被错误哈希 | `beq`→`bne` + 增加 136 等值检查 |
| Expand 用 hmac_opad 作消息缓冲 | hmac_sha3_256 覆盖消息 | 改用 ikm_buf (Extract 后空闲) |
| IKM 尾部 \x00 多余 | OKM 全错 | role=9B, IKM=96B (24 words 完美对齐) |
| t_buf 被 T(1) 覆盖 | T(2)+ 密钥错误 | PRK 存 hmac_key_hashed (独立缓冲区) |

## 测试状态

| 测试 | 状态 |
|------|------|
| `mlkem768_keypair_test` | PASS |
| `mlkem768_encap_test` | PASS |
| `mlkem768_decap_test` | PASS |
| `p256_ecdh_test` | PASS |
| `kmac_sha3_test` | PASS |
| `hkdf_test` | PASS |
| `hmac_sha3_test` (shell) | PASS |
| `hybrid_kem_test` (Ibex) | COMPILE OK, Verilator pending |
