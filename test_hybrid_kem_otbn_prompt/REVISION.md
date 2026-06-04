# 修订记录

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-06-02 | 初始搭建: test_hybrid_kem_paper 目录, 5 个 standalone chip sim 测试 |
| v1.1 | 2026-06-03 | LOG_INFO "PASS" → "OK" 修复假阳性 |
| v1.2 | 2026-06-03 | ML-KEM keypair/encap/decap chip sim 通过 |
| v2.0 | 2026-06-04 | P-256 深度调试: 定位官方 vs 我们的差异 |
| v2.1 | 2026-06-04 | 测试向量从示例点 P 切换为基点 G → p256_shared_key chip sim 通过 |
| v2.2 | 2026-06-04 | ISS test wrapper 统一到 otbn/test/, 删除 otbn/p256/ 重复副本 |
| v2.3 | 2026-06-04 | IKM 去掉 role, HKDF info 支持角色绑定 |
| v2.4 | 2026-06-04 | hkdf_sha3_256.s: hkdf_expand 添加 info 支持 |
| v2.5 | 2026-06-04 | hkdf_test.s/hkdf_test.dexp/test_hkdf_only.c 同步更新 |
| v2.6 | 2026-06-04 | hkdf_kat.py/hkdf_dexp.py: Alice/Bob 双份 OKM 生成 |
| v2.7 | 2026-06-04 | ref/ 目录: 新增 p256_kat.py, hkdf_dexp.py |
| v2.8 | 2026-06-04 | Phase 1/2 拆分: phase1_keygen, phase2_alice_encap, phase2_bob_decap |
| v2.9 | 2026-06-04 | MAI 硬件加速器集成尝试 (保留, A2B 语义不兼容) |
| v3.0 | 2026-06-04 | 文档完善: API/USAGE/REVISION/SECURITY_AND_TEST/IMPLEMENTATION/FLOW/README/PHASE_FLOW_DETAIL |
| v3.1 | 2026-06-04 | HKDF info 支持: hkdf_extract 不再将 info_len 误加入 IKM (68+32+32+16→68+32+32=132B) |
| v3.2 | 2026-06-04 | IKM 统一: ctx=32B, sid=32B, info=16B; HKDF ISS 测试通过 |

## 当前测试状态 (2026-06-04)

| 测试 | ISS | Chip Sim | 验证 |
|------|-----|------|------|
| P-256 ECDH (test_p256_only) | ✅ | ✅ | x0 ^ x1 == ss_e |
| P-256 KeyGen (test_p256_official) | ✅ | ✅ | pk_x, pk_y |
| ML-KEM keypair | ✅ | ✅ | pk_m[1184], sk_m[2400] |
| ML-KEM encap | ✅ | ✅ | ct_m[1088], ss_m[32] |
| ML-KEM decap | ✅ | ✅ | ss_m[32] |
| HKDF | ✅ | ⬜ | OKM[32] (info=16B 支持已修复) |
| Phase 1 KeyGen | ⬜ | ⬜ | P-256 + ML-KEM |
| Phase 2 Alice | ⬜ | ⬜ | ECDH + Encap + HKDF |
| Phase 2 Bob | ⬜ | ⬜ | Decap + ECDH + HKDF |

### v3.1 HKDF info 支持修复 (2026-06-04)

**根因**: `hkdf_extract` 中仍将 `input_lengths[+8]`（原 `role_len`，改为 `info_len` 后忘删）加入 IKM:
```
旧: ikm_len = 68 + ctx_len + sid_len + info_len = 68 + 32 + 32 + 16 = 148B ❌
新: ikm_len = 68 + ctx_len + sid_len           = 68 + 32 + 32      = 132B ✅
```
info 仅在 `hkdf_expand` 的 HMAC 消息中使用，不应参与 Extract。

## 关键发现

### P-256 Alert 48 (2026-06-04)

- 汇编与官方 MD5 一致，测试向量相同
- 示例点 P 触发 RTL `scalar_mult_int` z=0 bug
- 切换为基点 G 后通过
- RTL bug 为点坐标依赖的计算偏差
- GitHub issue 已提交

### HKDF 角色绑定 (2026-06-04)

- role 从 IKM 移至 `info` (HKDF-Expand)
- PRK 相同 → KEM 正确性
- OKM 不同 → 角色绑定在 info 层

## 修改的系统文件

| 文件 | 修改内容 |
|------|---------|
| `rules/otbn.bzl` | copts + BNMULV_VER |
| `hw/ip/otbn/util/otbn_as.py` | --bnmulv_version_id CLI |
| `hw/ip/otbn/util/shared/reg_dump.py` | f-string 语法修复 |
| `hw/ip/otbn/rtl/otbn_controller.sv` | $display DEBUG |
| `hw/ip/otbn/rtl/otbn_predecode.sv` | BignumArith 译码追踪 |
| `hw/ip/otbn/rtl/otbn_alu_bignum.sv` | adder flags 追踪 + 修复 |
