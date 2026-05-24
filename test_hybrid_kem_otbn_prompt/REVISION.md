# 修订记录

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-05-23 | hkdf_sha3_256.s 初版: construct_ikm + hmac_sha3_256 + hkdf_sha3_256 |
| v1.1 | 2026-05-23 | DMEM 对齐修复: balign32→balign4(ctx/sid/role), ipad/opad 160B 对齐, 精确偏移验证 |
| v2.0 | 2026-05-23 | 测试/生产双模式 (BUILD defines 切换) + checksum+指令计数验证 |
| v2.1 | 2026-05-23 | mlkem768 三目录合并为单目录, pack_ciphertext 统一使用 encap SIMD 版 |
| v2.2 | 2026-05-23 | 子目录独立 BUILD + test/ 仿真测试目录 |
| v2.3 | 2026-05-23 | otbn_as.py: --bnmulv_version_id CLI 参数; rules/otbn.bzl: copts 属性 + BNMULV_VER |
| v2.4 | 2026-05-23 | reg_dump.py: {line:!r}→{line!r}; hkdf_sha3_256.s: blt/bge/not/mv 替换为 RV32I 基础指令 |
| v2.5 | 2026-05-23 | P-256 回归官方 kyber_ver1（移除 MAI）, 5 个仿真测试全部通过 |

---

## 修改的 OpenTitan 系统文件

| 文件 | 修改内容 |
|------|---------|
| `rules/otbn.bzl` | `_otbn_assemble_sources`: 按文件编译 + copts + BNMULV_VER 环境变量; `_otbn_library`: 多 obj 返回; `_otbn_binary`: obj 列表 + BNMULV_VER 提取; `_run_sim_test`: 测试脚本 `export BNMULV_VER`; 所有规则 attrs 加 `copts` 属性 |
| `hw/ip/otbn/util/otbn_as.py` | 新增 `--bnmulv_version_id` CLI 参数 (兼容 `BNMULV_VER` 环境变量) |
| `hw/ip/otbn/util/shared/reg_dump.py` | 修复 `{line:!r}` → `{line!r}` (Python f-string 语法错误) |

---

## hkdf_sha3_256.s OTBN 精简指令集适配

OTBN 仅支持 RV32I 子集: `add, addi, sub, sll, slli, srl, srli, sra, srai, and, andi, or, ori, xor, xori, lw, sw, lui, beq, bne, jal, jalr, ecall, csrrs, csrrw, loop, loopi`。

| 伪指令 | 替换 |
|--------|------|
| `blt a, b, L` | `sub x30,a,b; srli x30,x30,31; bne x30,x0,L` |
| `bge a, b, L` | `sub x30,a,b; srli x30,x30,31; beq x30,x0,L` |
| `not rd, rs` | `xori rd, rs, -1` |
| `mv rd, rs` | `addi rd, rs, 0` |

支持: `li`, `la`, `ret` (YAML 伪指令定义)。

---

## P-256 MAI 问题

- kyber_ver2 的 P-256 新增了 `mai_hw_driver.s` (MAI 掩码加速器)
- shell 脚本通过，Bazel 构建失败 (`DMEM_INTG_VIOLATION`)
- 根因: MAI 硬件和 Bazel 链接流程不兼容
- 解决方案: 回退到 kyber_ver1 官方 P-256 (无 MAI)
- MAI 加速后续单独评估

---

## 已知限制

1. HKDF 完整测试 wrapper 待补充 (当前仅测 KMAC/SHA3 底层)
2. 指令计数阈值待实测填入 (HYBRID_KEM_INSNS_*)
3. Ibex 集成测试 (opentitan_test) 待规则确认后启用
4. P-256 MAI 加速待单独调试后加回
