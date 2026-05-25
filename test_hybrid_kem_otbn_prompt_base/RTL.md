# RTL 修改说明 (ver0_base — 纯软件基线)

## 概述

**本版本无需任何 RTL 修改。**

`test_hybrid_kem_otbn_prompt_base` 是纯软件基线实现：

- SHA-3 使用 **纯软件 Keccak-f[1600]**（`sha3_shake.s`），不访问 KMAC 硬件
- ML-KEM 使用 **基线 OTBN 指令集**，不需要 BN 向量扩展（`bnmulv_version_id=2`）
- 所有密码学运算完全在 OTBN 标准指令集上运行

---

## 与参考版对比

| 组件 | 参考版 (KMAC加速) | 基线版 (ver0_base) |
|------|-------------------|---------------------|
| SHA-3 | KMAC 硬件 (CSR 0xFC2/0x7D9-0x7DE) | 软件 Keccak-f (WDR 运算) |
| ML-KEM 模乘 | Montgomery (MOD=R\|Q) + bn.addvm.16H | Barrett 约简 + 基线 bn.add |
| NTT 蝶形 | bn.addvm.16H / bn.subvm.16H | 基线 bn.add / bn.sub |
| 向量移位 | bn.shv.16H | 标量移位操作 |
| 向量转置 | bn.trn.16H | 未使用 |

---

## OTBN 硬件使用情况 (ver0_base)

| 硬件单元 | 使用 | 说明 |
|---------|------|------|
| OTBN 大数 ALU | ✓ | bn.add/bn.sub/bn.mul 等基线指令 |
| OTBN WDR (256-bit) | ✓ | Keccak-f[1600] 向量化实现 |
| OTBN DMEM/IMEM | ✓ | 标准使用 |
| KMAC 硬件 | ✗ | **不使用** |
| BN 向量扩展 | ✗ | **不使用** |

---

## 构建标志

基线版 Otbn 汇编使用**标准 OTBN 指令集编码**，无需特殊构建标志：

```bash
# 标准 otbn_binary 构建（无 copts）
otbn_binary(
    name = "mlkem768_keypair_ver0",
    srcs = [...],  # 无 copts = ["--bnmulv_version_id=2"]
)
```

---

## 适用场景

- 评估硬件加速（KMAC / BNMULV 宏）带来的性能提升倍数
- 纯软件实现的面积/功耗基线
- 验证硬件加速功能正确性的参考对比点
