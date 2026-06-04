# Hybrid KEM — 正确验证流程

## 一、密钥派生

```
IKM = len_cls(2B:0x0020) || ss_e(32B) || len_pqc(2B:0x0020) || ss_m(32B) || role

Alice (encaps):   role = "initiator"
Bob (decaps):     role = "responder"

PRK = HMAC-SHA3-256(salt, IKM)
OKM = HKDF-Expand(PRK, info="", L)
```

## 二、正确性验证

| 步骤 | Alice | Bob | 预期 |
|------|------|------|------|
| P-256 ECDH | d_eph * pk_e_Bob → ss_e | sk_e_Bob * ek_Alice → ss_e' | **ss_e == ss_e'** ✅ |
| ML-KEM | Encap(pk_m) → ss_m | Decap(sk_m, ct_m) → ss_m' | **ss_m == ss_m'** ✅ |
| HKDF | OKM_enc | OKM_dec | **OKM_enc ≠ OKM_dec** ✅ |

> OKM_enc ≠ OKM_dec 不是 bug——是**角色绑定**安全特性，防止反射攻击。
> 正确性由中间值 ss_e/ss_m 匹配验证。

## 三、测试架构

```
Phase 1 (KeyGen):
  1. P-256 ECDH → pk_e (64B)
  2. ML-KEM keypair → pk_m (1184B), sk_m (2400B)
  3. PK_Hyb = pk_m || pk_e (1248B)
  4. SK_Hyb = sk_m || sk_e (2432B)

Phase 2 (Encaps → Decaps 往返):
  1. Alice: P-256 ephemeral → ek → ECDH → ss_e
  2. Alice: ML-KEM encap → ct_m, ss_m
  3. Alice: HKDF("initiator") → OKM_enc
  4. Bob: P-256 ECDH → ss_e', CHECK: ss_e == ss_e'
  5. Bob: ML-KEM decap → ss_m', CHECK: ss_m == ss_m'
  6. Bob: HKDF("responder") → OKM_dec
  7. CHECK: OKM_enc ≠ OKM_dec (role binding)
```

## 四、验证层

| 层 | 用途 | 方式 |
|------|------|------|
| OTBN ISS | 集成逻辑 | 全部 5 个测试 PASS |
| Chip sim | 单模块硬件 | **同一 binary reload 模式**（官方 `otbn_ecdsa_op_irq_test` 模式） |
| Chip sim | 多阶段 | wipe + reload 同一 `mlkem_combined` binary |
| FPGA | 端到端 | KAT → CHECK_ARRAYS_EQ |
| Python HKDF | 参考实现 | 独立计算交叉比对 |

## 五、官方多阶段模式

参考 `otbn_ecdsa_op_irq_test.c`（sign → verify）：

```c
// 阶段 N: 加密
otbn_testutils_load_app(otbn, kAppMlkem);   // 加载 combined binary
// 写 mode=1 (encap)、输入数据 → 执行 → 读结果

// 切换: wipe + reload
otbn_wipe_dmem(otbn);
otbn_testutils_load_app(otbn, kAppMlkem);   // 同一 binary reload

// 阶段 N+1: 解密
// 写 mode=2 (decap)、输入数据 → 执行 → 读结果
```

**关键**：只用 1 个 OTBN binary（`mlkem_combined`），通过 mode dispatch + reload 切换阶段。芯片仿真友好。

## 五、KAT 对照表

| 变量 | 来源 | 值 |
|------|------|------|
| pk_e[0..31] | P-256 ISS (.dexp x XOR y) | `5f33d746a326640a...` |
| pk_m[1184] | ML-KEM ISS (.dexp ek) | `28f0196e13ae1700...` |
| sk_m[2400] | ML-KEM ISS (.dexp dk) | `2a20294fb51cd060...` |
| ct_m[1088] | ML-KEM ISS (.dexp ct) | `69ac720ab29ef70c...` |
| ss_m[32] | ML-KEM ISS (.dexp ss, reversed) | `ac865f83...` |
| OKM_enc[L] | hkdf_kat.py (initiator) | 运行脚本生成 |
| OKM_dec[L] | hkdf_kat.py (responder) | 运行脚本生成 |
