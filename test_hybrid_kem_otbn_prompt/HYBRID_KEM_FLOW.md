# Hybrid KEM — 验证流程

## 一、密钥派生

```
IKM = be16(32) || ss_e(32B) || be16(32) || ss_m(32B) || ctx || sid

PRK = HMAC-SHA3-256(salt=0x00*32, IKM)     (Alice == Bob, KEM 正确性)

OKM = HKDF-Expand(PRK, info="", L)    (KEM unified, Alice == Bob)
```

role 不放入 IKM 也不放入 info。标准 KEM 输出统一 OKM。
角色绑定是**上层协议**责任——用 OKM 做第二次 HKDF: `HKDF-Expand(OKM, "initiator"/"responder", L)`。

## 二、正确性验证

| 步骤 | Alice | Bob | 预期 |
|------|------|------|------|
| P-256 ECDH | sk_e_eph * pk_e → ss_e | sk_e * ek → ss_e' | **ss_e == ss_e'** |
| ML-KEM | Encap(pk_m) → ct_m, ss_m | Decap(sk_m, ct_m) → ss_m' | **ss_m == ss_m'** |
| HKDF | PRK = HMAC(salt, IKM) | PRK = HMAC(salt, IKM) | **PRK == PRK** |
| HKDF | OKM | OKM | **OKM == OKM** |

> 标准 KEM 语法: `(c, K) ← Encap(pk)`, `K ← Decap(sk, c)`, 要求 K == K。

## 三、测试架构

```
Phase 1 (KeyGen):
  1. P-256 ECDH → ss_e (32B) = d*G.x
  2. ML-KEM keypair → pk_m (1184B), sk_m (2400B)
  3. PK_Hyb = pk_m || ss_e
  4. SK_Hyb = sk_m || d

Phase 2 (Encaps → Decaps):
  Alice (phase2_alice_encap.c):
    1. P-256 ECDH → ss_e
    2. ML-KEM encap → ct_m, ss_m
    3. HKDF(info="") → OKM (KEM unified)

  Bob (phase2_bob_decap.c):
    1. ML-KEM decap → ss_m, CHECK match
    2. P-256 ECDH → ss_e, CHECK match
    3. HKDF(info="") → OKM, CHECK: OKM_alice == OKM_bob
```

## 四、KAT 对照表

| 变量 | 来源 | 值 |
|------|------|------|
| ss_e[32] | P-256 ECDH (d*G.x) | `815215ad...` |
| pk_m[1184] | ML-KEM keypair (.dexp ek) | `28f0196e...` |
| sk_m[2400] | ML-KEM keypair (.dexp dk) | `2a20294f...` |
| ct_m[1088] | ML-KEM encap (.dexp ct) | `69ac720a...` |
| ss_m[32] | ML-KEM encap (.dexp ss) | `ac865f83...` |
| PRK[32] | `ref/hkdf_kat.py` | `8f004baa...` |
| OKM[32] | `ref/hkdf_kat.py` (info="") | `0ce68c4c...` (Alice == Bob) |
