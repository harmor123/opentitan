# ML-KEM-768 KAT 测试数据

## 目录结构

```
assets/
├── README.md                           ← 本文件
│
├── PQCkemKAT_2400.rsp                  ← NIST RSP 格式 KAT (100 组, seed→pk/sk/ct/ss)
├── aes256_ctr_drbg.py                  ← NIST SP 800-90A AES-256-CTR DRBG 参考实现
│
├── ML-KEM-keyGen-FIPS203/              ← NIST ACVP keyGen 测试数据
│   ├── prompt.json                     ← 输入: d(32B) + z(32B)
│   └── expectedResults.json            ← 输出: ek(1184B) + dk(2400B)   [tgId=2=ML-KEM-768]
│
├── ML-KEM-encapDecap-FIPS203/          ← NIST ACVP encap/decap 测试数据
│   ├── prompt.json                     ← encap输入: ek+m, decap输入: dk+c
│   └── expectedResults.json            ← encap输出: c+k, decap输出: k  [tgId=2=encap, tgId=5=decap]
│
├── converters/                          ← 转换脚本
│   ├── kat_to_asm.py                   ← ACVP → 汇编 .word (d/z/m 已展开)
│   └── rsp_to_asm.py                   ← RSP → 汇编 .word (AES-CTR DRBG 展开 seed)
│
└── output/                              ← 生成的测试向量
    ├── kat/                             ← ACVP 输出
    │   └── tcId_NNN/
    │       ├── keypair.s                ← .globl kat_coins, kat_pk, kat_sk
    │       ├── encap.s                  ← .globl kat_coins, kat_ct, kat_ss
    │       └── decap.s                  ← .globl kat_ct, kat_ss
    │
    └── rsp/                             ← RSP 输出
        └── count_NNN/
            ├── keypair.s
            ├── encap.s
            └── decap.s
```

## 数据和脚本来源

| 文件 | 来源 | 说明 |
|---|---|---|
| `PQCkemKAT_2400.rsp` | NIST KAT 网站 | ML-KEM-768 官方测试向量 |
| `ML-KEM-*FIPS203/` | NIST ACVP 服务器 | FIPS 203 验证数据 |
| `aes256_ctr_drbg.py` | ML-KEM 参考实现 | NIST SP 800-90A DRBG |

## 两个 KAT 格式的区别

| | ACVP (kat_to_asm.py) | RSP (rsp_to_asm.py) |
|---|---|---|
| 输入文件 | `ML-KEM-*FIPS203/prompt.json` + `expectedResults.json` | `PQCkemKAT_2400.rsp` |
| Coins 来源 | 直接给定 `d`, `z`, `m` (已展开) | `seed` (48B) → AES-256-CTR DRBG 展开 |
| 测试组数 | keyGen×25, encap×25, decap×10 (triples: 10) | 100 组完整 triple |
| 匹配方式 | tcId 对齐 (decap = keygen + 60) | 每组自带 pk/sk/ct/ss |
| 优势 | 无需 DRBG 实现 | 官方 KAT，公认权威 |

## 用法

```bash
cd assets/converters

# ACVP: 导出前 5 组
python3 kat_to_asm.py 5

# ACVP: 导出全部 10 组
python3 kat_to_asm.py -1

# RSP: 导出前 10 组
python3 rsp_to_asm.py 10

# RSP: 导出全部 100 组
python3 rsp_to_asm.py -1
```

## 在 OTBN 测试汇编中使用

```asm
/* 引入 KAT 期望值 */
.include "output/rsp/count_000/keypair.s"

/* kat_coins, kat_pk, kat_sk 现在可用 */
test_keypair:
    la   x10, kat_coins    /* coins = d || z (64B) */
    la   x11, output_pk    /* OTBN 生成的 pk */
    la   x12, output_sk    /* OTBN 生成的 sk */
    jal  x1, crypto_kem_keypair

    /* 比较 output_pk vs kat_pk (1184B) */
    /* 比较 output_sk vs kat_sk (2400B) */
```

## ML-KEM-768 参数速查

| 参数 | 值 |
|---|---|
| 安全级别 | 3 (NIST) |
| k (向量维度) | 3 |
| η1 (CBD 参数) | 2 |
| η2 (CBD 参数) | 2 |
| du (压缩) | 10 |
| dv (压缩) | 4 |
| pk 长度 | 1184 bytes |
| sk 长度 | 2400 bytes |
| ct 长度 | 1088 bytes |
| ss 长度 | 32 bytes |
| coins (keypair) | 64 bytes (d \|\| z) |
| coins (encap) | 32 bytes (m) |
