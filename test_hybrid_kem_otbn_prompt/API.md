# API 接口说明

## 一、常量定义

| 常量 | 值 | 说明 |
|------|----|------|
| `kPkM_Bytes` | 1184 | ML-KEM-768 公钥 |
| `kSkM_Bytes` | 2400 | ML-KEM-768 私钥 |
| `kCtM_Bytes` | 1088 | ML-KEM-768 密文 |
| `kSsMBytes` | 32 | ML-KEM-768 共享密钥 |
| `kPkE_Bytes` | 32 | P-256 公钥 X 坐标 (共享密钥) |
| `kSkE_Bytes` | 64 | P-256 私钥 (320-bit 份额) |
| `kSalt_Bytes` | 32 | HKDF salt |
| `kOkmMax` | 256 | OKM 最大长度 |

## 二、OTBN 汇编接口 — P-256 ECDH

**二进制**: `//test_hybrid_kem_paper/otbn/p256:p256_ecdh_shared_key`

| 标签 | 大小 | 方向 | 说明 |
|------|------|------|------|
| `d0` | 64B | Ibex → OTBN | 标量算术份额 0 (320-bit) |
| `d1` | 64B | Ibex → OTBN | 标量算术份额 1 (全零=无掩码) |
| `x` | 32B | 双向 | 输入点 x / 输出布尔份额 x0 |
| `y` | 32B | 双向 | 输入点 y / 输出布尔份额 x1 |

**输出**: `ss_e = x0 XOR x1` (32B, Ibex 侧 XOR)

## 三、OTBN 汇编接口 — ML-KEM-768

| 二进制 | 标签 | 大小 | 方向 |
|------|------|------|------|
| `mlkem768_keypair` | `coins` | 64B | Ibex → OTBN |
| | `ek` | 1184B | OTBN → Ibex |
| | `dk` | 2400B | OTBN → Ibex |
| `mlkem768_encap` | `coins` | 32B | Ibex → OTBN |
| | `ek` | 1184B | Ibex → OTBN |
| | `ct` | 1088B | OTBN → Ibex |
| | `ss` | 32B | OTBN → Ibex |
| `mlkem768_decap` | `ct` | 1088B | Ibex → OTBN |
| | `dk` | 2400B | Ibex → OTBN |
| | `ss` | 32B | OTBN → Ibex |

## 四、OTBN 汇编接口 — HKDF-SHA3-256

**二进制**: `//test_hybrid_kem_paper/otbn/hkdf:hkdf_sha3_256`

### 子程序

| 子程序 | 功能 | 接口 |
|------|------|------|
| `hkdf_extract` | PRK = HMAC-SHA3-256(salt, IKM) | 从 DMEM label 读取, PRK → `hmac_key_hashed` |
| `hkdf_expand` | OKM = HKDF-Expand(PRK, info, L) | 从 DMEM label 读取, OKM → `output_okm` |

### DMEM 标签

| 标签 | 大小 | 说明 |
|------|------|------|
| `input_salt` | 32B | HKDF salt |
| `ikm_prebuilt` | 可变 | 预拼接 IKM = be16(32)\|\|ss_e\|\|be16(32)\|\|ss_m\|\|ctx\|\|sid |
| `input_info` | 可变 | HKDF-Expand info 字节序列 |
| `input_lengths` | 32B | +0=ctx_len, +4=sid_len, +8=info_len, +12=okm_len |
| `output_okm` | 256B | OKM 输出 |
| `t_buf` | 32B | T(i) 暂存 |
| `hmac_key_hashed` | 32B | PRK 暂存 (Extract → Expand) |
| `hmac_inner` | 32B | HMAC 内部哈希输出 |
| `ikm_buf` | 1024B | Expand 消息缓冲 |
| `hmac_ipad` / `hmac_opad` | 160B | HMAC 工作区 |
| `const_0x36` / `const_0x5c` | 160B | HMAC 常量 |

### IKM 格式

```
be16(32) || ss_e(32B) || be16(32) || ss_m(32B) || ctx || sid
```
> role 不放入 IKM。标准 KEM 输出统一 OKM，角色绑定是上层责任。

### HKDF 流程

```
Extract:  PRK = HMAC-SHA3-256(salt=0x00*32, IKM)   (Alice == Bob)
Expand:   OKM = HKDF-Expand(PRK, info="", L)        (Alice == Bob)

OKM 相同 → 标准 KEM 正确性
Role binding via upper layer: HKDF-Expand(OKM, "initiator"/"responder", L)
```

## 五、Phase 1/2 C 接口

```c
// Phase 1: 密钥生成
//   输入: kInputD0[64], kInputD1[64], kInputGx[32], kInputGy[32]
//   输出: ss_e = x0 ^ x1 (32B)
//   输入: kInputCoinsKp[64]
//   输出: pk_m[1184], sk_m[2400]
//   PK_Hyb = pk_m || ss_e, SK_Hyb = sk_m || d0

// Phase 2 Alice: 封装
//   Step 1: P-256 ECDH(sk_e_alice, pk_e_bob) → ss_e
//   Step 2: ML-KEM Encap(pk_m) → ct_m, ss_m
//   Step 3: HKDF(ss_e, ss_m, info="") → OKM

// Phase 2 Bob: 解封装
//   Step 1: ML-KEM Decap(sk_m, ct_m) → ss_m
//   Step 2: P-256 ECDH(sk_e_bob, ek_alice) → ss_e
//   Step 3: HKDF(ss_e, ss_m, info="") → OKM
//   CHECK: OKM_alice == OKM_bob (standard KEM)
```

## 六、测试向量格式

| 类型 | 扩展名 | 格式 | 用途 |
|------|--------|------|------|
| DMEM 期望 | `.dexp` | `label: hex` (BE 字节序) | ISS DMEM 比对 |
| C 数组 | `ref/*.py` 输出 | `static const uint8_t name[N]` | Ibex 测试 CHECK_ARRAYS_EQ |

### 生成命令

```bash
python3 ref/p256_kat.py       # P-256: 公钥 + 共享密钥
python3 ref/hkdf_kat.py 32    # HKDF: Alice + Bob OKM (C数组)
python3 ref/hkdf_dexp.py 32   # HKDF: .dexp + .s 数据段
python3 ref/gen_kat.py        # ML-KEM: .dexp → C 数组
```
