# 使用文档 (ver0_base — 纯软件基线)

## 一、项目概述

基于 OpenTitan OTBN 协处理器的 ML-KEM-768 + P-256 ECDH 混合密钥协商系统 **纯软件基线版**。

所有密码学运算均在 OTBN 内部完成，使用**纯软件 Keccak-f[1600]** 实现 SHA-3（无 KMAC 硬件加速），ML-KEM 使用**基线 OTBN 指令**（无 BN 向量扩展）。Ibex 主核负责调度、数据搬移和性能测量。

> 此版本是 `test_hybrid_kem_otbn_prompt`（KMAC 硬件加速版）的**纯软件性能基线**，用于量化硬件加速（KMAC / BNMULV 宏扩展）带来的性能提升。

### 与参考版的核心差异

| 特性 | 参考版 (KMAC加速) | 基线版 (ver0_base) |
|------|-------------------|---------------------|
| SHA-3 实现 | KMAC 硬件 (CSR/WSR) | 软件 Keccak-f[1600] |
| ML-KEM 指令 | BN 向量扩展 (`bnmulv_version_id=2`) | 基线 OTBN 指令 |
| HKDF 哈希 | `kmac_init` / `kmac_squeeze_32B` | `sha3_init` / `sha3_final` |
| RTL 修改 | 需要 (7 个 RTL 文件) | **无需** |
| 构建标志 | `--bnmulv_version_id=2` | 无特殊标志 |

### 双模式设计

通过 BUILD 文件中 `defines` 控制：

| 特性 | 测试模式 | 生产模式 |
|------|---------|---------|
| 编译 | `defines = ["HYBRID_KEM_TEST_MODE"]` | 不定义该宏 |
| ML-KEM coins | 硬编码 KAT 向量 | `dif_entropy_src` TRNG |
| P-256 标量 d | 硬编码测试值 | 每轮随机生成 |
| P-256 d1 份额 | 全零 | 真随机拆分 |

### 目录结构

```
test_hybrid_kem_otbn_prompt_base/
├── BUILD                                # 顶层: opentitan_test (Ibex)
├── API.md / USAGE.md / REVISION.md / SECURITY_AND_TEST.md / RTL.md
├── ibex/
│   ├── hybrid_kem.h                     # 公共 API + 大小常量
│   ├── hybrid_kem.c                     # OTBN 调度器 + 性能计数器
│   ├── otbn_utils.h                     # MCYCLE 读取宏
│   └── hkdf_integration.h / .c          # HKDF DMEM 打包封装
└── otbn/
    ├── hkdf/                             # HKDF-SHA3-256 (纯软件)
    │   ├── BUILD
    │   ├── hkdf_sha3_256.s               # 纯函数库 (hkdf_extract / hkdf_expand)
    │   ├── hmac_sha3.s                   # 纯函数库 (hmac_sha3_256)
    │   ├── hkdf_wrapper.s                # Ibex 二进制包装 (DMEM 标签 + main)
    │   └── sha3_shake.s                  # Keccak-f[1600]
    ├── mlkem768/                         # ML-KEM-768 (纯软件)
    │   ├── BUILD
    │   ├── mlkem_keypair_test.s          # keypair 二进制包装
    │   ├── mlkem_encap_test.s            # encap 二进制包装
    │   ├── mlkem_decap_test.s            # decap 二进制包装
    │   ├── sha3_shake.s                  # Keccak-f[1600]
    │   └── 支撑文件: basemul/cbd/ntt/intt/poly/pack_keys/symmetric
    ├── p256_ecdh/                        # P-256 ECDH
    │   ├── BUILD
    │   ├── p256_ecdh_test.s              # ECDH 二进制包装
    │   └── p256_{shared_key,base,isoncurve_proj}.s
    └── test/                             # OTBN 仿真测试
        ├── BUILD                         # 7 个 otbn_sim_test 目标
        ├── sha3_shake_test.s / .exp      # SHA3/SHAKE 测试 (来自 kyber_ver0_base)
        ├── hmac_test.s                   # HMAC-SHA3-256 测试
        ├── hkdf_test.s                   # HKDF-SHA3-256 测试
        ├── hkdf_dexp.py                  # HKDF 预期输出生成器
        ├── mlkem_base_{keypair,encap,decap}_test.s / .dexp  # ML-KEM 测试
        └── p256_ecdh_shared_key_test.s / .exp               # P-256 测试
```

---

## 二、构建

### 2.1 前置条件

- OpenTitan 代码库
- RISC-V 交叉编译工具链
- Bazel 构建系统

### 2.2 OTBN 仿真测试 (otbn_sim_test)

```bash
cd ~/opentitan

# SHA-3 / SHAKE — 10 项纯软件测试（来自 kyber_ver0_base）
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:sha3_shake_test

# HMAC-SHA3-256 — 纯软件基线
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:hmac_test

# HKDF-SHA3-256 — 纯软件基线
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:hkdf_test

# ML-KEM-768 KeyPair
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:mlkem768_keypair_test

# ML-KEM-768 Encap
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:mlkem768_encap_test

# ML-KEM-768 Decap
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:mlkem768_decap_test

# P-256 ECDH
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:p256_ecdh_test

# 全部一次性运行
bazel test //test_hybrid_kem_otbn_prompt_base/otbn/test:all
```

### 2.3 OTBN 二进制构建 (otbn_binary, Ibex 集成用)

```bash
cd ~/opentitan
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_keypair_ver0
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_encap_ver0
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/mlkem768:mlkem768_decap_ver0
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/p256_ecdh:p256_ecdh_ver0
bazel build //test_hybrid_kem_otbn_prompt_base/otbn/hkdf:hkdf_sha3_256_ver0
```

### 2.4 Ibex 集成测试

```bash
# 功能测试模式
bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_test_sim_verilator \
  --sandbox_writable_path=/run/user/1000/ccache-tmp

# 生产安全模式
bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_prod_sim_verilator \
  --sandbox_writable_path=/run/user/1000/ccache-tmp

# 或禁用 ccache
CCACHE_DISABLE=1 bazel test //test_hybrid_kem_otbn_prompt_base:hybrid_kem_test
```

---

## 三、OTBN 上下文切换规范

每次密码学模块切换必须执行完整生命周期：

```
1. dif_otbn_load_app(otbn, app)          # 加载到 IMEM/DMEM
2. 写入输入参数到 DMEM                     # write_and_verify (写后回读验证)
3. dif_otbn_start(otbn)                  # 启动执行
4. dif_otbn_wait_for_done(otbn)          # 等待完成
5. 读出结果                                # otbn_testutils_read_data
6. otbn_full_sec_wipe(otbn)              # DMEM + IMEM 安全擦除
```

| 阶段 | OTBN 加载序列（严格顺序，每次切换间必须 wipe） |
|------|------------------------------------------------|
| **KeyGen** | `mlkem768_keypair_ver0` → wipe → `p256_ecdh_ver0` → wipe |
| **Encaps** | `p256_ecdh_ver0` (临时密钥) → wipe → `p256_ecdh_ver0` (ECDH) → wipe → `mlkem768_encap_ver0` → wipe → `hkdf_sha3_256_ver0` → wipe |
| **Decaps** | `p256_ecdh_ver0` → wipe → `mlkem768_decap_ver0` → wipe → `hkdf_sha3_256_ver0` → wipe |

---

## 四、性能测量

基线版内置 `mcycle` 性能计数器，自动输出：

- **各阶段总周期数**
- **每次 OTBN 调用的执行周期数**
- **安全擦除开销周期数**
- **OTBN 调用总次数**
- **DMEM 写入/读取总字节数**
- **安全擦除次数**

输出格式见 `API.md` 第八节。

---

## 五、关键安全特性

- **常数时间**: `hybrid_decaps` 始终执行完整流程（P-256 → ML-KEM → HKDF），即使中间步骤失败
- **角色绑定**: Alice=`"initiator"`, Bob=`"responder"` 编码入 IKM，防止反射攻击
- **DMEM 写入验证**: 所有 DMEM 写入后回读比对 (`write_and_verify`)
- **安全擦除**: 每次模块切换 `SecWipeDmem` + `SecWipeImem`
- **栈清零**: Ibex 侧 `memwipe`（volatile 防编译器优化）清除所有临时密钥材料
- **无硬编码 DMEM 偏移**: 全部通过 `OTBN_DECLARE_SYMBOL_ADDR` / `OTBN_ADDR_T_INIT`

---

## 六、生产部署注意事项

1. **随机数**: 切换 BUILD `defines` 去掉 `HYBRID_KEM_TEST_MODE` 启用 TRNG
2. **DMEM 地址**: 构建流水线自动生成，不要硬编码
3. **指令计数**: 从 OTBN 仿真器获取实测值填入 `HYBRID_KEM_INSNS_*` 阈值
4. **性能对比**: 本版本主要目的为与 KMAC/BNMULV 硬件加速版性能对比
5. **P-256 unmask**: 生产代码应在 OTBN 内部完成布尔共享 XOR 还原
