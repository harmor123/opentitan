# 使用文档

## 一、项目概述

基于 OpenTitan OTBN 协处理器的 ML-KEM-768 + P-256 ECDH 混合密钥协商系统。

所有密码学运算均在 OTBN 内部完成，Ibex 主核仅负责调度和数据搬移。

> 当前在 `test_hybrid_kem_otbn_prompt/` 独立验证，全部 OTBN 仿真测试通过。后续移植到 `sw/device/tests/hybrid_kem/`。

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
test_hybrid_kem_otbn_prompt/
├── BUILD                            # 顶层: opentitan_test (Ibex)
├── USAGE.md / API.md / REVISION.md / SECURITY_AND_TEST.md
├── ibex/
│   ├── hybrid_kem.h
│   └── hybrid_kem.c
└── otbn/
    ├── hkdf/                         # HKDF-SHA3-256 (新增)
    │   ├── BUILD                     # otbn_library ×3 + otbn_binary
    │   ├── hkdf_sha3_256.s           #   251行 (纯函数库, Extract+Expand 分离)
    │   ├── hmac_sha3.s               #   179行 (合并 ipad/opad 循环优化)
    │   └── kmac_sha3_template.s
    ├── mlkem768/                     # ML-KEM-768 (三阶段合并)
    │   ├── BUILD                     # otbn_library ×12 + otbn_binary ×3
    │   ├── mlkem_keypair.s / mlkem_encap.s / mlkem_decap.s
    │   └── 共享库: basemul/cbd/intt/ntt/pack_keys/poly/poly_gen_matrix
    ├── p256_ecdh/                    # P-256 ECDH (官方 ver1, 无 MAI)
    │   ├── BUILD                     # otbn_library ×3 + otbn_binary
    │   └── p256_base.s / p256_shared_key.s / p256_isoncurve_proj.s
    └── test/
        ├── BUILD                     # otbn_sim_test ×6
        ├── mlkem768_*_test.dexp      # ML-KEM 预期值
        ├── p256_ecdh_shared_key_test.dexp
        └── sha3_test.dexp
```

---

## 二、构建

### 2.1 前置条件

- OpenTitan 代码库 + 已修改的 `rules/otbn.bzl` 和 `otbn_as.py`
- RISC-V 交叉编译工具链

### 2.2 部署

```bash
cp -r test_hybrid_kem_otbn_prompt ~/pqc/opentitan/
cp rules/otbn.bzl ~/pqc/opentitan/rules/
cp hw/ip/otbn/util/otbn_as.py ~/pqc/opentitan/hw/ip/otbn/util/
cp hw/ip/otbn/util/shared/reg_dump.py ~/pqc/opentitan/hw/ip/otbn/util/shared/
```

### 2.3 OTBN 二进制构建

```bash
cd ~/pqc/opentitan
bazel build //test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair
bazel build //test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap
bazel build //test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap
bazel build //test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh
bazel build //test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256
```

### 2.4 OTBN 仿真测试 — 全部 6 个通过

```bash
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_keypair_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_encap_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_decap_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:p256_ecdh_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:kmac_sha3_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:hkdf_test
```

### 2.5 OTBN RTL+ISS 联调 (硬件正确性验证)

构建 OTBN 独立 Verilator 模型 (一次性):

```bash
fusesoc --cores-root=. run --target=sim --setup --build \
  --flag=bnmulv_ver2 \
  --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
  --make_options="-j$(nproc)"
```

BUILD 规则运行联调 (RTL 与 ISS 逐指令比对):

```bash
# 全部 5 个 app
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:all_co_sim --test_output=all

# 单个 app
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:hkdf_co_sim    --test_output=all
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:p256_ecdh_co_sim --test_output=all
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:mlkem_keypair_co_sim
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:mlkem_encap_co_sim
bazel test //hw/ip/otbn/dv/smoke/hybrid_kem:mlkem_decap_co_sim
```

KMAC DEBUG 输出已受 `ifdef KMAC_DEBUG` 控制，默认关闭。

### 2.6 Ibex 集成测试

Ibex C 代码编译通过, Verilator 仿真待 ccache sandbox 权限修复后运行:

```bash
# 添加 sandbox writable path 解决 ccache 只读文件系统错误
bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_test \
  --sandbox_writable_path=/run/user/1000/ccache-tmp

# 或设环境变量禁用 ccache
CCACHE_DISABLE=1 bazel test //test_hybrid_kem_otbn_prompt:hybrid_kem_test
```

---

## 三、关键安全特性

- **常数时间**: hybrid_decaps 始终执行完整流程
- **角色绑定**: Alice="initiator", Bob="responder" 编码入 IKM
- **构建验证**: LOAD_CHECKSUM + 指令计数 + DMEM 写入回读
- **安全擦除**: 每次模块切换 DMEM+IMEM 双擦除
- **DMEM 地址**: 构建流水线自动解析, 无硬编码偏移

---

## 四、测试向量格式

| 类型 | 扩展名 | 格式 | BUILD 属性 |
|------|--------|------|-----------|
| 寄存器期望 | `.exp` | 文本 `name = 0xVAL` | `exp = "foo.exp"` |
| DMEM 期望 | `.dexp` | 文本 `label: hex` 或二进制 | `dexp = "foo.dexp"` |

---

## 五、生产部署注意事项

1. 随机数: 切换 BUILD `defines` 去掉 `HYBRID_KEM_TEST_MODE` 启用 TRNG
2. DMEM 地址: 构建流水线自动生成, 不要硬编码
3. 指令计数: 从 OTBN 仿真器获取实测值填入
4. P-256 MAI: 当前使用官方 P-256, MAI 加速单独评估后加回
