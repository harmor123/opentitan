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

### 2.4 OTBN 仿真测试 — 全部 8 个通过

```bash
# 一键全部测试（推荐）
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:all --cache_test_results=no

# 逐个测试
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_keypair_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_encap_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:mlkem768_decap_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:p256_ecdh_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:kmac_sha3_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:hkdf_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:hmac_test
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:kmac_sha3_test
```

### 2.5 KMAC 掩码模式测试

OTBN 内部 KMAC 支持两种 squeeze 输出模式，通过 `SEC_FIX_KMAC_MASKING` 环境变量控制：

| 模式 | 环境变量 | WSR 8 (share0) | WSR 9 (share1) | 对应 RTL 参数 |
|------|---------|---------------|---------------|-------------|
| 确定性 (DV) | `SEC_FIX_KMAC_MASKING=1` (默认) | plain | **0** | `SecFixKmacMasking=1` |
| 掩码 (SCA) | `SEC_FIX_KMAC_MASKING=0` | plain ⊕ URND | **URND** (非零) | `SecFixKmacMasking=0` |

```bash
# 确定性模式（默认 — dexp 期望值直接比对）
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:all --cache_test_results=no

# 掩码模式（2-share URND 掩码 — OTBN asm 内部 XOR 解掩码后结果一致）
SEC_FIX_KMAC_MASKING=0 bazel test //test_hybrid_kem_otbn_prompt/otbn/test:all --cache_test_results=no
```

两种模式都 PASS → 掩码+解掩码正确。

**直观验证掩码生效**（standalone verbose trace）：

```bash
# 掩码模式 — s1 应为非零随机数
SEC_FIX_KMAC_MASKING=0 hw/ip/otbn/dv/otbnsim/standalone.py --verbose \
    /path/to/sha3_test_bin.elf 2>&1 | grep 'kmac_data_s1' | head -3
# w10 = 0x...23ccf4f87016af27  ← 非零掩码

# 确定性模式 — s1 应为全零
SEC_FIX_KMAC_MASKING=1 hw/ip/otbn/dv/otbnsim/standalone.py --verbose \
    /path/to/sha3_test_bin.elf 2>&1 | grep 'kmac_data_s1' | head -3
# w10 = 0x0000000000000000  ← 全零
```

### 2.5 OTBN RTL smoke 测试 — KMAC + Bigint

```bash
# KMAC smoke (SHA3/SHAKE 确定性测试)
hw/ip/otbn/dv/smoke/run_kmac_smoke.sh
hw/ip/otbn/dv/smoke/run_kmac_shake128_run.sh
hw/ip/otbn/dv/smoke/run_kmac_pad_edge.sh

# OTBN full smoke
hw/ip/otbn/dv/smoke/run_smoke.sh
hw/ip/otbn/dv/smoke/run_smoke.sh vectorized

# Bigint (bnmulv_ver2)
hw/ip/otbn/dv/smoke/bnmulv_ver2/run_bnminimal_lid.sh
hw/ip/otbn/dv/smoke/bnmulv_ver2/run_bnaddsubv.sh
# ... 全部 9 个 bnmulv test

# 一键全部
for t in hw/ip/otbn/dv/smoke/run_kmac_smoke.sh \
         hw/ip/otbn/dv/smoke/run_kmac_shake128_run.sh \
         hw/ip/otbn/dv/smoke/run_kmac_pad_edge.sh \
         hw/ip/otbn/dv/smoke/run_smoke.sh; do
    printf "%-50s" "$t"
    timeout 360s bash $t 2>&1 | grep -q "PASS" && echo "PASS" || echo "FAIL"
done
```

### 2.6 KMAC 掩码模式测试

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

## 五、合并上游 OpenTitan 官方改动

### 5.1 首次设置（仅一次）

```bash
cd ~/pqc/opentitan
git remote add upstream https://github.com/lowRISC/opentitan.git
git remote -v  # 确认: origin=你的fork, upstream=官方
```

### 5.2 定期合并流程

```bash
# 1. 确保本地无未提交改动
git status

# 2. 拉取上游最新
git fetch upstream master

# 3. 合并（--no-commit 可先预览，--no-ff 保留合并记录）
git merge upstream/master --no-commit --no-ff

# 4. 检查冲突（通常很少）
git diff --name-only --diff-filter=U
```

### 5.3 处理冲突

| 文件类型 | 处理方式 |
|---------|---------|
| `test_hybrid_kem_otbn_prompt/**` | 你的专属文件 → `git checkout --ours <file>` |
| `hw/ip/otbn/rtl/otbn_${kmac,rnd,pkg,core}.sv`, `otbn.sv` | 你的 B2 实现 → `git checkout --ours <file>` |
| 官方 bugfix / 你没改过的文件 | `git checkout --theirs <file>` |
| 两边改过同一行（罕见） | 手动编辑，删 `<<<<<<`/`====`/`>>>>>>` 标记 |

### 5.4 验证合并正确性

```bash
# 确认 B2 改动完整保留
grep "KmacDomWidth\|kmac_dom_rand\|EnMaskingOtnb\|SecFixKmacMasking" \
    hw/ip/otbn/rtl/otbn_pkg.sv \
    hw/ip/otbn/rtl/otbn_kmac.sv \
    hw/ip/otbn/rtl/otbn_rnd.sv \
    hw/ip/otbn/rtl/otbn_core.sv \
    hw/ip/otbn/rtl/otbn.sv | wc -l
# 应输出 47+（合并前基准）

# 确认 test 目录完整
ls test_hybrid_kem_otbn_prompt/ibex/ test_hybrid_kem_otbn_prompt/otbn/

# 跑测试验证
bazel test //test_hybrid_kem_otbn_prompt/otbn/test:all --cache_test_results=no
```

### 5.5 提交并推送

```bash
git commit -m "merge upstream/master"
git push origin master
```

---

## 六、生产部署注意事项

1. 随机数: 切换 BUILD `defines` 去掉 `HYBRID_KEM_TEST_MODE` 启用 TRNG
2. DMEM 地址: 构建流水线自动生成, 不要硬编码
3. 指令计数: 从 OTBN 仿真器获取实测值填入
4. P-256 MAI: 当前使用官方 P-256, MAI 加速单独评估后加回
