#!/bin/bash
set -e

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 向上搜索 OpenTitan 根目录（包含 hw/ip/otbn）
OT_ROOT=""
CUR="$SCRIPT_DIR"
while [[ "$CUR" != "/" ]]; do
    if [[ -d "$CUR/hw/ip/otbn" ]]; then
        OT_ROOT="$CUR"
        break
    fi
    CUR="$(dirname "$CUR")"
done

if [[ -z "$OT_ROOT" ]]; then
    echo "Error: Could not find OpenTitan root (missing hw/ip/otbn)"
    exit 1
fi

echo "OpenTitan root: $OT_ROOT"

# 源文件目录（位于 OpenTitan 根目录下）
SOURCE_DIR="$OT_ROOT/test/kyber_ver2/hkdf"
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

# 工具路径
OTBN_AS="$OT_ROOT/hw/ip/otbn/util/otbn_as.py"
OTBN_LD="$OT_ROOT/hw/ip/otbn/util/otbn_ld.py"
OTBN_SIM="$OT_ROOT/hw/ip/otbn/dv/otbnsim/standalone.py"
OTBN_SIM_TEST="$OT_ROOT/hw/ip/otbn/util/otbn_sim_test.py"

# 临时目录
TMPDIR="$SCRIPT_DIR/tmp-kybertest"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# 汇编 .s 文件 (hkdf_test.s 提供测试数据, hkdf_sha3_256.s 提供 main)
"$OTBN_AS" -o "$TMPDIR/hkdf_test.o" "$SOURCE_DIR/hkdf_test.s"
"$OTBN_AS" -o "$TMPDIR/hkdf_sha3_256.o" "$SOURCE_DIR/hkdf_sha3_256.s"
"$OTBN_AS" -o "$TMPDIR/hmac_sha3.o" "$SOURCE_DIR/hmac_sha3.s"
"$OTBN_AS" -o "$TMPDIR/kmac_sha3_template.o" "$SOURCE_DIR/kmac_sha3_template.s"

# 链接生成 .elf 文件 (测试 wrapper 在前, 其数据定义优先)
"$OTBN_LD" -o "$TMPDIR/hkdf_test.elf" \
    "$TMPDIR/hkdf_test.o" \
    "$TMPDIR/hkdf_sha3_256.o" \
    "$TMPDIR/hmac_sha3.o" \
    "$TMPDIR/kmac_sha3_template.o"

export PYTHONPATH="$OT_ROOT:$PYTHONPATH"

# 第一次模拟：使用 standalone.py 导出 DMEM 二进制文件（用于调试）
echo "第一次模拟：导出 DMEM 内容..."
"$OTBN_SIM" --verbose --dump-dmem "$TMPDIR/dmem.bin" "$TMPDIR/hkdf_test.elf" > "$TMPDIR/sim_standalone.log" 2>&1
echo "DMEM 已导出到: $TMPDIR/dmem.bin"
echo "模拟日志: $TMPDIR/sim_standalone.log"

# 第二次模拟：使用 otbn_sim_test.py 进行期望值比对
echo "第二次模拟：比对 DMEM 期望值..."
"$OTBN_SIM_TEST" --verbose "$OTBN_SIM" --expected_dmem "$SOURCE_DIR/hkdf_test.dexp" "$TMPDIR/hkdf_test.elf" > "$TMPDIR/sim_test.log" 2>&1
echo "模拟测试完成. 日志: $TMPDIR/sim_test.log"
