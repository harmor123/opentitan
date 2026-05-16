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
SOURCE_DIR="$OT_ROOT/test/kyber_ver2/mlkem768_keypair_ver2"
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

# Use ISA version with .16H support 
export BNMULV_VER=2 

# 工具路径
OTBN_AS="$OT_ROOT/hw/ip/otbn/util/otbn_as.py"
OTBN_LD="$OT_ROOT/hw/ip/otbn/util/otbn_ld.py"
OTBN_SIM="$OT_ROOT/hw/ip/otbn/dv/otbnsim/standalone.py"
OTBN_SIM_TEST="$OT_ROOT/hw/ip/otbn/util/otbn_sim_test.py"

# 临时目录
TMPDIR="$SCRIPT_DIR/tmp-kybertest"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# 汇编 .s 文件,key阶段没有调用intt.s 
"$OTBN_AS" -o "$TMPDIR/mlkem_base_keypair_test.o" "$SOURCE_DIR/mlkem_base_keypair_test.s"
"$OTBN_AS" -o "$TMPDIR/pack_keys.o" "$SOURCE_DIR/pack_keys.s"
"$OTBN_AS" -o "$TMPDIR/kmac_sha3_template.o" "$SOURCE_DIR/kmac_sha3_template.s"
"$OTBN_AS" -o "$TMPDIR/poly_gen_matrix.o" "$SOURCE_DIR/poly_gen_matrix.s"
"$OTBN_AS" -o "$TMPDIR/poly.o" "$SOURCE_DIR/poly.s"
"$OTBN_AS" -o "$TMPDIR/cbd.o" "$SOURCE_DIR/cbd.s"
"$OTBN_AS" -o "$TMPDIR/basemul.o" "$SOURCE_DIR/basemul.s"
"$OTBN_AS" -o "$TMPDIR/ntt.o" "$SOURCE_DIR/ntt.s"

"$OTBN_AS" -o "$TMPDIR/mlkem_keypair.o" "$SOURCE_DIR/mlkem_keypair.s"

# 链接生成 .elf 文件
"$OTBN_LD" -o "$TMPDIR/kyber768_mklem_keypair_test.elf" \
    "$TMPDIR/mlkem_base_keypair_test.o" \
    "$TMPDIR/pack_keys.o" \
    "$TMPDIR/kmac_sha3_template.o" \
    "$TMPDIR/poly_gen_matrix.o" \
    "$TMPDIR/poly.o" \
    "$TMPDIR/cbd.o" \
    "$TMPDIR/basemul.o" \
    "$TMPDIR/ntt.o" \
    "$TMPDIR/mlkem_keypair.o"

export PYTHONPATH="$OT_ROOT:$PYTHONPATH"

# 第一次模拟：使用 standalone.py 导出 DMEM 二进制文件（用于调试）
echo "第一次模拟：导出 DMEM 内容..."
"$OTBN_SIM" --verbose --dump-dmem "$TMPDIR/dmem.bin" "$TMPDIR/kyber768_mklem_keypair_test.elf" > "$TMPDIR/sim_standalone.log" 2>&1
echo "DMEM 已导出到: $TMPDIR/dmem.bin"
echo "模拟日志: $TMPDIR/sim_standalone.log"

# 第二次模拟：使用 otbn_sim_test.py 进行期望值比对
echo "第二次模拟：比对 DMEM 期望值..."
"$OTBN_SIM_TEST" --verbose "$OTBN_SIM" --expected_dmem "$SOURCE_DIR/mlkem768_keypair_test.dexp" "$TMPDIR/kyber768_mklem_keypair_test.elf" > "$TMPDIR/sim_test.log" 2>&1
echo "模拟测试完成. 日志: $TMPDIR/sim_test.log"

