#!/bin/bash
set -e
set -o pipefail  # 确保管道中任何命令失败都能正确触发退出

# ==========================================
# 路径配置
# ==========================================

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/bench_v0_$(date +%Y%m%d_%H%M%S).log"

# 若日志文件尚未存在，则设置重定向；否则直接追加
if [ ! -f "$LOG_FILE" ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
else
    exec >> "$LOG_FILE" 2>&1
fi


echo ">>> Log will be saved to: $LOG_FILE"
echo ""

# ==========================================
# 以下所有输出均同时输出到屏幕和日志文件
# ==========================================
{
# 向上搜索 OpenTitan 根目录
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

PYTHON_SCRIPT="$SCRIPT_DIR/bench_mlkem768.py"
SIMULATOR="$OT_ROOT/hw/ip/otbn/dv/otbnsim/standalone.py"

# 工具路径
OTBN_AS="$OT_ROOT/hw/ip/otbn/util/otbn_as.py"
OTBN_LD="$OT_ROOT/hw/ip/otbn/util/otbn_ld.py"

# ========== 所有源码的根目录 ==========
BASE_DIR="$SCRIPT_DIR/kyber_ver0_base"

# ---------- HASH ----------
HASH_DIR="$BASE_DIR/hash"
HASH_TMP="$HASH_DIR/tmp-kybertest"
ELF_HASH="$HASH_TMP/sha3_shake_test.elf"

# ---------- ML-KEM-768 ----------
KEYPAIR_DIR="$BASE_DIR/mlkem768_keypair_ver0"
ENCAP_DIR="$BASE_DIR/mlkem768_encap_ver0"
DECAP_DIR="$BASE_DIR/mlkem768_decap_ver0"

KEYPAIR_TMP="$KEYPAIR_DIR/tmp-kybertest"
ENCAP_TMP="$ENCAP_DIR/tmp-kybertest"
DECAP_TMP="$DECAP_DIR/tmp-kybertest"

ELF_KEYPAIR="$KEYPAIR_TMP/kyber768_mklem_keypair_test.elf"
ELF_ENCAP="$ENCAP_TMP/kyber768_mklem_encap_test.elf"
ELF_DECAP="$DECAP_TMP/kyber768_mklem_decap_test.elf"

# ---------- P-256 ECDH ----------
P256_SOURCE_DIR="$BASE_DIR/p256_shared_keys"
P256_TMP="$P256_SOURCE_DIR/tmp-kybertest"
ELF_P256="$P256_TMP/p256_ecdh_shared_key_test.elf"

# ==========================================
# 自动编译缺失的 ELF 文件
# ==========================================
compile_if_missing() {
    local elf_path=$1
    local src_dir=$2
    local elf_name=$3
    shift 3
    local s_files=("$@")

    if [[ -f "$elf_path" ]]; then
        return 0
    fi

    echo "--------------------------------------------"
    echo " [自动编译] 未找到 $elf_name"
    echo " 源码目录: $src_dir"
    echo "--------------------------------------------"

    mkdir -p "$(dirname "$elf_path")"

    local obj_files=()
    for s_file in "${s_files[@]}"; do
        local obj_name=$(basename "$s_file" .s).o
        local obj_path="$(dirname "$elf_path")/$obj_name"
        echo "  汇编: $s_file"
        "$OTBN_AS" -o "$obj_path" "$src_dir/$s_file"
        obj_files+=("$obj_path")
    done

    echo "  链接: $elf_name"
    "$OTBN_LD" -o "$elf_path" "${obj_files[@]}"
    echo "  编译完成: $elf_path"
    echo "--------------------------------------------"
}

# P-256 自动编译
compile_if_missing "$ELF_P256" "$P256_SOURCE_DIR" "p256_ecdh_shared_key_test.elf" \
    "p256_ecdh_shared_key_test.s" \
    "p256_shared_key.s" \
    "p256_base.s" \
    "p256_isoncurve_proj.s"

# ==========================================
# 预检查
# ==========================================
if [[ ! -f "$PYTHON_SCRIPT" ]]; then
    echo "Error: Python script not found at $PYTHON_SCRIPT"
    exit 1
fi
if [[ ! -f "$SIMULATOR" ]]; then
    echo "Error: OTBN Simulator not found at $SIMULATOR"
    exit 1
fi

for label_path in "KEYPAIR:$ELF_KEYPAIR" "ENCAP:$ELF_ENCAP" "DECAP:$ELF_DECAP" "P256:$ELF_P256"; do
    label="${label_path%%:*}"
    path="${label_path##*:}"
    if [[ ! -f "$path" ]]; then
        echo "Error: ELF not found for $label: $path"
        exit 1
    fi
done

echo "--------------------------------------------"
echo " Python   : $PYTHON_SCRIPT"
echo " Simulator: $SIMULATOR"
echo " Hash     : $ELF_HASH"
echo " Keypair  : $ELF_KEYPAIR"
echo " Encap    : $ELF_ENCAP"
echo " Decap    : $ELF_DECAP"
echo " P-256    : $ELF_P256"
echo "--------------------------------------------"

export PYTHONPATH="$OT_ROOT:$PYTHONPATH"

# ==========================================
# 执行测试（共 5 项）
# ==========================================
echo ""
echo ">>> [1/5] Hash"
python3 "$PYTHON_SCRIPT" "$SIMULATOR" \
    "hash_test#$ELF_HASH" \
    hash_test

echo ""
echo ">>> [2/5] ML-KEM-768 Keypair"
python3 "$PYTHON_SCRIPT" "$SIMULATOR" \
    "mlkem768_keypair#$ELF_KEYPAIR" \
    mlkem768_keypair

echo ""
echo ">>> [3/5] ML-KEM-768 Encap"
python3 "$PYTHON_SCRIPT" "$SIMULATOR" \
    "mlkem768_encap#$ELF_ENCAP" \
    mlkem768_encap

echo ""
echo ">>> [4/5] ML-KEM-768 Decap"
python3 "$PYTHON_SCRIPT" "$SIMULATOR" \
    "mlkem768_decap#$ELF_DECAP" \
    mlkem768_decap

echo ""
echo ">>> [5/5] P-256 ECDH Shared Key"
python3 "$PYTHON_SCRIPT" "$SIMULATOR" \
    "p256_ecdh#$ELF_P256" \
    p256_ecdh

echo ""
echo "============================================"
echo " All 5 tests passed!"
echo " DB saved to: $SCRIPT_DIR/kyber_bench.db"
echo " Log saved to: $LOG_FILE"
echo "============================================"

} 2>&1 | tee "$LOG_FILE"
