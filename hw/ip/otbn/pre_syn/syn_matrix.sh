#!/bin/bash
# ==============================================================================
# syn_matrix.sh — OTBN 面积基准矩阵测试
#
# 用法: bash syn_matrix.sh <config>
# 配置: baseline | baseline_kmac | baseline_kmac_masked | paper2_ver2 | paper2_ver2_kmac
#
# 与 syn_kmac_ab.sh 的区别:
#   1. 5 配置矩阵（非仅 baseline/kmac）
#   2. 精确文件列表（不包含未使用的 .sv）
#   3. BNMULV/TOWARDS_BASE 宏控制
#   4. EnMasking 参数切换
# ==============================================================================
set -e; set -o pipefail

CONFIG="${1:?Usage: $0 <baseline|baseline_kmac|baseline_kmac_masked|paper2_ver2|paper2_ver2_kmac>}"

case "$CONFIG" in
  baseline|baseline_kmac|baseline_kmac_masked|paper2_ver2|paper2_ver2_kmac) ;;
  *) echo >&2 "Error: Unknown config '$CONFIG'"; exit 1 ;;
esac

error () { echo >&2 "$@"; exit 1; }
teelog () { tee "$LR_SYNTH_OUT_DIR/log/$1.log"; }

[ -f syn_setup.sh ] || error "No syn_setup.sh file: see README.md for instructions"

#-------------------------------------------------------------------------
# setup flow variables
#-------------------------------------------------------------------------
source syn_setup.sh
export LR_SYNTH_FLATTEN=0

#-------------------------------------------------------------------------
# output dir
#-------------------------------------------------------------------------
LR_SYNTH_OUT_DIR=$(date +"syn_out/${CONFIG}_%Y_%m_%d_%H_%M_%S")
export LR_SYNTH_OUT_DIR
mkdir -p "$LR_SYNTH_OUT_DIR"/{generated,log,reports/timing}
rm -f syn_out/latest && ln -s "${LR_SYNTH_OUT_DIR#syn_out/}" syn_out/latest

echo "=============================================="
echo "  Config: $CONFIG"
echo "  Out:    $LR_SYNTH_OUT_DIR"
echo "=============================================="

export LR_SYNTH_SRC_DIR="../../$LR_SYNTH_IP_NAME"  # = ../../otbn

# ==============================================================================
# Macro matrix
# ==============================================================================
case "$CONFIG" in
  baseline)
    OT_DEFINES=(--define=SYNTHESIS --define=SYN_NO_KMAC)
    EN_MASKING=0 ;;
  baseline_kmac)
    OT_DEFINES=(--define=SYNTHESIS)
    EN_MASKING=0 ;;
  baseline_kmac_masked)
    OT_DEFINES=(--define=SYNTHESIS)
    EN_MASKING=1 ;;
  paper2_ver2)
    # BNMULV + ACCH: TOWARDS_BASE excluded (triggers Yosys simplify.cc:2731 bug).
    # TOWARDS_BASE adds only 16-bit vector MUXes, negligible area.
    OT_DEFINES=(--define=SYNTHESIS --define=SYN_NO_KMAC --define=BNMULV --define=BNMULV_ACCH)
    EN_MASKING=0 ;;
  paper2_ver2_kmac)
    OT_DEFINES=(--define=SYNTHESIS --define=BNMULV --define=BNMULV_ACCH)
    EN_MASKING=0 ;;
esac

echo ">>> Defines: ${OT_DEFINES[@]}"
echo ">>> EnMasking: $EN_MASKING"

# EnMasking 参数切换（仅 masked 配置）
MASKING_RESTORE=0
if [ "$EN_MASKING" -eq 1 ]; then
  sed -i 's/EnMaskingOtnb = 1'\''b0/EnMaskingOtnb = 1'\''b1/' "$LR_SYNTH_SRC_DIR"/rtl/otbn_core.sv
  MASKING_RESTORE=1
  echo ">>> EnMaskingOtnb = 1'b1 (masked mode)"
fi

# ==============================================================================
# 1. Package files (include context, not synthesized directly)
# ==============================================================================
PKG_DIRS=(
  "$LR_SYNTH_SRC_DIR/../../top_earlgrey/rtl"
  "$LR_SYNTH_SRC_DIR/../edn/rtl"
  "$LR_SYNTH_SRC_DIR/../csrng/rtl"
  "$LR_SYNTH_SRC_DIR/../entropy_src/rtl"
  "$LR_SYNTH_SRC_DIR/../lc_ctrl/rtl"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl"
  "$LR_SYNTH_SRC_DIR/../prim/rtl"
  "$LR_SYNTH_SRC_DIR/../prim_generic/rtl"
  "$LR_SYNTH_SRC_DIR/../keymgr/rtl"
  "$LR_SYNTH_SRC_DIR/../otp_ctrl/rtl"
)
PKG_FILES=()
for dir in "${PKG_DIRS[@]}"; do
  [ -d "$dir" ] && for f in "$dir"/*_pkg.sv; do
    [ -f "$f" ] && PKG_FILES+=("$f")
  done
done
# KMAC pkg (仅非 SYN_NO_KMAC)
if [[ ! " ${OT_DEFINES[*]} " =~ "SYN_NO_KMAC" ]]; then
  for f in "$LR_SYNTH_SRC_DIR/../kmac/rtl/"*_pkg.sv; do
    [ -f "$f" ] && PKG_FILES+=("$f")
  done
fi

# OTBN local pkgs
PKG_FILES+=("$LR_SYNTH_SRC_DIR"/rtl/otbn_pkg.sv)
PKG_FILES+=("$LR_SYNTH_SRC_DIR"/rtl/otbn_reg_pkg.sv)

# ==============================================================================
# 2. External dependency sources
# ==============================================================================
DEP_DEFINES=(--define=SYNTHESIS --define=SYNTHESIS_MEMORY_BLACK_BOXING --define=YOSYS)

OT_DEP_SOURCES=(
  # tlul (11 files)
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_adapter_reg.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_err.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_cmd_intg_chk.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_rsp_intg_gen.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_data_integ_dec.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_data_integ_enc.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_adapter_sram.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_sram_byte.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_socket_1n.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_err_resp.sv"
  "$LR_SYNTH_SRC_DIR/../tlul/rtl/tlul_fifo_sync.sv"
  # prim (35 files — actual used subset)
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_secded_inv_64_57_dec.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_secded_inv_64_57_enc.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_secded_inv_39_32_dec.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_secded_inv_39_32_enc.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_sparse_fsm_flop.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_subreg.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_subreg_ext.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_subreg_shadow.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_subreg_arb.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_alert_sender.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_diff_decode.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_lc_sync.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_sync_reqack_data.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_sync_reqack.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_packer_fifo.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_lfsr.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_cdc_rand_delay.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_reg_we_check.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_onehot_check.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_mubi4_sender.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_fifo_sync_cnt.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_sec_anchor_buf.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_sec_anchor_flop.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_intr_hw.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_edn_req.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_fifo_sync.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_arbiter_fixed.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_packer.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_count.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_double_lfsr.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_onehot_mux.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_onehot_enc.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_blanker.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_crc32.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_xoshiro256pp.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_ram_1p_scr.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_ram_1p_adv.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_subst_perm.sv"
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_prince.sv"
  # URND PRNG (always needed by otbn_rnd)
  "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_trivium.sv"
  # prim_generic + prim_xilinx
  "$LR_SYNTH_SRC_DIR/../prim_generic/rtl/prim_flop_2sync.sv"
  "$LR_SYNTH_SRC_DIR/../prim_generic/rtl/prim_ram_1p.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_flop.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_flop_en.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_and2.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_buf.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_xor2.sv"
  "$LR_SYNTH_SRC_DIR/../prim_xilinx/rtl/prim_xnor2.sv"
)

# KMAC 额外依赖（仅非 SYN_NO_KMAC 配置）
if [[ ! " ${OT_DEFINES[*]} " =~ "SYN_NO_KMAC" ]]; then
  OT_DEP_SOURCES+=(
    "$LR_SYNTH_SRC_DIR/../kmac/rtl/keccak_round.sv"
    "$LR_SYNTH_SRC_DIR/../kmac/rtl/keccak_2share.sv"
    "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_keccak.sv"
    "$LR_SYNTH_SRC_DIR/../prim/rtl/prim_dom_and_2share.sv"
  )
fi

# Convert dependency sources
for file in "${OT_DEP_SOURCES[@]}"; do
  [ -f "$file" ] || continue
  module=$(basename -s .sv "$file")
  echo "$module" | grep -q '_pkg$' && continue
  sv2v "${DEP_DEFINES[@]}" "${PKG_FILES[@]}" \
    -I"$LR_SYNTH_SRC_DIR"/../prim/rtl \
    "$file" > "$LR_SYNTH_OUT_DIR/generated/${module}.v"
  sed -i '/$value\$plusargs(.*/d' "$LR_SYNTH_OUT_DIR/generated/${module}.v"
done

# Fix prim_sparse_fsm_flop naming
sed -i 's/module prim_sparse_fsm_flop_.*/module prim_sparse_fsm_flop (/g' \
  "$LR_SYNTH_OUT_DIR/generated/prim_sparse_fsm_flop.v" 2>/dev/null || true

# Fix KMAC dependency files
for f in keccak_round keccak_2share prim_keccak; do
  [ -f "$LR_SYNTH_OUT_DIR/generated/${f}.v" ] || continue
  sed -i 's/prim_sparse_fsm_flop_.*/prim_sparse_fsm_flop \#(/g' "$LR_SYNTH_OUT_DIR/generated/${f}.v"
  sed -i '/\.StateEnumT[_(].*Width.*(.*/d' "$LR_SYNTH_OUT_DIR/generated/${f}.v"
done

# ==============================================================================
# 3. OTBN core RTL — precise file list (no unused .sv)
# ==============================================================================
OTBN_CORE=(
  otbn_controller otbn_decoder otbn_predecode otbn_instruction_fetch
  otbn_rf_base otbn_rf_bignum otbn_rf_base_ff otbn_rf_bignum_ff
  otbn_lsu otbn_alu_base otbn_alu_bignum
  otbn_mac_bignum_fsm otbn_mac_bignum
  otbn_mod_result_selector
  otbn_vec_adder otbn_vec_multiplier otbn_vec_shifter otbn_vec_transposer
  otbn_mai otbn_mask_accelerator
  otbn_loop_controller otbn_stack
  otbn_rnd otbn_start_stop_control
  otbn_kmac
  otbn_core
  otbn_reg_top otbn_scramble_ctrl otbn
)

# bn_vec_core files (only for BNMULV)
# unified_mul: BNMULV multiplier replacement
# buffer_bit: default MAC_ADDER + ALU_ADDER for BNMULV
# (mul_dsp, otbn_bignum_mul, and all adder variants are NOT instantiated)
BNVEC=(
  unified_mul buffer_bit
)

should_include_otbn() {
  case "$1" in
    otbn_sec_add) return 1 ;;                 # never instantiated in otbn_core
    otbn_mul) return 1 ;;                     # dead code, no references
    otbn_rf_base_fpga|otbn_rf_bignum_fpga) return 1 ;; # FPGA-only
    otbn_bignum_mul|mul_dsp) return 1 ;;      # not instantiated
    *) return 0 ;;
  esac
}

for module in "${OTBN_CORE[@]}"; do
  should_include_otbn "$module" || continue
  sv2v "${OT_DEFINES[@]}" "${PKG_FILES[@]}" \
    -I"$LR_SYNTH_SRC_DIR"/../prim/rtl \
    "$LR_SYNTH_SRC_DIR/rtl/${module}.sv" \
    > "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || {
    echo "WARNING: sv2v failed for $module, skipping"
    continue
  }
  # Fix prim_sparse_fsm_flop instances
  sed -i 's/prim_sparse_fsm_flop_.*/prim_sparse_fsm_flop \#(/g' \
    "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
  sed -i '/\.StateEnumT[_(].*Width.*(.*/d' "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
  sed -i '/operation_i\.op\.name()/d' "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
done

# bn_vec_core files (only when BNMULV defined)
if [[ " ${OT_DEFINES[*]} " =~ "BNMULV" ]]; then
  for module in "${BNVEC[@]}"; do
    sv2v "${OT_DEFINES[@]}" "${PKG_FILES[@]}" \
      -I"$LR_SYNTH_SRC_DIR"/../prim/rtl \
      "$LR_SYNTH_SRC_DIR/rtl/bn_vec_core/${module}.sv" \
      > "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || {
      echo "WARNING: sv2v failed for bn_vec_core/$module, skipping"
      continue
    }
    sed -i 's/prim_sparse_fsm_flop_.*/prim_sparse_fsm_flop \#(/g' \
      "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
    sed -i '/\.StateEnumT[_(].*Width.*(.*/d' "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
    sed -i '/operation_i\.op\.name()/d' "$LR_SYNTH_OUT_DIR/generated/${module}.v" 2>/dev/null || true
  done
fi

# ==============================================================================
# 4. Yosys synthesis
# ==============================================================================
yosys -c ./tcl/yosys_run_synth.tcl |& teelog syn || {
  error "Failed to synthesize RTL with Yosys"
}

# ==============================================================================
# 5. Area report
# ==============================================================================
python3 python/get_kge.py "$LR_SYNTH_CELL_LIBRARY_PATH" \
  "$LR_SYNTH_OUT_DIR/reports/area.rpt" 2>/dev/null && echo "" || true

echo ""
echo "=== $CONFIG: 关键模块面积 ==="
grep -E "Number of cells|Chip area|otbn_kmac|keccak_round|unified_mul|buffer_bit|otbn_mac_bignum|otbn_alu_bignum|otbn_rnd" \
  "$LR_SYNTH_OUT_DIR/reports/area.rpt" 2>/dev/null || true

# ==============================================================================
# Restore EnMasking
# ==============================================================================
if [ "$MASKING_RESTORE" -eq 1 ]; then
  sed -i 's/EnMaskingOtnb = 1'\''b1/EnMaskingOtnb = 1'\''b0/' "$LR_SYNTH_SRC_DIR"/rtl/otbn_core.sv
  echo ">>> EnMaskingOtnb restored to 1'b0"
fi

echo ""
echo "=== $CONFIG: DONE ==="
echo "Area report: $LR_SYNTH_OUT_DIR/reports/area.rpt"
