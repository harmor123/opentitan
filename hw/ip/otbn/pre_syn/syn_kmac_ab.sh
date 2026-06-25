#!/bin/bash
# ==============================================================================
# syn_kmac_ab.sh — OTBN baseline vs +otbn_kmac 面积增量
#
# 基于官方 syn_yosys.sh，最小改动:
#   1. OT_DEP_SOURCES 追加 3 个 KMAC 文件
#   2. OT_DEP_PACKAGES 追加 kmac_pkg
#   3. 核心 RTL sv2v 追加 --define=SYN_NO_KMAC (仅 baseline 模式)
#   4. FLATTEN=0 + 分层面积报告
# ==============================================================================
set -e
set -o pipefail

MODE="${1:?Usage: $0 <baseline|kmac|ver2_base|ver2_kmac|modp256|ver2_modp256>}"
if [ "$MODE" != "baseline" ] && [ "$MODE" != "kmac" ] && \
   [ "$MODE" != "ver2_base" ] && [ "$MODE" != "ver2_kmac" ] && \
   [ "$MODE" != "modp256" ] && [ "$MODE" != "ver2_modp256" ]; then
    echo >&2 "Error: MODE must be 'baseline', 'kmac', 'ver2_base', 'ver2_kmac', 'modp256', or 'ver2_modp256'"
    exit 1
fi

error () {
    echo >&2 "$@"
    exit 1
}

teelog () {
    tee "$LR_SYNTH_OUT_DIR/log/$1.log"
}

if [ ! -f syn_setup.sh ]; then
    error "No syn_setup.sh file: see README.md for instructions"
fi

#-------------------------------------------------------------------------
# setup flow variables
#-------------------------------------------------------------------------
source syn_setup.sh

# ★ 覆盖: 保留层次以获取分层面积
export LR_SYNTH_FLATTEN=0

#-------------------------------------------------------------------------
# prepare output folders
#-------------------------------------------------------------------------
LR_SYNTH_OUT_DIR_PREFIX="syn_out/ab_${MODE}"
LR_SYNTH_OUT_DIR=$(date +"${LR_SYNTH_OUT_DIR_PREFIX}_%Y_%m_%d_%H_%M_%S")
export LR_SYNTH_OUT_DIR

mkdir -p "$LR_SYNTH_OUT_DIR/generated"
mkdir -p "$LR_SYNTH_OUT_DIR/log"
mkdir -p "$LR_SYNTH_OUT_DIR/reports/timing"

rm -f syn_out/latest_ab
ln -s "${LR_SYNTH_OUT_DIR#syn_out/}" syn_out/latest_ab

echo "=============================================="
echo "  KMAC A/B Synthesis: $MODE"
echo "  Out dir: $LR_SYNTH_OUT_DIR"
echo "  Flatten: $LR_SYNTH_FLATTEN"
echo "  Top:     $LR_SYNTH_TOP_MODULE"
echo "=============================================="

#-------------------------------------------------------------------------
# use sv2v to convert all SystemVerilog files to Verilog
#-------------------------------------------------------------------------
export LR_SYNTH_SRC_DIR="../../$LR_SYNTH_IP_NAME"

# ★ KMAC defines — only difference between baseline and kmac modes
if [ "$MODE" = "baseline" ] || [ "$MODE" = "ver2_base" ] || [ "$MODE" = "ver2_modp256" ]; then
    KMAC_DEFINE=(--define=SYN_NO_KMAC)
    echo ">>> SYN_NO_KMAC=1  (otbn_kmac removed)"
else
    KMAC_DEFINE=()
    echo ">>> SYN_NO_KMAC=0  (otbn_kmac present)"
fi

# ★ MODP256 defines — A/B test for modp256 area
if [ "$MODE" = "baseline" ] || [ "$MODE" = "kmac" ] || [ "$MODE" = "ver2_base" ]; then
    MODP256_DEFINE=(--define=SYN_NO_MODP256)
    echo ">>> SYN_NO_MODP256=1  (otbn_modp256 removed)"
else
    MODP256_DEFINE=()
    echo ">>> SYN_NO_MODP256=0  (otbn_modp256 present)"
fi

# ★ ver2 defines — enable BNMULV unified multiplier
if [ "$MODE" = "ver2_base" ] || [ "$MODE" = "ver2_kmac" ] || [ "$MODE" = "ver2_modp256" ]; then
    VER2_DEFINE=(--define=BNMULV --define=BNMULV_ACCH)
    echo ">>> BNMULV=1 BNMULV_ACCH=1  (ver2 unified multiplier)"
else
    VER2_DEFINE=()
fi

#-------------------------------------------------------------------------
# Get OpenTitan dependency sources (official list + KMAC additions) ★
#-------------------------------------------------------------------------
OT_DEP_SOURCES=(
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_adapter_reg.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_err.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_cmd_intg_chk.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_rsp_intg_gen.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_data_integ_dec.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_data_integ_enc.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_secded_inv_64_57_dec.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_secded_inv_64_57_enc.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_secded_inv_39_32_dec.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_secded_inv_39_32_enc.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_sparse_fsm_flop.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_subreg.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_subreg_ext.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_subreg_shadow.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_subreg_arb.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_alert_sender.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_diff_decode.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_lc_sync.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_sync_reqack_data.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_sync_reqack.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_packer_fifo.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_lfsr.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_cdc_rand_delay.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_reg_we_check.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_onehot_check.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_mubi4_sender.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_fifo_sync_cnt.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_sec_anchor_buf.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_sec_anchor_flop.sv
    "$LR_SYNTH_SRC_DIR"/../prim_generic/rtl/prim_flop_2sync.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_flop.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_flop_en.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_and2.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_buf.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_xor2.sv
    "$LR_SYNTH_SRC_DIR"/../prim_xilinx/rtl/prim_xnor2.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_adapter_sram.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_sram_byte.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_socket_1n.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_err_resp.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/tlul_fifo_sync.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_intr_hw.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_edn_req.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_fifo_sync.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_arbiter_fixed.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_packer.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_count.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_double_lfsr.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_onehot_mux.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_onehot_enc.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_blanker.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_crc32.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_xoshiro256pp.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_ram_1p_scr.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_ram_1p_adv.sv
    "$LR_SYNTH_SRC_DIR"/../prim_generic/rtl/prim_ram_1p.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_subst_perm.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_prince.sv
    # ★ 额外依赖 — 官方脚本遗漏的模块
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_trivium.sv
    "$LR_SYNTH_SRC_DIR"/../kmac/rtl/keccak_round.sv
    "$LR_SYNTH_SRC_DIR"/../kmac/rtl/keccak_2share.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_keccak.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/prim_dom_and_2share.sv
)

# Get OpenTitan dependency packages (official list + KMAC pkg) ★
OT_DEP_PACKAGES=(
    "$LR_SYNTH_SRC_DIR"/../../top_earlgrey/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../edn/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../csrng/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../entropy_src/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../lc_ctrl/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../tlul/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../prim/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../prim_generic/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../keymgr/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../otp_ctrl/rtl/*_pkg.sv
    "$LR_SYNTH_SRC_DIR"/../kmac/rtl/*_pkg.sv
)

#-------------------------------------------------------------------------
# Convert OpenTitan dependency sources (identical to official)            
#-------------------------------------------------------------------------
for file in "${OT_DEP_SOURCES[@]}"; do
    module=`basename -s .sv $file`

    # Skip packages
    if echo "$module" | grep -q '_pkg$'; then
        continue
    fi

    sv2v \
        --define=SYNTHESIS --define=SYNTHESIS_MEMORY_BLACK_BOXING --define=YOSYS \
        "${OT_DEP_PACKAGES[@]}" \
        -I"$LR_SYNTH_SRC_DIR"/../prim/rtl \
        $file \
        > $LR_SYNTH_OUT_DIR/generated/${module}.v

    # Remove calls to $value$plusargs(). Yosys doesn't seem to support this.
    sed -i '/$value$plusargs(.*/d' $LR_SYNTH_OUT_DIR/generated/${module}.v
done

# Rename the prim_sparse_fsm_flop module (unchanged)
sed -i 's/module prim_sparse_fsm_flop_.*/module prim_sparse_fsm_flop \(/g' \
    $LR_SYNTH_OUT_DIR/generated/prim_sparse_fsm_flop.v

# ★ KMAC dependency files also use prim_sparse_fsm_flop — apply same instance fix
for f in "$LR_SYNTH_OUT_DIR"/generated/keccak_round.v \
         "$LR_SYNTH_OUT_DIR"/generated/keccak_2share.v \
         "$LR_SYNTH_OUT_DIR"/generated/prim_keccak.v; do
    [ -f "$f" ] || continue
    sed -i 's/prim_sparse_fsm_flop_.*/prim_sparse_fsm_flop \#(/g' "$f"
    # Remove StateEnumT parameters (yosys can't handle sv2v's expanded types).
    # Pattern covers otbn_pkg, sha3_pkg, and any other prefix.
    sed -i '/\.StateEnumT[_(].*Width.*(.*/d' "$f"
done

#-------------------------------------------------------------------------
# Get and convert core sources (official + SYN_NO_KMAC for baseline)      ★
#-------------------------------------------------------------------------
for file in "$LR_SYNTH_SRC_DIR"/rtl/*.sv; do
    module=`basename -s .sv $file`

    # Skip packages
    if echo "$module" | grep -q '_pkg$'; then
        continue
    fi

    sv2v \
        --define=SYNTHESIS \
        "${KMAC_DEFINE[@]}" \
        "${MODP256_DEFINE[@]}" \
        "${VER2_DEFINE[@]}" \
        "${OT_DEP_PACKAGES[@]}" \
        "$LR_SYNTH_SRC_DIR"/rtl/*_pkg.sv \
        -I"$LR_SYNTH_SRC_DIR"/../prim/rtl \
        $file \
        > $LR_SYNTH_OUT_DIR/generated/${module}.v

    # ★ Fix: removed instance-rename sed lines that mapped prim_* → prim_xilinx_*.
    # OT_DEP_SOURCES already loads prim_xilinx/rtl/ modules (named prim_flop, prim_buf,
    # etc.), so renaming instances to prim_xilinx_flop/prim_xilinx_buf creates references
    # to modules that don't exist.  Loading the xilinx files directly is sufficient —
    # there is no generic/xilinx name collision because the generic primitives are NOT
    # in OT_DEP_SOURCES.

    # Rename prim_sparse_fsm_flop instances (unchanged)
    sed -i 's/prim_sparse_fsm_flop_.*/prim_sparse_fsm_flop \#(/g' \
        $LR_SYNTH_OUT_DIR/generated/${module}.v

    # Remove the StateEnumT parameter (unchanged)
    sed -i '/\.StateEnumT(logic \[.*/d' $LR_SYNTH_OUT_DIR/generated/${module}.v
    sed -i '/\.StateEnumT_otbn_pkg.*Width.*(.*/d' $LR_SYNTH_OUT_DIR/generated/${module}.v
done

#-------------------------------------------------------------------------
# run Yosys synthesis (official)                                          
#-------------------------------------------------------------------------
yosys -c ./tcl/yosys_run_synth.tcl |& teelog syn || {
    error "Failed to synthesize RTL with Yosys"
}

#-------------------------------------------------------------------------
# run static timing analysis (official)                                   
#-------------------------------------------------------------------------
if [[ $LR_SYNTH_TIMING_RUN == 1 ]] ; then
    sta ./tcl/sta_run_reports.tcl |& teelog sta || {
        error "Failed to run static timing analysis"
    }
    ./translate_timing_rpts.sh
fi

#-------------------------------------------------------------------------
# report kGE number (official)                                            
#-------------------------------------------------------------------------
python/get_kge.py $LR_SYNTH_CELL_LIBRARY_PATH $LR_SYNTH_OUT_DIR/reports/area.rpt

#-------------------------------------------------------------------------
# ★ 分层面积报告 (新增)
#-------------------------------------------------------------------------
echo ">>> Generating hierarchical area report..."

HIER_TCL="$LR_SYNTH_OUT_DIR/generated/_hier_area.tcl"

cat > "$HIER_TCL" << 'HIER_EOF'
yosys "read_verilog -sv $::env(LR_SYNTH_OUT_DIR)/generated/otbn_core.pre_map.v"
# pre_map.v already has parameters resolved ($paramod\otbn_core\...).
# Use hierarchy -top with wildcard to auto-detect the parameterized name.
yosys "hierarchy -top $::env(LR_SYNTH_TOP_MODULE)"

set fh [open "$::env(LR_SYNTH_OUT_DIR)/reports/hier_area.rpt" w]
puts $fh "============================================================"
puts $fh "  KMAC A/B - Hierarchical Area Report"
puts $fh "============================================================"

foreach mod [list \
  *otbn_kmac* \
  *keccak_round* \
  *prim_keccak* \
  *prim_dom_and_2share* \
  *otbn_mac_bignum* \
  *otbn_alu_bignum* \
  *otbn_rf_bignum* \
  *otbn_controller* \
  *otbn_rnd* \
  *otbn_lsu* \
  *otbn_loop_controller* \
  *otbn_mai* \
  *otbn_stack* \
  *otbn_instruction_fetch* \
  *otbn_start_stop_control* \
  *otbn_mac_bignum_fsm* \
  *otbn_mul_unified* \
  *otbn_adder_buffer_bit* \
  *otbn_modp256* \
  *otbn_vec_multiplier* \
] {
  if {[llength [yosys "select -list $mod"]] > 0} {
    puts $fh "\n--- $mod ---"
    yosys "tee -a $::env(LR_SYNTH_OUT_DIR)/reports/hier_area.rpt stat -liberty $::env(LR_SYNTH_CELL_LIBRARY_PATH)"
  }
}

puts $fh "\n=== TOTAL ==="
yosys "tee -a $::env(LR_SYNTH_OUT_DIR)/reports/hier_area.rpt stat -liberty $::env(LR_SYNTH_CELL_LIBRARY_PATH)"
close $fh
HIER_EOF

yosys -c "$HIER_TCL" 2>&1 | tee -a "$LR_SYNTH_OUT_DIR/log/syn.log" || \
    echo "NOTE: hierarchical area report failed (non-fatal). Use area.rpt for totals."

echo ""
echo "=============================================="
echo "  Synthesis complete: $MODE"
echo "  Area:     $LR_SYNTH_OUT_DIR/reports/area.rpt"
echo "  Hier:     $LR_SYNTH_OUT_DIR/reports/hier_area.rpt"
echo "=============================================="
