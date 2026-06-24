// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

/**
 * OTBN bignum multiply and accumulate module
 *
 * This module supports 3 types of multiplication and accumulation instructions:
 * - bn.mulqacc: Regular 64-bit multiplication with result shifting and accumulation capabilities
 *     (see instruction description). The 64-bit multiplication operands can be selected from the
 *     input WDRs. Executes in one cycle.
 * - bn.mulv(l): Vectorized multiplication of 32-bit elements from 256-bit vectors (WDRs). Operates
 *     either vector-element-wise or multiples each element of vector A with a fixed element of
 *     vector B. The later mode is referred to as lane-wise multiplication. Performs two 32-bit
 *     multiplications in parallel and takes 4 cycles to process the 256-bit vectors.
 * - bn.mulvm(l): Vectorized Montgomery multiplication of 32-bit elements from 256-bit vectors
 *     (WDRs). Also supports the lane mode. Performs two Montgomery multiplications in parallel
 *     over the duration of 3 cycles. It takes 3 * 4 = 12 cycles to process the 256-bit vectors.
 *     The final conditional subtraction step of the Montgomery algorithm is neglected to optimize
 *     area and timing. See below for more details about the Montgomery implementation.
 *
 * The multi-cycle instructions stall the OTBN pipeline by keeping the operation_valid_o flag low
 * until the computation has finished. This multi-cycle logic is controlled by an internal FSM
 * which controls the data path. It operates in tandem with a duplicate in the instruction fetch
 * stage. This duplicate generates the predecoded signals which are compared here to the locally
 * generated signals.
 *
 * The main components of this module are a vectorized 64-bit multiplier capable of computing
 * either 1 64-bit or 2 32-bit multiplications at once, a vectorized 256-bit adder as well as the
 * 256-bit wide ACC WSR. These components allow to implement the regular 64-bit multiplication with
 * accumulation in a single cycle. For the vectorized multiplications, the multiplications are
 * pipelined on the vectorized multiplier to save area. The partial results are combined to a full
 * 256-bit vector using the ACC WSR. As the Montgomery multiplication requires 3 multiplications
 * these are also pipelined on the vectorized multiplier and the final result is constructed in the
 * ACC WSR. Both vectorized instructions clear the ACC WSR at the end of the instruction using
 * random data supplied externally. See below.
 *
 * Montgomery implementation details:
 * The Montgomery algorithm efficiently computes a multiplication and reduction by converting
 * divisions to power of two divisions and modulo operations. This module implements the unsigned
 * version of Montgomery and does not compute the conditional subtraction step to optimize for area
 * and timing.
 *
 * Algorithm inputs:
 * - a, b: Operands in [0, q[
 * - d:    Bitwidth of operands (fixed to 32 bit)
 * - q:    Modulus in ]0, 2^d]
 * - mu:   Montgomery constant, precomputed, mu = (-q)^(-1) mod 2^d
 *
 * The required constants q and mu are expected to be in the MOD WSR at following locations:
 * q  @ [31:0]
 * mu @ [63:32]
 *
 * Outputs:
 * - r = a*b * 2^(-d) mod q and r in [0,q[
 *
 * This can be computed with (where []_d are the lower d bits, []^d are the higher d bits):
 *   c = a * b
 *   r = [c + [[c]_d * mu]_d * q]^d
 *   if r >= q then                      <- not implemented in this HW
 *       return r - q
 *   return r
 *
 * Due to the neglected conditional subtraction the result is in ]0,2q[ and can be reduced into
 * ]0,q[ using the bn.addvm instruction.
 *
 * As the 3 multiplications are pipelined onto the multiplier it requires two additional registers
 * for intermediate values named "TMP" and "C". These registers hold the following intermediate
 * values when computing a Montgomery multiplication:
 *   Cycle 1:  Reg(TMP) = [a*b]_d,     Reg(C) = a*b
 *   Cycle 2:  Reg(TMP) = [TMP*mu]_d,  Reg(C) = a*b
 *   Cycle 3:  Output   = c + (TMP)*q mod q = [c + (TMP)*q]^d
 *
 * These two hidden registers are cleared with randomness after each vector chunk (i.e., every 3
 * cycles).
 *
 * Register clearing details:
 * As described, the ACC WSR and the two hidden registers are cleared using randomness. The ACC WSR
 * is directly cleared by writing the current value of URND to it. The two hidden registers are
 * cleared with a permutation of URND as shown below. The permutation is based on a netlist secret.
 *
 *              +-------------+
 * URND --+---->| Permutation |-----+----------+
 *        |     +-------------+     |          |
 *        |                      [127:0]   [192:128]
 *        v                         v          v
 *     +-----+                   +-----+    +-----+
 *     | ACC |                   |  C  |    | TMP |
 *     +-----+                   +-----+    +-----+
 */
module otbn_mac_bignum
  import otbn_pkg::*;
#(
  // Compile-time permutation for URND permutation
  parameter bn_mac_urnd_perm_t RndCnstBnMacUrndPerm = RndCnstBnMacUrndPermDefault
) (
  input logic clk_i,
  input logic rst_ni,

  input mac_bignum_operation_t operation_i,
  // The signal mac_en_i must only used by the FSM or by assertions! Everywhere else use the
  // predecoded version. This ensures that there is a redundancy check in place.
  input logic                  mac_en_i,
  input logic                  mac_commit_i,

  output logic [WLEN-1:0] operation_result_o,
  output logic            operation_valid_o,
  output flags_t          operation_flags_o,
  output flags_t          operation_flags_en_o,
  output logic            operation_intg_violation_err_o,

  input  mac_bignum_predec_t predec_i,
  output logic               predec_error_o,

  input  logic [WLEN-1:0] urnd_data_i,
  input  logic            sec_wipe_urnd_i,
  input  logic            sec_wipe_running_i,
  output logic            sec_wipe_err_o,

  // Signals whenever the URND input is used to clear any of the internal registers. This is
  // required to advance the URND PRNG if the SecMuteUrnd parameter is set.
  output logic urnd_used_o,

  output logic [ExtWLEN-1:0] ispr_acc_intg_o,
  input  logic [ExtWLEN-1:0] ispr_acc_wr_data_intg_i,
  input  logic               ispr_acc_wr_en_i,

`ifdef BNMULV_ACCH
  output logic [ExtWLEN-1:0] ispr_acch_intg_o,
  input  logic [ExtWLEN-1:0] ispr_acch_wr_data_intg_i,
  input  logic               ispr_acch_wr_en_i,
`endif

  input  logic [ExtWLEN-1:0] ispr_mod_intg_i,

  output logic state_err_o
);
  localparam int unsigned ELEN = QWLEN / 2;

  // URND permutations for register clearing
  logic [WLEN-1:0]  urnd_permutation;
  logic             unused_urnd_permutation;
  logic [WLEN-1:0]  acc_clear_data;
  logic [HWLEN-1:0] c_clear_data;
  logic [QWLEN-1:0] tmp_clear_data;

  for (genvar i = 0; i < WLEN; i++) begin : gen_urnd_perm
    assign urnd_permutation[i] = urnd_data_i[RndCnstBnMacUrndPerm[i]];
  end

  assign acc_clear_data = urnd_data_i;
  assign c_clear_data   = urnd_permutation[HWLEN-1:0];
  assign tmp_clear_data = urnd_permutation[HWLEN+:QWLEN];

  assign unused_urnd_permutation = ^urnd_permutation[HWLEN + QWLEN +: QWLEN];

  //////////////////
  // ACC Register //
  //////////////////
  logic                          acc_wr_en;
  logic                          acc_clear_en;
  logic [ExtWLEN-1:0]            acc_intg_d;
  logic [ExtWLEN-1:0]            acc_intg_q;
  logic [ExtWLEN-1:0]            acc_intg_calc;
  logic [WLEN-1:0]               acc_no_intg_d;
  logic [WLEN-1:0]               acc_no_intg_q;
  logic [2*BaseWordsPerWLEN-1:0] acc_intg_err;
  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_acc_words
    prim_secded_inv_39_32_enc i_secded_enc (
      .data_i(acc_no_intg_d[i_word * 32 +: 32]),
      .data_o(acc_intg_calc[i_word * 39 +: 39])
    );
    prim_secded_inv_39_32_dec i_secded_dec (
      .data_i    (acc_intg_q[i_word * 39 +: 39]),
      .data_o    (/* unused because we abort on any integrity error */),
      .syndrome_o(/* unused */),
      .err_o     (acc_intg_err[i_word * 2 +: 2])
    );
    assign acc_no_intg_q[i_word * 32 +: 32] = acc_intg_q[i_word * 39 +: 32];
  end

  always_ff @(posedge clk_i) begin
    if (acc_wr_en) begin
      acc_intg_q <= acc_intg_d;
    end
`ifdef BNMULV_ACCH
    if (acch_wr_en) begin
      acch_intg_q <= acch_intg_d;
    end
`endif
  end

  ////////////////
  // Register C //
  ////////////////
  logic                           c_wr_en;
  logic                           c_clear_en;
  logic [ExtHWLEN-1:0]            c_intg_d;
  logic [ExtHWLEN-1:0]            c_intg_q;
  logic [HWLEN-1:0]               c_new_value;
  logic [HWLEN-1:0]               c_no_intg_d;
  logic [HWLEN-1:0]               c_no_intg_q;
  logic [2*BaseWordsPerHWLEN-1:0] c_intg_err;

  for (genvar i_word = 0; i_word < BaseWordsPerHWLEN; i_word++) begin : g_c_words
    prim_secded_inv_39_32_enc i_c_secded_enc (
      .data_i(c_no_intg_d[i_word * 32 +: 32]),
      .data_o(c_intg_d[i_word * 39 +: 39])
    );
    prim_secded_inv_39_32_dec i_c_secded_dec (
      .data_i    (c_intg_q[i_word * 39 +: 39]),
      .data_o    (/* unused because we abort on any integrity error */),
      .syndrome_o(/* unused */),
      .err_o     (c_intg_err[i_word * 2 +: 2])
    );
    assign c_no_intg_q[i_word * 32 +: 32] = c_intg_q[i_word * 39 +: 32];
  end

  always_comb begin
    c_no_intg_d = '0;
    unique case (1'b1)
      (sec_wipe_urnd_i | c_clear_en): c_no_intg_d = c_clear_data;
      default:                        c_no_intg_d = c_new_value;
    endcase
  end

  always_ff @(posedge clk_i) begin
    if (c_wr_en) begin
      c_intg_q <= c_intg_d;
    end
  end

  //////////////////
  // Register TMP //
  //////////////////
  logic                           tmp_wr_en;
  logic                           tmp_clear_en;
  logic [ExtQWLEN-1:0]            tmp_intg_d;
  logic [ExtQWLEN-1:0]            tmp_intg_q;
  logic [QWLEN-1:0]               tmp_new_value;
  logic [QWLEN-1:0]               tmp_no_intg_d;
  logic [QWLEN-1:0]               tmp_no_intg_q;
  logic [2*BaseWordsPerQWLEN-1:0] tmp_intg_err;

  for (genvar i_word = 0; i_word < BaseWordsPerQWLEN; i_word++) begin : g_tmp_words
    prim_secded_inv_39_32_enc i_tmp_secded_enc (
      .data_i(tmp_no_intg_d[i_word * 32 +: 32]),
      .data_o(tmp_intg_d[i_word * 39 +: 39])
    );
    prim_secded_inv_39_32_dec i_tmp_secded_dec (
      .data_i    (tmp_intg_q[i_word * 39 +: 39]),
      .data_o    (/* unused because we abort on any integrity error */),
      .syndrome_o(/* unused */),
      .err_o     (tmp_intg_err[i_word * 2 +: 2])
    );
    assign tmp_no_intg_q[i_word * 32 +: 32] = tmp_intg_q[i_word * 39 +: 32];
  end

  always_comb begin
    tmp_no_intg_d = '0;
    unique case (1'b1)
      (sec_wipe_urnd_i | tmp_clear_en): tmp_no_intg_d = tmp_clear_data;
      default:                          tmp_no_intg_d = tmp_new_value;
    endcase
  end

  always_ff @(posedge clk_i) begin
    if (tmp_wr_en) begin
      tmp_intg_q <= tmp_intg_d;
    end
  end

`ifdef BNMULV_ACCH
  ////////////////////
  // ACCH Register  //
  ////////////////////
  logic               acch_wr_en;
  logic [ExtWLEN-1:0] acch_intg_d;
  logic [ExtWLEN-1:0] acch_intg_q;
  logic [ExtWLEN-1:0] acch_intg_calc;
  logic [WLEN-1:0]    acch_no_intg_d;
  logic [WLEN-1:0]    acch_no_intg_q;
  logic [WLEN-1:0]    acch_blanked;
  logic [2*BaseWordsPerWLEN-1:0] acch_intg_err;

  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_acch_words
    prim_secded_inv_39_32_enc i_acch_secded_enc (
      .data_i(acch_no_intg_d[i_word * 32 +: 32]),
      .data_o(acch_intg_calc[i_word * 39 +: 39])
    );
    prim_secded_inv_39_32_dec i_acch_secded_dec (
      .data_i    (acch_intg_q[i_word * 39 +: 39]),
      .data_o    (/* unused because we abort on any integrity error */),
      .syndrome_o(/* unused */),
      .err_o     (acch_intg_err[i_word * 2 +: 2])
    );
    assign acch_no_intg_q[i_word * 32 +: 32] = acch_intg_q[i_word * 39 +: 32];
  end
`endif // BNMULV_ACCH

  ////////////////////
  // Input blanking //
  ////////////////////
  logic [WLEN-1:0] operand_a_blanked;
  logic [WLEN-1:0] operand_b_blanked;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_operand_a_blanker (
    .in_i (operation_i.operand_a),
    .en_i (predec_i.mac_en
`ifdef BNMULV
           | operation_i.mulv
`endif
           ),
    .out_o(operand_a_blanked)
  );

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_operand_b_blanker (
    .in_i (operation_i.operand_b),
    .en_i (predec_i.mac_en
`ifdef BNMULV
           | operation_i.mulv
`endif
           ),
    .out_o(operand_b_blanked)
  );

  ///////////////////
  // MOD Extractor //
  ///////////////////
  // The modulus and Montgomery constant are expected in the MOD register at:
  // q  @ [31:0]
  // mu @ [63:32]
  logic [2*39-1:0] ispr_mod_intg_blanked;
  logic            unused_ispr_mod_intg;
  logic [63:0]     mod_no_intg;
  logic [3:0]      mod_intg_err;

  // Only the first two 32-bit words are required as q and mu reside in the first 64 bits.
  // This needs blanking to avoid mixing values from MOD with the input B when performing a regular
  // multiplication.
  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(2*39)) u_mod_blanker (
    .in_i (ispr_mod_intg_i[2*39-1:0]),
    .en_i (predec_i.is_mod),
    .out_o(ispr_mod_intg_blanked)
  );

  assign unused_ispr_mod_intg = ^ispr_mod_intg_i[ExtWLEN-1:2*39];

  for (genvar i_word = 0; i_word < 2; i_word++) begin : g_mod_words
    prim_secded_inv_39_32_dec i_mod_secded_dec (
      .data_i    (ispr_mod_intg_blanked[i_word * 39 +: 39]),
      .data_o    (/* unused because we abort on any integrity error */),
      .syndrome_o(/* unused */),
      .err_o     (mod_intg_err[i_word * 2 +: 2])
    );
    assign mod_no_intg[i_word * 32 +: 32] = ispr_mod_intg_blanked[i_word * 39 +: 32];
  end

  // For the 32-bit vectorized multiplications we have to replicate the constants
  logic [QWLEN-1:0] mod_q;  // The Montgomery modulus q
  logic [QWLEN-1:0] mod_mu; // The Montgomery constant mu

  assign mod_q  = {2{mod_no_intg[31:0]}};
  assign mod_mu = {2{mod_no_intg[63:32]}};

  ///////////////////////////
  // Vectorized multiplier //
  ///////////////////////////

  // Input operand quad word selection
  logic [QWLEN-1:0] qword_a;
  logic [QWLEN-1:0] qword_b;

  // This MUX is predecoded to optimize timing.
  assign qword_a = operand_a_blanked[predec_i.op_a_qw_sel * QWLEN +: QWLEN];

  // The qword_b MUXing is elementwise to implement the lane functionality.
  // These 8-to-1 MUXs are predecoded to optimize timing.
  assign qword_b[   0+:ELEN] = operand_b_blanked[predec_i.op_b_elem0_sel * ELEN +: ELEN];
  assign qword_b[ELEN+:ELEN] = operand_b_blanked[predec_i.op_b_elem1_sel * ELEN +: ELEN];

  // Multiplier operand selection
  logic [QWLEN-1:0] mul_op_a;
  logic [QWLEN-1:0] mul_op_b;
  logic [HWLEN-1:0] mul_res;

  assign mul_op_a = predec_i.mul_op_a_tmp_sel ? qword_a : tmp_no_intg_q;

  // Here a regular MUX is sufficient because q and mu are blanked for regular multiplications.
  // For Montgomery these values are anyway combined.
  always_comb begin
    unique case (predec_i.mul_op_b_sel)
      MulOpB:  mul_op_b = qword_b;
      MulOpMu: mul_op_b = mod_mu;
      MulOpq:  mul_op_b = mod_q;
      default: mul_op_b = qword_b;
    endcase
  end

`ifdef BNMULV
  ////////////////////////////////////////////////////////////////
  // BNMULV: unified multiplier replaces otbn_vec_multiplier   //
  // for ALL operations (MULQACC via MODE_64, MULV via MODE_32/16). //
  ////////////////////////////////////////////////////////////////
`ifdef BNMULV_ACCH
  logic [2*WLEN-1:0] bnmulv_mul_res;

  // ============ BN.MODP256 Instruction Support ============
  logic is_modp256;
  assign is_modp256 = operation_i.is_modp256;

  // modp256 control signals from otbn_modp256
  logic [1:0]        modp256_mul_wsel_a, modp256_mul_wsel_b;
  logic [1:0]        modp256_mul_wmode,  modp256_mul_dshift;
  logic [WLEN-1:0]   modp256_mul_A,      modp256_mul_B;
  logic [2*WLEN-1:0] modp256_adder_op_a, modp256_adder_op_b;
  vec_type_e         modp256_adder_wm_lo, modp256_adder_wm_hi;
  logic              modp256_adder_cin_lo, modp256_adder_cin_hi;
  logic [WLEN-1:0]   modp256_acc_d,      modp256_acch_d;
  logic              modp256_acc_wr_en_add, modp256_acch_wr_en_add;
  logic              modp256_acc_blk_dis, modp256_acch_blk_dis;
  logic [WLEN-1:0]   modp256_result;
  logic              modp256_valid;
  flags_t            modp256_flags,       modp256_flags_en;
  logic [15:0]       modp256_adder_cout;

  otbn_modp256 u_modp256 (
    .clk_i, .rst_ni,
    .is_modp256_i     (is_modp256),
    .mac_en_i,
    .mac_commit_i,
    .predec_i,
    .operand_a_i      (operand_a_blanked),
    .operand_b_i      (operand_b_blanked),
    .mul_wsel_a_o     (modp256_mul_wsel_a),
    .mul_wsel_b_o     (modp256_mul_wsel_b),
    .mul_wmode_o      (modp256_mul_wmode),
    .mul_dshift_o     (modp256_mul_dshift),
    .mul_A_o          (modp256_mul_A),
    .mul_B_o          (modp256_mul_B),
    .mul_result_i     (bnmulv_mul_res),
    .adder_op_a_o     (modp256_adder_op_a),
    .adder_op_b_o     (modp256_adder_op_b),
    .adder_word_mode_lo_o (modp256_adder_wm_lo),
    .adder_word_mode_hi_o (modp256_adder_wm_hi),
    .adder_cin_lo_o   (modp256_adder_cin_lo),
    .adder_cin_hi_o   (modp256_adder_cin_hi),
    .adder_result_i   (adder_result),
    .adder_cout_i     (modp256_adder_cout),
    .acc_q_i          (acc_no_intg_q),
    .acch_q_i         (acch_no_intg_q),
    .acc_d_o          (modp256_acc_d),
    .acch_d_o         (modp256_acch_d),
    .acc_wr_en_add_o  (modp256_acc_wr_en_add),
    .acch_wr_en_add_o (modp256_acch_wr_en_add),
    .acc_blk_dis_o    (modp256_acc_blk_dis),
    .acch_blk_dis_o   (modp256_acch_blk_dis),
    .result_o         (modp256_result),
    .valid_o          (modp256_valid),
    .flags_o          (modp256_flags),
    .flags_en_o       (modp256_flags_en)
  );
`else
  logic [WLEN-1:0]   bnmulv_mul_res;
`endif
  otbn_mul_unified u_mul (
`ifdef BNMULV_ACCH
    .word_mode  (is_modp256 ? modp256_mul_wmode  : {operation_i.mulv, operation_i.data_type}),
    .word_sel_A (is_modp256 ? modp256_mul_wsel_a : operation_i.op_a_qw_sel_raw),
    .word_sel_B (is_modp256 ? modp256_mul_wsel_b : operation_i.op_b_elem0_sel_raw[2:1]),
    .exec_mode  (is_modp256 ? 2'b00 : operation_i.exec_mode),
    .A          (is_modp256 ? modp256_mul_A : operand_a_blanked),
    .B          (is_modp256 ? modp256_mul_B : operand_b_blanked),
    .data_type_64_shift(is_modp256 ? modp256_mul_dshift : (operation_i.mulv ? operation_i.pre_acc_shift_imm : 2'd0)),
`else
    .word_mode  ({operation_i.mulv, operation_i.data_type}),
    .word_sel_A (operation_i.op_a_qw_sel_raw),
    .word_sel_B (operation_i.op_b_elem0_sel_raw[2:1]),
    .A          (operand_a_blanked),
    .B          (operand_b_blanked),
    .data_type_64_shift(operation_i.mulv ? operation_i.pre_acc_shift_imm : 2'd0),
`endif
    .half_sel   (operation_i.sel),
    .lane_mode  (operation_i.lane_mode),
    .lane_word_32(operation_i.lane_word_32),
    .lane_word_16(operation_i.lane_word_16),
    .result     (bnmulv_mul_res)
  );
  // MULQACC (mulv=0): MODE_64 result at [127:0] feeds Montgomery C/TMP path.
  // MULV   (mulv=1): bnmulv_mul_res used directly by mul_res_shifted.
  assign mul_res = bnmulv_mul_res[127:0];
`else
  otbn_vec_multiplier u_vec_multiplier (
    .operand_a_i(mul_op_a),
    .operand_b_i(mul_op_b),
    .elen_i     (predec_i.elen),
    .result_o   (mul_res)
  );
`endif

  //////////////////////////////////////////////////////////
  // Multiplier result handling for vectorized Montgomery //
  //////////////////////////////////////////////////////////
  // Store the full result to register C
  assign c_new_value = mul_res;

  // Store only the lower ELEN bits of the parallel multiplications to register TMP.
  assign tmp_new_value = {mul_res[QWLEN +: QWLEN / 2], mul_res[0 +: QWLEN / 2]};

  // Adder operand blanking and extension
  logic [HWLEN-1:0] half_mul_res_add;
  logic [WLEN-1:0]  mul_res_add;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(HWLEN)) u_half_mul_res_blanker (
    .in_i (mul_res),
    .en_i (predec_i.mul_add_en),
    .out_o(half_mul_res_add)
  );

  assign mul_res_add = {{HWLEN{1'b0}}, half_mul_res_add};

  //////////////////////////////////////////////////////////////////////
  // Multiplier result handling for regular vectorized multiplication //
  //////////////////////////////////////////////////////////////////////
  // Truncating and blanking of results towards the ACC merger for vectorized multiplication
  // without modulo reduction.
  logic [QWLEN-1:0] mul_res_merger;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(QWLEN)) u_mul_res_merger_blanker (
    .in_i (tmp_new_value),
    .en_i (predec_i.mul_merger_en),
    .out_o(mul_res_merger)
  );

  ///////////////////////////////////////////////////////////
  // Multiplier result handling for regular multiplication //
  ///////////////////////////////////////////////////////////
  // Blank and shift result prior to accumulation
  logic [HWLEN-1:0] mul_res_pre_shifted;
`ifdef BNMULV_ACCH
  logic [2*WLEN-1:0] mul_res_shifted;
`else
  logic [WLEN-1:0]  mul_res_shifted;
`endif

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(HWLEN)) u_mul_res_shift_blanker (
    .in_i (mul_res),
    .en_i (predec_i.mul_shift_en),
    .out_o(mul_res_pre_shifted)
  );

  // Shift the HWLEN multiply result into a WLEN word before accumulating using the shift amount
  // supplied in the instruction (pre_acc_shift_imm). The shift is on a QWORD granularity and a
  // 192-bit shift will drop the upper QWORD of the multiply result.
  always_comb begin
`ifdef BNMULV
    if (operation_i.mulv) begin
      mul_res_shifted = bnmulv_mul_res;
    end else begin
`endif
    mul_res_shifted = '0;

    unique case (operation_i.pre_acc_shift_imm)
      2'd0:    mul_res_shifted = {{QWLEN * 2{1'b0}}, mul_res_pre_shifted};
      2'd1:    mul_res_shifted = {{QWLEN{1'b0}}, mul_res_pre_shifted, {QWLEN{1'b0}}};
      2'd2:    mul_res_shifted = {mul_res_pre_shifted, {QWLEN * 2{1'b0}}};
      2'd3:    mul_res_shifted = {mul_res_pre_shifted[QWLEN-1:0], {QWLEN * 3{1'b0}}};
      default: mul_res_shifted = {{QWLEN * 2{1'b0}}, mul_res_pre_shifted};
    endcase
`ifdef BNMULV
    end
`endif
  end

  `ASSERT_KNOWN_IF(PreAccShiftImmKnown, operation_i.pre_acc_shift_imm, mac_en_i)

  //////////////////////
  // Vectorized Adder //
  //////////////////////
  logic [HWLEN-1:0] c_blanked;
  logic [WLEN-1:0]  acc_add_blanked;
`ifdef BNMULV_ACCH
  logic [2*WLEN-1:0] adder_op_a;
  logic [2*WLEN-1:0] adder_op_b;
  logic [2*WLEN-1:0] adder_result;
`else
  logic [WLEN-1:0]  adder_op_a;
  logic [WLEN-1:0]  adder_op_b;
  logic [WLEN-1:0]  adder_result;
`endif

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(HWLEN)) u_reg_c_blanker (
    .in_i (c_no_intg_q),
    .en_i (predec_i.c_add_en),
    .out_o(c_blanked)
  );

  // SEC_CM: DATA_REG_SW.SCA
  // acc_add_en is so if .Z set in MULQACC (zero_acc) so accumulator reads as 0
  prim_blanker #(.Width(WLEN)) u_acc_add_blanker (
    .in_i (acc_no_intg_q),
    .en_i (predec_i.acc_add_en
`ifdef BNMULV_ACCH
           && !modp256_acc_blk_dis
`endif
          ),
    .out_o(acc_add_blanked)
  );

`ifdef BNMULV_ACCH
  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_acch_blanker (
    .in_i (acch_no_intg_q),
    .en_i (predec_i.acc_add_en & operation_i.mulv
           & ~modp256_acch_blk_dis),
    .out_o(acch_blanked)
  );
`endif

  // Perform the additions. The vectorized path only uses the lower 128 bits of the adder and
  // operates on 64-bit elements. The full 256 bit width is used for bn.mulqacc instructions.
  // Here the MUXs can be implemented with OR gates because input signals are exclusively blanked
  // for the whole duration of an instruction.
  // - c_blanked is only non zero for Montgomery multiplications where mul_res_shifted is unused.
  //   Vice versa mul_res_shifted is only non zero for regular multiplications where c_blanked is
  //   unused.
  // - mul_res_add is only non zero for vectorized multiplications where acc_add_blanked is unused.
  //   Vice versa acc_add_blanked is only non zero for regular multiplications where mul_res_add is
  //   blanked.
`ifdef BNMULV_ACCH
  assign adder_op_a = is_modp256 ? modp256_adder_op_a : ({{128{1'b0}}, c_blanked} | mul_res_shifted);
  assign adder_op_b = is_modp256 ? modp256_adder_op_b : ({acch_blanked, acc_add_blanked} | {mul_res_add, mul_res_add});
`else
  assign adder_op_a = {{128{1'b0}}, c_blanked} | mul_res_shifted;
  assign adder_op_b = mul_res_add              | acc_add_blanked;
`endif

`ifdef BNMULV
  vec_type_e mac_adder_mode;
  assign mac_adder_mode = operation_i.mulv ? (operation_i.data_type == 1'b0 ? VecType_s32 : VecType_d64) : VecType_v256;

  otbn_adder_buffer_bit u_mac_adder (
    .A        (adder_op_a[WLEN-1:0]),
    .B        (adder_op_b[WLEN-1:0]),
`ifdef BNMULV_ACCH
    .word_mode(is_modp256 ? modp256_adder_wm_lo : mac_adder_mode),
    .cin      (is_modp256 ? modp256_adder_cin_lo : 1'b0),
`else
    .word_mode(mac_adder_mode),
    .cin      (1'b0),
`endif
    .res      (adder_result[WLEN-1:0]),
`ifdef BNMULV_ACCH
    .cout     (modp256_adder_cout)
`else
    .cout     ()
`endif
  );
`ifdef BNMULV_ACCH
  otbn_adder_buffer_bit u_mac_adder_h (
    .A        (adder_op_a[WLEN+:WLEN]),
    .B        (adder_op_b[WLEN+:WLEN]),
    .word_mode(is_modp256 ? modp256_adder_wm_hi : (operation_i.data_type == 1'b0 ? VecType_s32 : VecType_d64)),
    .cin      (is_modp256 ? modp256_adder_cin_hi : 1'b0),
    .res      (adder_result[WLEN+:WLEN]),
    .cout     ()
  );
`endif
`else
  otbn_adder_buffer_bit u_mac_adder (
    .A        (adder_op_a),
    .B        (adder_op_b),
    .word_mode(|predec_i.adder_carry_sel ? VecType_d64 : VecType_v256),
    .cin      (1'b0),
    .res      (adder_result),
    .cout     ()
  );
`endif

  /////////////////////////////////////////////
  // Vectorized adder modulo result handling //
  /////////////////////////////////////////////
  logic [QWLEN-1:0] adder_result_mod;
  logic [QWLEN-1:0] montg_r;

  // Montgomery upper bit selection
  // Take only the upper ELEN bits of the addition.
  // The result is "r" of the montgomery algorithm
  assign adder_result_mod = {adder_result[32 * 3 +: 32], adder_result[32 * 1 +: 32]};

  prim_blanker #(.Width(QWLEN)) u_add_mod_blanker (
    .in_i (adder_result_mod),
    .en_i (predec_i.add_mod_en),
    .out_o(montg_r)
  );

  // The conditional subtraction is not performed to optimize timing and area.
  // It can be performed using the bn.addvm instruction with a zero vector.
  logic [QWLEN-1:0] montg_r_cor;
  assign montg_r_cor = montg_r;

  ///////////////////////////////////////////
  // ACC merging for vectorized operations //
  ///////////////////////////////////////////
  logic [QWLEN-1:0] acc_new_qw;
  logic [WLEN-1:0]  acc_blanked;
  logic [WLEN-1:0]  acc_merged;

  // This MUX can be implemented using a regular OR because both inputs are exclusively blanked.
  // The mul_res_merger comes directly from a blanker which is only active (passes data through) if
  // we are performing a regular vectorized multiplication (default or lane). In this case the
  // montg_r_cor is all zero as the signal is blanked with u_add_mod_blanker. During a Montgomery
  // multiplication the montg_r_cor contains the data but mul_res_merger is blanked.
  // These blankers are exclusively used for the whole duration of an instruction.
  assign acc_new_qw = montg_r_cor | mul_res_merger;

  // This blanker is used to zero the ACC register
  prim_blanker #(.Width(WLEN)) u_acc_merger_blanker (
    .in_i (acc_no_intg_q),
    .en_i (predec_i.acc_merger_en),
    .out_o(acc_blanked)
  );

  // Place the computed 64-bit chunk at the desired location in the ACC register.
  for (genvar qw = 0; qw < VLEN/QWLEN; qw++) begin : gen_acc_merged
    assign acc_merged[qw * QWLEN +: QWLEN] = predec_i.acc_qw_sel[qw] ?
        acc_new_qw : acc_blanked[qw * QWLEN +: QWLEN];
  end

  //////////////////////////////////////////////////////
  // Adder result handling for regular multiplication //
  //////////////////////////////////////////////////////
  logic [WLEN-1:0] adder_result_blanked;
  logic [WLEN-1:0] regular_acc_update_value;

  prim_blanker #(.Width(WLEN)) u_add_res_blanker (
    .in_i (adder_result[WLEN-1:0]),
    .en_i (predec_i.add_res_en),
    .out_o(adder_result_blanked)
  );

  assign regular_acc_update_value = operation_i.shift_acc ?
      {{HWLEN{1'b0}}, adder_result_blanked[HWLEN+:HWLEN]} :
      adder_result_blanked;

  /////////////////
  // Flag update //
  /////////////////
  // Vectorized operation never updates flags
  logic [1:0] adder_result_hw_is_zero;

  // Split zero check between the two halves of the result. This is used for flag setting (see
  // below).
  assign adder_result_hw_is_zero[0] = adder_result_blanked[WLEN/2-1:0] == 'h0;
  assign adder_result_hw_is_zero[1] = adder_result_blanked[WLEN/2+:WLEN/2] == 'h0;

  flags_t flags_norm, flags_en_norm;

  assign flags_norm.L    = adder_result_blanked[0];
  // L is always updated for .WO, and for .SO when writing to the lower half-word
`ifdef BNMULV
  assign flags_en_norm.L = operation_i.mulv                    ? 1'b0 :
                           predec_i.is_vec                     ? 1'b0 :
                           operation_i.shift_acc               ? ~operation_i.wr_hw_sel_upper : 1'b1;
`else
  assign flags_en_norm.L = predec_i.is_vec       ? 1'b0                         :
                           operation_i.shift_acc ? ~operation_i.wr_hw_sel_upper : 1'b1;
`endif

  // For .SO M is taken from the top-bit of shifted out half-word, otherwise it is taken from the
  // top-bit of the full result.
  assign flags_norm.M    = operation_i.shift_acc ? adder_result_blanked[WLEN/2-1] :
                                                   adder_result_blanked[WLEN-1];
  // M is always updated for .WO, and for .SO when writing to the upper half-word.
`ifdef BNMULV
  assign flags_en_norm.M = operation_i.mulv                    ? 1'b0 :
                           predec_i.is_vec                     ? 1'b0 :
                           operation_i.shift_acc               ? operation_i.wr_hw_sel_upper : 1'b1;
`else
  assign flags_en_norm.M = predec_i.is_vec       ? 1'b0                        :
                           operation_i.shift_acc ? operation_i.wr_hw_sel_upper : 1'b1;
`endif

  // For .SO Z is calculated from the shifted out half-word, otherwise it is calculated on the full
  // result.
  assign flags_norm.Z    = operation_i.shift_acc ? adder_result_hw_is_zero[0] :
                                                   &adder_result_hw_is_zero;

  // Z is updated for .WO. For .SO updates are based upon result and half-word:
  // - When writing to lower half-word always update Z.
  // - When writing to upper half-word clear Z if result is non-zero otherwise leave it alone.
`ifdef BNMULV
  assign flags_en_norm.Z = operation_i.mulv ? 1'b0 :
                           predec_i.is_vec                                     ? 1'b0                        :
                           operation_i.shift_acc & operation_i.wr_hw_sel_upper ? ~adder_result_hw_is_zero[0] : 1'b1;
`else
  assign flags_en_norm.Z =
      predec_i.is_vec                                     ? 1'b0                        :
      operation_i.shift_acc & operation_i.wr_hw_sel_upper ? ~adder_result_hw_is_zero[0] : 1'b1;
`endif

  // MAC never sets the carry flag (except MODP256)
  assign flags_norm.C    = 1'b0;
  assign flags_en_norm.C = 1'b0;

`ifdef BNMULV_ACCH
  assign operation_flags_o    = is_modp256 ? modp256_flags    : flags_norm;
  assign operation_flags_en_o = is_modp256 ? modp256_flags_en : flags_en_norm;
`else
  assign operation_flags_o    = flags_norm;
  assign operation_flags_en_o = flags_en_norm;
`endif

  ////////////////
  // ACC update //
  ////////////////
  always_comb begin
    acc_no_intg_d = '0;
    unique case (1'b1)
      // Non-encoded inputs have to be encoded before writing to the register.
      (sec_wipe_urnd_i | acc_clear_en): begin
        acc_no_intg_d = acc_clear_data;
        acc_intg_d    = acc_intg_calc;
      end
      default: begin
        // If performing an ACC ISPR write the next accumulator value is taken from the ISPR write
        // data, otherwise it is drawn from the adder result or the vectorized ACC merger.
        if (ispr_acc_wr_en_i) begin
          acc_intg_d = ispr_acc_wr_data_intg_i;
        end else begin
`ifdef BNMULV
          if (operation_i.mulv) begin
`ifdef BNMULV_ACCH
            if (is_modp256) begin
              acc_no_intg_d = modp256_acc_d;
            end else begin
`endif
            // BNMULV: ACC gets the adder result directly
            acc_no_intg_d = adder_result[WLEN-1:0];
`ifdef BNMULV_ACCH
            end
`endif
            acc_intg_d    = acc_intg_calc;
          end else begin
`endif
          // The MUX for the input selection can be implemented with a simple OR gate because both
          // inputs are exclusively blanked. For regular multiplications acc_merged is zero because
          // the ACC merger just receives zero values. For vectorized multiplications (incl.
          // Montgomery) the regular_acc_update_value is zero because add_res_en is reset.
          // These blankers are exclusively used for the whole duration of an instruction.
          acc_no_intg_d = acc_merged | regular_acc_update_value;
          acc_intg_d    = acc_intg_calc;
`ifdef BNMULV
          end
`endif
        end
      end
    endcase
  end

`ifdef BNMULV_ACCH
  // ACCH write logic
  always_comb begin
    acch_no_intg_d = '0;
    unique case (1'b1)
      sec_wipe_urnd_i: begin
        acch_no_intg_d = urnd_data_i;
        acch_intg_d    = acch_intg_calc;
      end
      ispr_acc_wr_en_i: begin
        acch_no_intg_d = '0;
        acch_intg_d    = acch_intg_calc;
      end
      default: begin
        if (ispr_acch_wr_en_i) begin
          acch_intg_d = ispr_acch_wr_data_intg_i;
        end else begin
`ifdef BNMULV_ACCH
          if (is_modp256) begin
            acch_no_intg_d = modp256_acch_d;
          end else begin
`endif
          acch_no_intg_d = adder_result[2*WLEN-1:WLEN];
`ifdef BNMULV_ACCH
          end
`endif
          acch_intg_d    = acch_intg_calc;
        end
      end
    endcase
  end
`endif // BNMULV_ACCH

  ///////////////////////////
  // Register Write Enable //
  ///////////////////////////
  // The raw write enables are set by the state machine. These are then combined with the input
  // signals which handle the validity of the instruction.
  logic acc_wr_en_raw;
  logic tmp_wr_en_raw;
  logic c_wr_en_raw;

  assign acc_wr_en = (((is_modp256 ? 1'b0 : acc_wr_en_raw) | acc_clear_en
`ifdef BNMULV_ACCH
                       | modp256_acc_wr_en_add
`endif
                      ) & (predec_i.mac_en & mac_commit_i))
                     | ispr_acc_wr_en_i | sec_wipe_urnd_i;
  assign tmp_wr_en = ((tmp_wr_en_raw | tmp_clear_en) & (predec_i.mac_en & mac_commit_i))
                     | sec_wipe_urnd_i;
  assign c_wr_en   = ((c_wr_en_raw | c_clear_en) & (predec_i.mac_en & mac_commit_i))
                     | sec_wipe_urnd_i;

`ifdef BNMULV_ACCH
  assign acch_wr_en = (predec_i.mac_en & mac_commit_i &
                        (is_modp256 ? modp256_acch_wr_en_add
                         : (operation_i.mulv | modp256_acch_wr_en_add)))
                       | ispr_acch_wr_en_i | ispr_acc_wr_en_i | sec_wipe_urnd_i;
`endif

  /////////////////////////
  // Multi-cycle control //
  /////////////////////////
  // The multi-cycle execution is controlled by a FSM. This FSM works in tandem with a duplicate
  // in the instruction fetch stage. The duplicate operates one cycle in advance and provides the
  // predecoded signals. These signals are compared to the ones generated here.
  mac_bignum_contrl_t contrl;
  mac_bignum_predec_t expected_predec;

  otbn_mac_bignum_fsm u_mac_bignum_fsm (
    .clk_i,
    .rst_ni,

    // This FSM here must use the decoded signals as the counterpart operates on the predecoded
    // signals. Otherwise both FSMs would be controlled with the same control signals.
    .start_i          (mac_en_i),
    .mac_en_i         (mac_en_i),
`ifdef BNMULV
    .mulv_i           (operation_i.mulv),
`endif
`ifdef BNMULV_ACCH
    .is_modp256_i     (is_modp256),
`endif
    .is_vec_i         (operation_i.is_vec),
    .is_mod_i         (operation_i.is_mod),
    .is_lane_i        (operation_i.is_lane),
    .lane_index_i     (operation_i.lane_index),
    .elen_i           (operation_i.elen),
    .adder_carry_sel_i(operation_i.adder_carry_sel),
    .acc_add_en_i     (operation_i.acc_add_en),
    .op_a_qw_sel_i    (operation_i.op_a_qw_sel_raw),
    .op_b_elem0_sel_i (operation_i.op_b_elem0_sel_raw),
    .op_b_elem1_sel_i (operation_i.op_b_elem1_sel_raw),

    .sec_wipe_i(sec_wipe_urnd_i),

    .contrl_o (contrl),
    .predec_o (expected_predec),
    .is_busy_o(/* only used in predecoder */),

    // Any tampering on the internal state will abort the execution.
    .state_err_o(state_err_o)
  );

  // For non modulo vectorized multiplications, the blanker must be active if the instructions
  // starts and it must definitively be high if it is already ongoing.
  `ASSERT(VecMulBlankerMulMergerEn_A,
          predec_i.is_vec && !predec_i.is_mod && predec_i.mac_en
          |-> predec_i.mul_merger_en,
          clk_i, !rst_ni || !predec_i.mac_en)

  // We have separate control signals to have a clean separation between the control logic and data
  // path components.
  assign tmp_wr_en_raw = contrl.tmp_wr_en_raw;
  assign tmp_clear_en  = contrl.tmp_clear_en;
  assign c_wr_en_raw   = contrl.c_wr_en_raw;
  assign c_clear_en    = contrl.c_clear_en;
  assign acc_wr_en_raw = contrl.acc_wr_en_raw;
  assign acc_clear_en  = contrl.acc_clear_en;

  // We must signal that we used URND so the PRNG is advanced even if the SecMuteUrnd parameter is
  // set.
  assign urnd_used_o = tmp_clear_en || c_clear_en || acc_clear_en;

  //////////////////////
  // Result selection //
  //////////////////////
  // Here the output MUX can be replaced with a simple OR gate because both inputs are exclusively
  // blanked. For regular multiplications the acc_merged is zero because the ACC merging just
  // receives zero inputs. For vectorized multiplications (incl. Montgomery) the
  // adder_result_blanked is blanked. These blankers are exclusively used for the whole duration of
  // an instruction.
  // For a regular multiplication shift_acc only applies to the new value written to the
  // accumulator.
  always_comb begin
    operation_result_o = acc_merged | adder_result_blanked;  // default: MULQACC
`ifdef BNMULV
    if (operation_i.mulv) begin
`ifdef BNMULV_ACCH
      if (is_modp256) begin
        operation_result_o = modp256_result;
      end else unique case (operation_i.exec_mode)
        2'b00: begin  // plain mulv
          if (operation_i.data_type == 1'b1) begin  // 32-bit mode (8S)
            operation_result_o = {adder_result[384 + 64*operation_i.sel +: 64],
                                  adder_result[256 + 64*operation_i.sel +: 64],
                                  adder_result[128 + 64*operation_i.sel +: 64],
                                  adder_result[      64*operation_i.sel +: 64]};
          end else begin  // 16-bit mode (16H)
            operation_result_o = {adder_result[448 + 32*operation_i.sel +: 32],
                                  adder_result[384 + 32*operation_i.sel +: 32],
                                  adder_result[320 + 32*operation_i.sel +: 32],
                                  adder_result[256 + 32*operation_i.sel +: 32],
                                  adder_result[192 + 32*operation_i.sel +: 32],
                                  adder_result[128 + 32*operation_i.sel +: 32],
                                  adder_result[ 64 + 32*operation_i.sel +: 32],
                                  adder_result[      32*operation_i.sel +: 32]};
          end
        end
        2'b01: begin  // .acc variant: interleave operand_a with adder result
          if (operation_i.data_type == 1'b1) begin  // 32-bit mode
            if (operation_i.sel == 1'b0) begin
              operation_result_o = {operand_a_blanked[224+:32], adder_result[384+:32],
                                    operand_a_blanked[160+:32], adder_result[256+:32],
                                    operand_a_blanked[ 96+:32], adder_result[128+:32],
                                    operand_a_blanked[ 32+:32], adder_result[  0+:32]};
            end else begin
              operation_result_o = {adder_result[384+64+:32], operand_a_blanked[192+:32],
                                    adder_result[256+64+:32], operand_a_blanked[128+:32],
                                    adder_result[128+64+:32], operand_a_blanked[ 64+:32],
                                    adder_result[  0+64+:32], operand_a_blanked[  0+:32]};
            end
          end else begin  // 16-bit mode (.lo, exec_mode=01)
            // With ACCH: all 16 products available, take product LOWER halves
            operation_result_o = {adder_result[480+:16], adder_result[448+:16],
                                  adder_result[416+:16], adder_result[384+:16],
                                  adder_result[352+:16], adder_result[320+:16],
                                  adder_result[288+:16], adder_result[256+:16],
                                  adder_result[224+:16], adder_result[192+:16],
                                  adder_result[160+:16], adder_result[128+:16],
                                  adder_result[ 96+:16], adder_result[ 64+:16],
                                  adder_result[ 32+:16], adder_result[  0+:16]};
          end
        end
        default: begin  // exec_mode 10 (.hi) / 11
          if (operation_i.data_type == 1'b1) begin  // 32-bit mode (8S)
            if (operation_i.sel == 1'b0) begin
              operation_result_o = {operand_a_blanked[224+:32], adder_result[416+:32],
                                    operand_a_blanked[160+:32], adder_result[288+:32],
                                    operand_a_blanked[ 96+:32], adder_result[160+:32],
                                    operand_a_blanked[ 32+:32], adder_result[ 32+:32]};
            end else begin
              operation_result_o = {adder_result[416+64+:32], operand_a_blanked[192+:32],
                                    adder_result[288+64+:32], operand_a_blanked[128+:32],
                                    adder_result[160+64+:32], operand_a_blanked[ 64+:32],
                                    adder_result[ 32+64+:32], operand_a_blanked[  0+:32]};
            end
          end else begin  // 16-bit mode (16H)
            operation_result_o = {adder_result[496+:16], adder_result[464+:16],
                                  adder_result[432+:16], adder_result[400+:16],
                                  adder_result[368+:16], adder_result[336+:16],
                                  adder_result[304+:16], adder_result[272+:16],
                                  adder_result[240+:16], adder_result[208+:16],
                                  adder_result[176+:16], adder_result[144+:16],
                                  adder_result[112+:16], adder_result[ 80+:16],
                                  adder_result[ 48+:16], adder_result[ 16+:16]};
          end
        end
      endcase
`else
      // Without ACCH: result is 256-bit, use directly
      operation_result_o = adder_result[WLEN-1:0];
`endif
    end
`endif
  end
`ifdef BNMULV_ACCH
  assign operation_valid_o  = is_modp256 ? modp256_valid :
`else
  assign operation_valid_o  = '0 |
`endif
                              predec_i.operation_valid_raw &
`ifdef BNMULV
                               (predec_i.mac_en | operation_i.mulv);
`else
                               predec_i.mac_en;
`endif

  /////////////////////
  // Integrity error //
  /////////////////////
  // Propagate integrity error only if a register is used and MAC is enabled
  logic tmp_used;
  logic c_used;
  logic mod_used;
  logic acc_used;
  // TMP is used if multiplier operand a is set to TMP
  assign tmp_used = predec_i.mac_en && !predec_i.mul_op_a_tmp_sel;
  // c is used if its blanker is enabled
  assign c_used = predec_i.mac_en & predec_i.c_add_en;
  // MOD is used if modulo operation is active
  assign mod_used = predec_i.mac_en && predec_i.is_mod;
  // The ACC is used if we do not reset it (regular mul) or require it to merge the current
  // quarter word
  assign acc_used = predec_i.mac_en && (predec_i.acc_merger_en || predec_i.acc_add_en);

  assign operation_intg_violation_err_o = (tmp_used && |(tmp_intg_err)) ||
                                          (c_used   && |(c_intg_err))   ||
                                          (mod_used && |(mod_intg_err)) ||
                                          (acc_used && |(acc_intg_err));

  //////////////////////
  // Redundancy check //
  //////////////////////
  // SEC_CM: CTRL.REDUN
  assign predec_error_o = expected_predec != predec_i;

  /////////////////////////////////////
  // Register and secure wipe output //
  /////////////////////////////////////
  assign ispr_acc_intg_o = acc_intg_q;

`ifdef BNMULV_ACCH
  assign ispr_acch_intg_o = acch_intg_q;
`endif

  assign sec_wipe_err_o = sec_wipe_urnd_i & ~sec_wipe_running_i;

  `ASSERT(NoISPRAccWrAndMacEn, ~(ispr_acc_wr_en_i & mac_en_i))

  // Only one QWORD must be overwritten at the same time.
  `ASSERT(AccQwSelOnehot_A,
          predec_i.acc_merger_en |-> $onehot(predec_i.acc_qw_sel),
          clk_i, !rst_ni || predec_error_o || state_err_o)

endmodule
