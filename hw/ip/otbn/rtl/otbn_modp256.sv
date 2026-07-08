// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

module otbn_modp256
  import otbn_pkg::*;
(
  input  logic clk_i,
  input  logic rst_ni,

  input  logic                    start_i,
  input  logic                    modp256_en_i,
  input  logic                    modp256_commit_i,
  input  logic [WLEN-1:0]         wrs1_i,
  input  logic [WLEN-1:0]         wrs2_i,

  // Shared MAC unified_mul interface
  output logic [1:0]              mul_wsel_a_o,
  output logic [1:0]              mul_wsel_b_o,
  input  logic [127:0]            mac_mul_result_i,

  output logic [WLEN-1:0]         result_o,
  output logic                    valid_o,
  output logic                    busy_o,

  input  modp256_predec_t         predec_i,
  output logic                    predec_error_o,

  input  logic [WLEN-1:0]         urnd_i,
  output logic                    urnd_used_o,

  output logic                    state_err_o
);

  localparam logic [WLEN-1:0] P256 =
    256'hffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_ffffffff;
  localparam logic [WLEN-1:0] R256 =
    256'h00000001_00000000_00000000_00000000_00000000_ffffffff_00000001;

  // ===========================================================================
  // FSM
  // ===========================================================================
  modp256_contrl_t fsm_ctrl;
  modp256_predec_t fsm_predec;

  otbn_modp256_fsm u_fsm (
    .clk_i, .rst_ni,
    .start_i, .modp256_en_i(modp256_en_i),
    .ctrl_o(fsm_ctrl), .predec_o(fsm_predec),
    .busy_o(busy_o), .state_err_o(state_err_o), .sec_wipe_i(1'b0)
  );

  assign predec_error_o = (fsm_predec != predec_i);
  assign urnd_used_o = fsm_ctrl.prod_lo_clear_en || fsm_ctrl.prod_hi_clear_en ||
                       fsm_ctrl.result_clear_en;

  // ===========================================================================
  // Phase 1: Schoolbook 512-bit accumulation
  // ===========================================================================
  logic [WLEN-1:0] prod_lo_d, prod_lo_q;
  logic [WLEN-1:0] prod_hi_d, prod_hi_q;
  logic [127:0]    product_128;

  assign product_128  = mac_mul_result_i;
  assign mul_wsel_a_o = fsm_predec.op_a_qw_sel;
  assign mul_wsel_b_o = fsm_predec.op_b_qw_sel;

  logic [WLEN-1:0] shifted_lo, shifted_hi;
  always_comb begin
    shifted_lo = '0; shifted_hi = '0;
    unique case (fsm_predec.dshift)
      0:   shifted_lo[127:0]   = product_128;
      64:  shifted_lo[191:64]  = product_128;
      128: shifted_lo[255:128] = product_128;
      192: begin
        shifted_lo[255:192] = product_128[63:0];
        shifted_hi[63:0]    = product_128[127:64];
      end
      256: shifted_hi[127:0]   = product_128;
      320: shifted_hi[191:64]  = product_128;
      384: shifted_hi[255:128] = product_128;
      default: ;
    endcase
  end

  // 2× buffer_bit adders
  logic [WLEN-1:0] alo_a, alo_b, alo_res;
  logic [15:0]     alo_cout;
  logic [WLEN-1:0] ahi_a, ahi_b, ahi_res;
  logic [15:0]     ahi_cout;

  buffer_bit u_adder_lo (.A(alo_a), .B(alo_b), .word_mode(VecType_v256),
                         .cin(1'b0), .res(alo_res), .cout(alo_cout));
  buffer_bit u_adder_hi (.A(ahi_a), .B(ahi_b), .word_mode(VecType_v256),
                         .cin(alo_cout[15]), .res(ahi_res), .cout(ahi_cout));

  always_comb begin
    alo_a = prod_lo_q; alo_b = shifted_lo;
    ahi_a = prod_hi_q; ahi_b = shifted_hi;
    if (fsm_predec.cond_add_p) begin
      alo_a = result_q; alo_b = P256;
    end else if (fsm_predec.cond_sub_p) begin
      // Subtraction: A + ~B + 1 (cin from is_neg)
      alo_a = result_q; alo_b = ~P256;
    end
  end

  always_comb begin
    prod_lo_d = prod_lo_q; prod_hi_d = prod_hi_q;
    if (fsm_ctrl.prod_lo_clear_en)      prod_lo_d = urnd_i;
    else if (fsm_ctrl.prod_lo_wr_en_raw && modp256_commit_i) prod_lo_d = alo_res;
    if (fsm_ctrl.prod_hi_clear_en)      prod_hi_d = urnd_i;
    else if (fsm_ctrl.prod_hi_wr_en_raw && modp256_commit_i) prod_hi_d = ahi_res;
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin prod_lo_q <= '0; prod_hi_q <= '0; end
    else         begin prod_lo_q <= prod_lo_d; prod_hi_q <= prod_hi_d; end
  end

  // ===========================================================================
  // Phase 2: Word-level carry chain
  // ===========================================================================

  // s_words[0..7] from prod_hi (S = high 256 bits): s_words[0]=MSB, s_words[7]=LSB
  logic [31:0] s_words [0:7];
  for (genvar k = 0; k < 8; k++) begin : gen_s_words
    assign s_words[k] = prod_hi_q[(7-k)*32 +: 32];
  end

  // TERM_ROM duplicated from FSM for datapath use
  typedef struct packed {
    logic        doubled, is_neg;
    logic [23:0] lane_sel;  // packed: {ls[0],...,ls[7]}, lane_sel[k*3+:3] = ls[7-k]
    logic [7:0]  zero_mask;
  } term_t;
  localparam term_t TERM[0:7] = '{
    '{1,0, 24'h004688, 8'h07},
    '{1,0, 24'h003440, 8'h87},
    '{0,0, 24'hFA8008, 8'h38},
    '{0,0, 24'hD62217, 8'h00},
    '{0,1, 24'h8D003D, 8'h38},
    '{0,1, 24'h688034, 8'h30},
    '{0,1, 24'h447D43, 8'h40},
    '{0,1, 24'h206B02, 8'h44}
  };

  logic signed [39:0] wl_total;
  logic signed [4:0]  carry_d, carry_q;
  logic [WLEN-1:0]    result_d, result_q;
  logic [2:0]         word_pos;
  assign word_pos = fsm_predec.term_idx;  // 0=LSB..7=MSB

  // Word-level carry chain combinational logic:
  // total = c0_word[k] + carry_in + sum of 8 term contributions
  always_comb begin
    // Start with c0_word at position word_pos
    wl_total = $signed({5'd0, result_q[word_pos*32 +: 32]}) + carry_q;

    for (int t = 0; t < 8; t++) begin
      if (!TERM[t].zero_mask[word_pos]) begin
        if (TERM[t].doubled)
          wl_total += TERM[t].is_neg
            ? -$signed({1'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]} << 1)
            :  $signed({1'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]} << 1);
        else
          wl_total += TERM[t].is_neg
            ? -$signed({1'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]})
            :  $signed({1'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]});
      end
    end
  end

  always_comb begin
    result_d = result_q;
    carry_d  = carry_q;
    if (fsm_ctrl.result_clear_en) begin
      result_d = urnd_i; carry_d = '0;
    end else if (fsm_predec.solinas_phase && fsm_ctrl.result_wr_en_raw && modp256_commit_i) begin
      result_d[word_pos*32 +: 32] = wl_total[31:0];
      carry_d = wl_total >> 32;
    end
  end

  // ===========================================================================
  // Phase 3: Conditional reduce
  // ===========================================================================
  logic [WLEN-1:0]   r256_val;
  logic              result_ge_p;

  // r256 × |carry| lookup
  always_comb begin
    unique case (|carry_q)
      1: r256_val = R256;
      2: r256_val = R256 << 1;
      3: r256_val = (R256 << 1) + R256;
      4: r256_val = R256 << 2;
      default: r256_val = '0;
    endcase
  end

  assign result_ge_p = result_q >= P256;

  // Phase 3: cycle 24 = carry<0? +P; cycle 25 = result>=P? -P
  always_comb begin
    result_d = result_q;
    carry_d  = carry_q;
    if (fsm_ctrl.result_clear_en) begin
      result_d = urnd_i; carry_d = '0;
    end
    // Cycle 24: cond_add_p — if carry<0, result += P256 (via alo)
    else if (fsm_predec.cond_add_p && fsm_ctrl.result_wr_en_raw && modp256_commit_i) begin
      if (carry_q < 0)
        result_d = alo_res;   // result + P256
      carry_d = '0;
    end
    // Cycle 25: cond_sub_p — if result>=P256, result -= P256 (via alo with ~P)
    else if (fsm_predec.cond_sub_p && fsm_ctrl.result_wr_en_raw && modp256_commit_i) begin
      if (result_ge_p)
        result_d = alo_res;   // result - P256
    end
  end

  // ===========================================================================
  // Registers
  // ===========================================================================
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      result_q <= '0;
      carry_q  <= '0;
    end else begin
      result_q <= result_d;
      carry_q  <= carry_d;
    end
  end

  // ===========================================================================
  // DEBUG: uncomment to trace FSM state
  // ===========================================================================
  logic dbg_was_busy;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) dbg_was_busy <= 1'b0;
    else         dbg_was_busy <= busy_o;
  end
  always_ff @(posedge clk_i) begin
    if (modp256_en_i && !dbg_was_busy)
      $display("[MODP256] t=%0t EN=1 busy=%0d wrs1_lo=%08x wrs2_lo=%08x",
               $time, busy_o, wrs1_i[31:0], wrs2_i[31:0]);
    if (fsm_predec.operation_valid_raw)
      $display("[MODP256] t=%0t DONE result_lo=%064x", $time, result_q);
  end

  // ===========================================================================
  // Result output
  // ===========================================================================
  assign result_o = result_q;
  assign valid_o  = fsm_predec.operation_valid_raw;

endmodule
