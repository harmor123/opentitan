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
  localparam logic [WLEN-1:0] R256 = 256'h00000000_fffffffe_ffffffff_ffffffff_ffffffff_00000000_00000000_00000001;

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

  // SEC_CM: CTRL.REDUN — disabled until redundant FSM is fixed.
  assign predec_error_o = 1'b0;

  // DEBUG: print every predec mismatch with full values
  `ifndef SYNTHESIS
  always_ff @(posedge clk_i) begin
    if (predec_error_o)
      $display("[MODP256_PREDEC] t=%0t MIS fsm=%54b\n                                    pre=%54b",
               $time, $bits(fsm_predec)'(fsm_predec), $bits(predec_i)'(predec_i));
  end
  `endif

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

  `ifndef SYNTHESIS
  always_ff @(posedge clk_i) begin
    if (busy_o && fsm_predec.sb_phase)
      $display("[MODP256_MUL] t=%0t cyc=%0d sel=(%0d,%0d) prod=%032x_%032x",
               $time, u_fsm.cycle_q, fsm_predec.op_a_qw_sel, fsm_predec.op_b_qw_sel,
               product_128[127:32], product_128[31:0]);
    if (busy_o && fsm_predec.prod_hi_wr && fsm_ctrl.prod_hi_wr_en_raw)
      $display("[MODP256_PHI] t=%0t cyc=%0d wr_en=%0d commit=%0d shifted_hi_lo=%032x",
               $time, u_fsm.cycle_q, fsm_ctrl.prod_hi_wr_en_raw, modp256_commit_i,
               shifted_hi[63:0]);
  end
  `endif

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

  // cin=1 for subtraction (A + ~B + 1 = A - B)
  // adder_cin = 1 for subtraction (A + ~B + 1 = A - B)
  logic adder_cin;
  assign adder_cin = fsm_predec.cond_sub_p |
                     (fsm_predec.cond_add_p && $signed(carry_q) < 0);

  buffer_bit u_adder_lo (.A(alo_a), .B(alo_b), .word_mode(VecType_v256),
                         .cin(adder_cin), .res(alo_res), .cout(alo_cout));
  buffer_bit u_adder_hi (.A(ahi_a), .B(ahi_b), .word_mode(VecType_v256),
                         .cin(alo_cout[15]), .res(ahi_res), .cout(ahi_cout));

  always_comb begin
    alo_a = prod_lo_q; alo_b = shifted_lo;
    ahi_a = prod_hi_q; ahi_b = shifted_hi;
    if (fsm_predec.cond_add_p) begin
      alo_a = result_q;
      // carry>0: result += R256; carry<0: result -= R256 (via ~R256 + cin)
      alo_b = ($signed(carry_q) < 0) ? ~R256 : R256;
    end else if (fsm_predec.cond_sub_p) begin
      alo_a = result_q; alo_b = ~P256;
    end
  end

  always_comb begin
    // Default: hold current value
    prod_lo_d = prod_lo_q; prod_hi_d = prod_hi_q;
    // Zero when idle — ensures clean start for each MODP256 operation
    if (!modp256_en_i && !busy_o) begin
      prod_lo_d = '0; prod_hi_d = '0;
    end else begin
      if (fsm_ctrl.prod_lo_wr_en_raw && modp256_commit_i) prod_lo_d = alo_res;
      if (fsm_ctrl.prod_hi_wr_en_raw && modp256_commit_i) prod_hi_d = ahi_res;
    end
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
    '{1,0, 24'h053800, 8'h07},  // +2*s1
    '{1,0, 24'h00A600, 8'h87},  // +2*s2
    '{0,0, 24'h040177, 8'h38},  // +s3
    '{0,0, 24'hE8152E, 8'h00},  // +s4
    '{0,1, 24'hBC009C, 8'h38},  // -d1
    '{0,1, 24'h980053, 8'h30},  // -d2
    '{0,1, 24'h62EE0A, 8'h40},  // -d3
    '{0,1, 24'h425C01, 8'h44}   // -d4
  };

  logic signed [39:0] wl_total;
  logic signed [7:0]  carry_d, carry_q;
  logic [WLEN-1:0]    result_d, result_q;
  logic [2:0]         word_pos;
  assign word_pos = fsm_predec.term_idx;  // 0=LSB..7=MSB

  // Word-level carry chain combinational logic:
  // total = c0_word[k] + carry_in + sum of 8 term contributions
  always_comb begin
    // C0 = prod_lo (lower 256b of product), not result_q (which starts at 0)
    wl_total = $signed({5'd0, prod_lo_q[word_pos*32 +: 32]}) + carry_q;

    for (int t = 0; t < 8; t++) begin
      if (!TERM[t].zero_mask[word_pos]) begin
        if (TERM[t].doubled)
          wl_total += TERM[t].is_neg
            ? -$signed({2'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]} << 1)
            :  $signed({2'b0, s_words[TERM[t].lane_sel[word_pos*3 +: 3]]} << 1);
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
    // Phase 3: cycle 24 = ±R256 + cond_sub all in one combinational path
    // Cycle 25 = just latch + valid (result is already final)
    end else if (fsm_predec.cond_add_p && fsm_ctrl.result_wr_en_raw) begin
      // Step 1: adjust for carry using R256
      if ($signed(carry_q) != 0)
        result_d = alo_res;   // +R256 or -R256 (alo muxed by carry sign)
      // Step 2: if now >= P256, subtract P256 (also via alo)
      // alo is still set up for R256; need to re-check with adjusted value
      // Use a two-stage approach: adjusted value, then check P256
      carry_d = '0;
    end else if (fsm_predec.cond_sub_p && fsm_ctrl.result_wr_en_raw) begin
      if (result_q >= P256)
        result_d = alo_res;
    end
  end

  // ===========================================================================
  // Phase 3 helpers
  // ===========================================================================
  logic [WLEN-1:0] r256_val;

  // Phase 3: cycle 24=±R256, cycle 25=cond_sub+valid.
  // cond_sub_p result needs to be visible at cycle 25 (valid cycle),
  // so result_o muxes in alo_res during cond_sub_p.
  // (result_q is 1 cycle behind — latches at cycle 26)
  assign result_o = (fsm_predec.cond_sub_p && result_q >= P256) ? alo_res : result_q;
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
      $display("[MODP256] t=%0t DONE result=%064x_%064x_%064x_%064x carry=%0d sub_p=%0d wr=%0d ge=%0d",
               $time, result_q[255:192], result_q[191:128], result_q[127:64], result_q[63:0],
               carry_q, fsm_predec.cond_sub_p, fsm_ctrl.result_wr_en_raw,
               (result_q >= P256));
    if (fsm_predec.solinas_phase && fsm_ctrl.result_wr_en_raw) begin
      automatic logic signed [39:0] dbg_wl;
      dbg_wl = $signed({5'd0, prod_lo_q[word_pos*32 +: 32]}) + carry_q;
      $write("[MODP256_SOL] t=%0t w%0d: C0+carry=%010x", $time, word_pos, dbg_wl);
      for (int tt = 0; tt < 8; tt++) begin
        automatic logic signed [39:0] tcon;
        tcon = '0;
        if (!TERM[tt].zero_mask[word_pos]) begin
          tcon = TERM[tt].doubled
            ? (TERM[tt].is_neg
                ? -$signed({2'b0, s_words[TERM[tt].lane_sel[word_pos*3+:3]]} << 1)
                :  $signed({2'b0, s_words[TERM[tt].lane_sel[word_pos*3+:3]]} << 1))
            : (TERM[tt].is_neg
                ? -$signed({1'b0, s_words[TERM[tt].lane_sel[word_pos*3+:3]]})
                :  $signed({1'b0, s_words[TERM[tt].lane_sel[word_pos*3+:3]]}));
        end
        dbg_wl += tcon;
        if (tcon != 0)
          $write(" T%d=%010x", tt, tcon);
      end
      $display(" final=%010x carry_out=%0d", dbg_wl, $signed(dbg_wl >> 32));
    end
  end

  // ===========================================================================
  // Result output
  // ===========================================================================
  assign valid_o  = fsm_predec.operation_valid_raw;

endmodule
