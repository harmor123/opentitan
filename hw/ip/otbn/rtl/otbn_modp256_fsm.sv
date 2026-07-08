// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

module otbn_modp256_fsm
  import otbn_pkg::*;
#(
  parameter bit EnableAlertTriggerSVA = 1
) (
  input  logic clk_i,
  input  logic rst_ni,

  input  logic                  start_i,
  input  logic                  modp256_en_i,

  output modp256_contrl_t       ctrl_o,
  output modp256_predec_t       predec_o,
  output logic                  busy_o,
  output logic                  state_err_o,

  input  logic sec_wipe_i
);

  localparam int LATENCY = 26;  // 16 SB + 8 Solinas + 2 cond-reduce

  // ===========================================================================
  // SB_ROM — 16 schoolbook (i,j) pairs (matches ISS _SB)
  // ===========================================================================
  typedef struct packed { logic [1:0] i, j; } sb_t;
  localparam sb_t SB[0:15] = '{
    '{0,0}, '{0,1}, '{1,0}, '{0,2}, '{1,1}, '{2,0}, '{0,3}, '{1,2},
    '{2,1}, '{3,0}, '{1,3}, '{2,2}, '{3,1}, '{2,3}, '{3,2}, '{3,3}
  };

  // ===========================================================================
  // TERM_ROM — 8 Solinas terms (matches ISS _TERMS)
  // ===========================================================================
  typedef struct packed {
    logic        doubled, is_neg;
    logic [23:0] lane_sel;  // 8×3 bits: {ls[0],ls[1],ls[2],ls[3],ls[4],ls[5],ls[6],ls[7]}
    logic [7:0]  zero_mask;
  } term_t;
  localparam term_t TERM[0:7] = '{
    '{1,0, 24'h053800, 8'h07},  // +2*s1  ISS ls=[0,1,2,3,4,0,0,0]
    '{1,0, 24'h00A600, 8'h87},  // +2*s2  ISS ls=[0,0,1,2,3,0,0,0]
    '{0,0, 24'h040177, 8'h38},  // +s3    ISS ls=[0,1,0,0,0,5,6,7]
    '{0,0, 24'hE8152E, 8'h00},  // +s4    ISS ls=[7,2,0,1,2,4,5,6]
    '{0,1, 24'hBC009C, 8'h38},  // -d1    ISS ls=[5,7,0,0,0,2,3,4]
    '{0,1, 24'h980053, 8'h30},  // -d2    ISS ls=[4,6,0,0,0,1,2,3]
    '{0,1, 24'h62EE0A, 8'h40},  // -d3    ISS ls=[3,0,5,6,7,0,1,2]
    '{0,1, 24'h425C01, 8'h44}   // -d4    ISS ls=[2,0,4,5,6,0,0,1]
  };

  // ===========================================================================
  // Pre-computed control signal arrays
  // ===========================================================================
  modp256_contrl_t ctrl_arr [LATENCY];
  modp256_predec_t pdec_arr [LATENCY];

  always_comb begin
    for (int c = 0; c < LATENCY; c++) begin
      ctrl_arr[c] = '0;
      pdec_arr[c] = '0;
    end

    // ---- Phase 1: Schoolbook (cycles 0-15) ----
    for (int c = 0; c < 16; c++) begin
      pdec_arr[c].sb_phase      = 1'b1;
      pdec_arr[c].op_a_qw_sel   = SB[c].i;
      pdec_arr[c].op_b_qw_sel   = SB[c].j;
      pdec_arr[c].dshift        = 9'(SB[c].i + SB[c].j) * 64;
      pdec_arr[c].adder_en      = 1'b1;
      pdec_arr[c].prod_lo_wr    = 1'b1;
      pdec_arr[c].prod_hi_wr    = (SB[c].i + SB[c].j >= 3);
      ctrl_arr[c].prod_lo_wr_en_raw = 1'b1;
      ctrl_arr[c].prod_hi_wr_en_raw = (SB[c].i + SB[c].j >= 3);
      ctrl_arr[c].adder_en_raw      = 1'b1;
    end

    // ---- Phase 2: Word-level carry chain (cycles 16-23) ----
    for (int c = 0; c < 8; c++) begin
      pdec_arr[16+c].solinas_phase  = 1'b1;
      pdec_arr[16+c].term_idx       = 3'(c);
      pdec_arr[16+c].adder_en       = 1'b1;
      pdec_arr[16+c].result_wr      = 1'b1;
      ctrl_arr[16+c].result_wr_en_raw = 1'b1;
      ctrl_arr[16+c].adder_en_raw     = 1'b1;
    end

    // ---- Phase 3: Conditional reduce (cycles 24-25) ----
    pdec_arr[24].cond_add_p = 1'b1;
    pdec_arr[24].result_wr  = 1'b1;
    pdec_arr[24].adder_en   = 1'b1;
    ctrl_arr[24].result_wr_en_raw = 1'b1;
    ctrl_arr[24].adder_en_raw     = 1'b1;

    pdec_arr[25].cond_sub_p = 1'b1;
    pdec_arr[25].result_wr  = 1'b1;
    pdec_arr[25].adder_en   = 1'b1;
    pdec_arr[25].operation_valid_raw = 1'b1;
    ctrl_arr[25].result_wr_en_raw = 1'b1;
    ctrl_arr[25].adder_en_raw     = 1'b1;

    // Accumulators auto-zero when idle (handled in otbn_modp256.sv datapath)
  end

  // ===========================================================================
  // Cycle counter
  // ===========================================================================
  localparam int CYCLE_W = $clog2(LATENCY + 1);
  logic [CYCLE_W-1:0] cycle_q, cycle_d;

  assign busy_o = (cycle_q != '0) || start_i;

  always_comb begin
    cycle_d = cycle_q;
    if (pdec_arr[cycle_q].operation_valid_raw || sec_wipe_i)
      cycle_d = '0;
    else if ((start_i || busy_o) && modp256_en_i)
      cycle_d = cycle_q + {{CYCLE_W-1{1'b0}}, 1'b1};
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      cycle_q <= '0;
    else
      cycle_q <= cycle_d;
  end

  assign ctrl_o   = ctrl_arr[cycle_q];
  assign predec_o = pdec_arr[cycle_q];
  assign state_err_o = cycle_q >= CYCLE_W'(LATENCY);

  // DEBUG: print every cycle when active to compare with redundant FSM
  `ifndef SYNTHESIS
  always_ff @(posedge clk_i) begin
    if (busy_o || modp256_en_i)
      $display("[MODP256_FSM] t=%0t cyc=%0d en=%0d busy=%0d pre=%54b",
               $time, cycle_q, modp256_en_i, busy_o,
               $bits(predec_o)'(predec_o));
  end
  `endif

  // ===========================================================================
  // Alert assertion
  // ===========================================================================
`ifdef INC_ASSERT
  logic unused_assert_connected;
  `ASSERT_INIT_NET(AssertConnected_A, unused_assert_connected === 1'b1 || !EnableAlertTriggerSVA)
`endif

endmodule
