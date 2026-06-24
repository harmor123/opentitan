// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// OTBN bn.modp256 — P-256 NIST Solinas modular multiplication.
// 16-cycle schoolbook + 10-term complement reduction + cond-sub + DONE.
// Total ~35 cycles. Verified against ISS (insn_ver2.py).

module otbn_modp256
  import otbn_pkg::*;
(
  input  logic clk_i,
  input  logic rst_ni,

  input  logic                  is_modp256_i,
  input  logic                  mac_en_i,
  input  logic                  mac_commit_i,
  input  mac_bignum_predec_t    predec_i,

  input  logic [WLEN-1:0]      operand_a_i,
  input  logic [WLEN-1:0]      operand_b_i,

  output logic [1:0]            mul_wsel_a_o,
  output logic [1:0]            mul_wsel_b_o,
  output logic [1:0]            mul_wmode_o,
  output logic [1:0]            mul_dshift_o,
  output logic [WLEN-1:0]       mul_A_o,
  output logic [WLEN-1:0]       mul_B_o,

  input  logic [2*WLEN-1:0]    mul_result_i,

  output logic [2*WLEN-1:0]    adder_op_a_o,
  output logic [2*WLEN-1:0]    adder_op_b_o,
  output vec_type_e             adder_word_mode_lo_o,
  output vec_type_e             adder_word_mode_hi_o,
  output logic                  adder_cin_lo_o,
  output logic                  adder_cin_hi_o,

  input  logic [2*WLEN-1:0]    adder_result_i,
  input  logic [15:0]          adder_cout_i,

  input  logic [WLEN-1:0]      acc_q_i,
  input  logic [WLEN-1:0]      acch_q_i,

  output logic [WLEN-1:0]      acc_d_o,
  output logic [WLEN-1:0]      acch_d_o,
  output logic                  acc_wr_en_add_o,
  output logic                  acch_wr_en_add_o,
  output logic                  acc_blk_dis_o,
  output logic                  acch_blk_dis_o,

  output logic [WLEN-1:0]      result_o,
  output logic                  valid_o,
  output flags_t                flags_o,
  output flags_t                flags_en_o
);

  // ============ Constants ============
  localparam P256 = 256'hffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
  localparam logic [WLEN-1:0] P256_2X = P256 * 2;  // 2p for d1,d2 complements

  // ============ FSM State ============
  typedef enum logic [1:0] {
    ST_IDLE, ST_MUL, ST_REDUCE, ST_DONE
  } state_e;
  state_e state_q, state_d;

  // ============ Schoolbook ============
  logic [3:0]      mul_cnt_q, mul_cnt_d;
  logic [WLEN-1:0] a_q, a_d, b_q, b_d;
  logic [1:0]      wsel_a, wsel_b, shift;
  logic            sel_hi;

  always_comb begin
    sel_hi = (mul_cnt_q >= 4'd10);
    unique case (mul_cnt_q)
      4'd0:  {wsel_a, wsel_b, shift} = {2'd0, 2'd0, 2'd0};
      4'd1:  {wsel_a, wsel_b, shift} = {2'd0, 2'd1, 2'd1};
      4'd2:  {wsel_a, wsel_b, shift} = {2'd0, 2'd2, 2'd2};
      4'd3:  {wsel_a, wsel_b, shift} = {2'd0, 2'd3, 2'd3};
      4'd4:  {wsel_a, wsel_b, shift} = {2'd1, 2'd0, 2'd1};
      4'd5:  {wsel_a, wsel_b, shift} = {2'd1, 2'd1, 2'd2};
      4'd6:  {wsel_a, wsel_b, shift} = {2'd1, 2'd2, 2'd3};
      4'd7:  {wsel_a, wsel_b, shift} = {2'd2, 2'd0, 2'd2};
      4'd8:  {wsel_a, wsel_b, shift} = {2'd2, 2'd1, 2'd3};
      4'd9:  {wsel_a, wsel_b, shift} = {2'd3, 2'd0, 2'd3};
      4'd10: {wsel_a, wsel_b, shift} = {2'd1, 2'd3, 2'd0};
      4'd11: {wsel_a, wsel_b, shift} = {2'd2, 2'd2, 2'd0};
      4'd12: {wsel_a, wsel_b, shift} = {2'd2, 2'd3, 2'd1};
      4'd13: {wsel_a, wsel_b, shift} = {2'd3, 2'd1, 2'd0};
      4'd14: {wsel_a, wsel_b, shift} = {2'd3, 2'd2, 2'd1};
      4'd15: {wsel_a, wsel_b, shift} = {2'd3, 2'd3, 2'd2};
    endcase
  end

  assign mul_wsel_a_o = wsel_a;
  assign mul_wsel_b_o = wsel_b;
  assign mul_wmode_o  = 2'b00;
  assign mul_dshift_o = shift;
  assign mul_A_o      = (state_q == ST_IDLE) ? operand_a_i : a_q;
  assign mul_B_o      = (state_q == ST_IDLE) ? operand_b_i : b_q;

  // ============ Reduction ============
  logic [3:0]      red_cnt_q, red_cnt_d;
  logic [WLEN-1:0] S_q, S_d;

  // 10-term Solinas ROM: {is_comp, lane_sel[7:0]}
  // Terms 0-5: add  (is_comp=0); Terms 6-9: complement (is_comp=1)
  // Lane sel 0-7 = S[255:224]..S[31:0]; 3'd0 = S[255:224]; zero via TERM_ZERO mask
  localparam int N_TERMS = 10;
  localparam logic [24:0] TERM_ROM [0:N_TERMS-1] = '{
    // +s1 : {S[7],S[6],S[5],S[4],S[3], 0,0,0}
    {1'b0, 3'd0, 3'd1, 3'd2, 3'd3, 3'd4, 3'd0, 3'd0, 3'd0},
    // +s1 (2nd)
    {1'b0, 3'd0, 3'd1, 3'd2, 3'd3, 3'd4, 3'd0, 3'd0, 3'd0},
    // +s2 : {0, S[7],S[6],S[5],S[4], 0,0,0}
    {1'b0, 3'd0, 3'd0, 3'd1, 3'd2, 3'd3, 3'd0, 3'd0, 3'd0},
    // +s2 (2nd)
    {1'b0, 3'd0, 3'd0, 3'd1, 3'd2, 3'd3, 3'd0, 3'd0, 3'd0},
    // +s3 : {S[7],S[6], 0,0,0, S[2],S[1],S[0]}
    {1'b0, 3'd0, 3'd1, 3'd0, 3'd0, 3'd0, 3'd5, 3'd6, 3'd7},
    // +s4 : {S[0],S[2],S[7],S[6],S[2],S[4],S[5],S[6]}
    {1'b0, 3'd7, 3'd2, 3'd0, 3'd1, 3'd2, 3'd4, 3'd5, 3'd6},
    // +(2p-d1): complement of d1={S[2],S[0],0,0,0,S[5],S[3],S[4]}
    {1'b1, 3'd5, 3'd7, 3'd0, 3'd0, 3'd0, 3'd2, 3'd3, 3'd4},
    // +(2p-d2): complement of d2={S[4],S[1],0,0,S[7],S[6],S[5],S[3]}
    {1'b1, 3'd4, 3'd6, 3'd0, 3'd0, 3'd0, 3'd1, 3'd2, 3'd3},
    // +(p-d3):  complement of d3={S[3],0,S[2],S[1],S[0],S[7],S[6],S[5]}
    {1'b1, 3'd3, 3'd0, 3'd5, 3'd6, 3'd7, 3'd0, 3'd1, 3'd2},
    // +(p-d4):  complement of d4={S[5],0,S[3],S[2],S[1],0,S[7],S[6]}
    {1'b1, 3'd2, 3'd0, 3'd4, 3'd5, 3'd6, 3'd0, 3'd0, 3'd1}
  };

  // Per-term zero lane masks
  localparam logic [7:0] TERM_ZERO [0:N_TERMS-1] = '{
    8'b00000111, 8'b00000111,  // +s1, +s1: lanes 2,1,0=0
    8'b10000111, 8'b10000111,  // +s2, +s2: lane 7=0, lanes 2,1,0=0
    8'b00111000,               // +s3: lanes 5,4,3=0
    8'b00000000,               // +s4: all used
    8'b00111000,               // d1: lanes 5,4,3=0
    8'b00110000,               // d2: lanes 5,4=0
    8'b01000000,               // d3: lane 6=0
    8'b01000100                // d4: lane 6=0, lane 2=0
  };

  function automatic logic [31:0] s_slice(logic [WLEN-1:0] S, logic [2:0] sel);
    unique case (sel)
      3'd0: return S[255:224];
      3'd1: return S[223:192];
      3'd2: return S[191:160];
      3'd3: return S[159:128];
      3'd4: return S[127:96];
      3'd5: return S[95:64];
      3'd6: return S[63:32];
      3'd7: return S[31:0];
    endcase
  endfunction

  logic            is_comp;
  logic [WLEN-1:0] term_val;
  logic [3:0]      term_idx;  // 0..9 for TERM_ROM lookup

  assign term_idx = red_cnt_q - 1;  // red_cnt 1..10 → idx 0..9

  always_comb begin
    term_val = '0;
    is_comp  = 1'b0;
    if (red_cnt_q >= 4'd1 && red_cnt_q <= 4'd10) begin
      is_comp = TERM_ROM[term_idx][24];
      for (int lane = 0; lane < 8; lane++) begin
        if (!TERM_ZERO[term_idx][lane])
          term_val[lane*32+:32] = s_slice(S_q, TERM_ROM[term_idx][3*lane+:3]);
      end
    end
  end

  logic in_s0, in_term, in_subp, subp_done;
  assign in_s0   = (state_q == ST_REDUCE) && (red_cnt_q == 4'd0);
  assign in_term = (state_q == ST_REDUCE) && (red_cnt_q >= 4'd1) && (red_cnt_q <= 4'd10);
  assign in_subp = (state_q == ST_REDUCE) && (red_cnt_q == 4'd11);
  assign subp_done = in_subp && (acch_q_i == '0) && !adder_cout_i[15];

  // ============ Adder routing ============
  logic [2*WLEN-1:0] mul_hi;
  assign mul_hi = {mul_result_i[WLEN-1:0], {WLEN{1'b0}}};

  logic            comp_hi;     // hardcoded: 1 for 2p (d1/d2), 0 for p (d3/d4)
  logic [WLEN-1:0] comp_lo;     // comp_p - term_val (256-bit subtraction)

  always_comb begin
    comp_hi = (red_cnt_q <= 4'd8);  // terms 7,8=2p(hi=1); terms 9,10=p(hi=0)
    comp_lo = ((red_cnt_q <= 4'd8) ? P256_2X : P256) - term_val;
  end

  always_comb begin
    if (in_term) begin
      if (is_comp) begin
        // Complement add: {ACCH, ACC} + {comp_hi, comp_p - term_val}
        adder_op_a_o = {{(WLEN-1){1'b0}}, comp_hi, comp_lo};
        adder_op_b_o = {acch_q_i, acc_q_i};
        adder_cin_lo_o = 1'b0;
      end else begin
        adder_op_a_o = {{WLEN{1'b0}}, term_val};
        adder_op_b_o = {acch_q_i, acc_q_i};
        adder_cin_lo_o = 1'b0;
      end
    end else if (in_subp) begin
      // {ACCH, ACC} - {0, P256}: upper all-1s needed for borrow propagation
      adder_op_a_o = {acch_q_i, acc_q_i};
      adder_op_b_o = ~{{WLEN{1'b0}}, P256};
      adder_cin_lo_o = 1'b1;
    end else begin
      adder_op_a_o = sel_hi ? mul_hi : mul_result_i;
      adder_op_b_o = (state_q == ST_IDLE) ? '0 : {acch_q_i, acc_q_i};
      adder_cin_lo_o = 1'b0;
    end
  end

  assign adder_word_mode_lo_o = VecType_v256;
  assign adder_word_mode_hi_o = VecType_v256;
  // VecType_v256: lo and hi adders are chained as single 512-bit adder.
  // cin_hi must be carry from lo for ALL operations.
  assign adder_cin_hi_o = adder_cout_i[15];

  // ============ Main FSM ============
  always_comb begin
    state_d    = state_q;
    mul_cnt_d  = mul_cnt_q;
    a_d        = a_q;
    b_d        = b_q;
    red_cnt_d  = red_cnt_q;
    S_d        = S_q;

    unique case (state_q)
      ST_IDLE: begin
        if (is_modp256_i && mac_en_i) begin
          state_d   = ST_MUL;
          mul_cnt_d = 4'd1;
          a_d       = operand_a_i;
          b_d       = operand_b_i;
        end
      end

      ST_MUL: begin
        if (mul_cnt_q == 4'd15)
          state_d = ST_REDUCE;
        else
          mul_cnt_d = mul_cnt_q + 1'b1;
      end

      ST_REDUCE: begin
        unique case (red_cnt_q)
          4'd0: begin  // S0: save S
            S_d       = acch_q_i;
            red_cnt_d = 4'd1;
          end
          4'd1, 4'd2, 4'd3, 4'd4, 4'd5,
          4'd6, 4'd7, 4'd8, 4'd9, 4'd10: begin
            red_cnt_d = red_cnt_q + 1'b1;
          end
          4'd11: begin  // SUB_P: done when ACCH==0 and no carry from lo
            if ((acch_q_i == '0) && !adder_cout_i[15])
              state_d = ST_DONE;
          end
          default: red_cnt_d = 4'd0;
        endcase
      end

      ST_DONE: begin
        state_d   = ST_IDLE;
        mul_cnt_d = 4'd0;
        red_cnt_d = 4'd0;
      end
      default: state_d = ST_IDLE;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q   <= ST_IDLE;
      mul_cnt_q <= 4'd0;
      a_q       <= '0;
      b_q       <= '0;
      red_cnt_q <= 4'd0;
      S_q       <= '0;
    end else begin
      state_q   <= state_d;
      mul_cnt_q <= mul_cnt_d;
      a_q       <= a_d;
      b_q       <= b_d;
      red_cnt_q <= red_cnt_d;
      S_q       <= S_d;
    end
  end

  // ============ ACC/ACCH data path ============
  always_comb begin
    acc_d_o  = adder_result_i[WLEN-1:0];
    acch_d_o = adder_result_i[2*WLEN-1:WLEN];

    if (in_s0) begin
      acc_d_o  = acc_q_i;
      acch_d_o = '0;
    end else if (state_q == ST_DONE) begin
      acch_d_o = '0;
    end
  end

  // ============ Write enables ============
  assign acc_wr_en_add_o = (state_q inside {ST_IDLE, ST_MUL})
                         | in_term
                         | (in_subp & ~subp_done);

  assign acch_wr_en_add_o = (state_q inside {ST_IDLE, ST_MUL})
                          | ((state_q == ST_REDUCE) & ~subp_done);

  assign acc_blk_dis_o  = (state_q inside {ST_IDLE, ST_MUL});
  assign acch_blk_dis_o = (state_q inside {ST_IDLE, ST_MUL});

  // ============ Result & flags ============
  assign result_o = acc_q_i;
  assign valid_o  = (state_q == ST_DONE);

  assign flags_o.L    = acc_q_i[0];
  assign flags_o.M    = acc_q_i[WLEN-1];
  assign flags_o.Z    = (acc_q_i == '0);
  assign flags_o.C    = |adder_cout_i;
  assign flags_en_o.L = (state_q == ST_DONE);
  assign flags_en_o.M = (state_q == ST_DONE);
  assign flags_en_o.Z = (state_q == ST_DONE);
  assign flags_en_o.C = (state_q == ST_DONE);

  // ============ DEBUG ============
  `ifdef VERILATOR
  always_ff @(posedge clk_i) begin
    if (is_modp256_i || state_q != ST_IDLE) begin
      $display("[MODP256] t=%0t st=%s mul=%0d red=%0d | S=%08x term=%08x comp=%08x is_comp=%0d | ACC=%08x ACCH=%08x | opA=%08x opB=%08x cin_lo=%0d cin_hi=%0d | adr=%08x adr_hi=%08x cout=%x | wr=%0d_%0d",
               $time,
               (state_q == ST_IDLE) ? "I" : (state_q == ST_MUL) ? "M" :
               (state_q == ST_REDUCE) ? "R" : "D",
               mul_cnt_q, red_cnt_q,
               S_q[31:0], term_val[31:0], {comp_hi, comp_lo[7:0]}, is_comp,
               acc_q_i[31:0], acch_q_i[31:0],
               adder_op_a_o[31:0], adder_op_b_o[31:0],
               adder_cin_lo_o, adder_cin_hi_o,
               adder_result_i[31:0], adder_result_i[WLEN+:32],
               adder_cout_i,
               acc_wr_en_add_o, acch_wr_en_add_o);
    end
  end
  `endif

endmodule
