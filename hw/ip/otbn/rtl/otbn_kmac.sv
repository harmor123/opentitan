// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// OTBN KMAC (Keccak/SHA3) interface
//
// Provides masked (2-share) KMAC/SHA3 access for OTBN programs.
// Follows the same CSR/WSR integration pattern as otbn_mai.sv.
//
// Instantiates keccak_round.sv from rtl/kmac/ for the actual
// Keccak-f[1600] permutation with 24 rounds.

`include "prim_assert.sv"

module otbn_kmac
  import otbn_pkg::*;
#(
  // Enable SCA-hardened 2-share DOM masking inside keccak_round.
  // When 1: DOM masked keccak-f (97 cycles) + URND squeeze masking (SCA production).
  // When 0: plain keccak-f (25 cycles) + zero squeeze masking (DV test).
  parameter bit    EnMasking          = 1'b0,
  // Keccak state width (fixed at 1600 for SHA3/SHAKE)
  parameter int    Width          = 1600,
  // Derived
  localparam int   W             = Width / 25,
  localparam int   L             = $clog2(W),
  localparam int   MaxRound      = 12 + 2 * L,
  localparam int   RndW          = $clog2(MaxRound + 1),
  localparam int   Share         = EnMasking ? 2 : 1
) (
  input  logic clk_i,
  input  logic rst_ni,

  // URND-based randomness (SCA countermeasure, same pattern as MAI)
  input  logic [UrndLen-1:0] urnd_data_i,

  // Secure wipe
  input  logic sec_wipe_kmac_i,
  input  logic sec_wipe_running_i,

  // CSR write ports
  input  logic        ispr_kmac_ctrl_wr_i,
  input  logic [31:0] ispr_kmac_ctrl_wdata_i,
  input  logic        ispr_kmac_msg_send_wr_i,     // kmac_msg_send (0x7DC)
  input  logic        ispr_kmac_byte_strobe_wr_i,  // kmac_byte_strobe (0x7DE)

  // CSR write — kmac_intr (W1C)
  input  logic        ispr_kmac_intr_wr_i,

  // CSR read ports
  output logic [31:0] ispr_kmac_ctrl_rdata_o,
  output logic [31:0] ispr_kmac_if_status_rdata_o,
  output logic [31:0] ispr_kmac_status_rdata_o,
  output logic [31:0] ispr_kmac_intr_rdata_o,
  output logic [31:0] ispr_kmac_error_rdata_o,

  // WSR write ports (IsprKmacDataS0 / IsprKmacDataS1)
  input  logic               ispr_kmac_data_s0_wr_i,
  input  logic               sec_wipe_kmac_data_s0_i,
  input  logic [ExtWLEN-1:0] ispr_kmac_data_s0_wdata_i,
  input  logic               ispr_kmac_data_s1_wr_i,
  input  logic               sec_wipe_kmac_data_s1_i,
  input  logic [ExtWLEN-1:0] ispr_kmac_data_s1_wdata_i,

  // WSR read ports
  output logic [ExtWLEN-1:0] ispr_kmac_data_s0_rdata_o,
  output logic [ExtWLEN-1:0] ispr_kmac_data_s1_rdata_o,

  // ISPR read strobes (for auto-advance on share read)
  input  logic               ispr_kmac_data_s0_rd_i,
  input  logic               ispr_kmac_data_s1_rd_i,

  // KMAC DOM masking randomness (800b, from otbn_rnd dedicated Trivium)
  // Only used when EnMasking=1.  Hardwired to 0 when EnMasking=0 (test mode).
  input  logic                        kmac_dom_rand_valid_i,
  input  logic [Width/2-1:0]          kmac_dom_rand_data_i,
  input  logic                        kmac_dom_rand_aux_i,
  output logic                        kmac_dom_rand_advance_o,

  // Error
  output logic kmac_state_err_o
);

  ////////////////////////////////////////////////////////////////////////////
  // Local parameters
  ////////////////////////////////////////////////////////////////////////////
  // Keccak timing: 1 cycle/round unmasked, 4 with DOM masking
  localparam int KeccakRounds   = 24;
  localparam int CyclesPerRound  = EnMasking ? 4 : 1;
  localparam int ProcessCycles   = KeccakRounds * CyclesPerRound;  // 24 or 96

  localparam int DInWidth  = 64;
  localparam int DInEntry  = Width / DInWidth;  // 1600/64 = 25
  localparam int DInAddr   = $clog2(DInEntry);  // 5 bits

  ////////////////////////////////////////////////////////////////////////////
  // FSM States (sparse encoding, HD≥3, 8 states)
  ////////////////////////////////////////////////////////////////////////////
  // Encoding generated with:
  // $ ./util/design/sparse-fsm-encode.py --language=sv \
  //     --seed 42 --distance 3 --states 8 --bits 8
  //
  // Minimum Hamming distance: 3
  // Maximum Hamming distance: 6
  localparam int KmacStateWidth = 8;
  typedef enum logic [KmacStateWidth-1:0] {
    StIdle            = 8'b00011100,
    StMsgFeed         = 8'b00000110,
    StPad             = 8'b10111101,
    StProcessing      = 8'b00100011,
    StSqueeze         = 8'b11100100,
    StTermError       = 8'b10001011,
    StSecWipeClearing = 8'b10010111,
    StSecWipeDone     = 8'b01110010
  } kmac_st_e;
  kmac_st_e st_q, st_d;

  ////////////////////////////////////////////////////////////////////////////
  // CSR Interface (field positions per csr.yml)
  ////////////////////////////////////////////////////////////////////////////
  // kmac_cfg (0x7DB): bit[0]=KMAC_EN, bits[3:1]=STRENGTH, bits[5:4]=MODE
  // kmac_cmd (0x7DD): bits[5:0]=CMD (START=0x1D, PROCESS=0x2E, RUN=0x31, DONE=0x16)
  // kmac_if_status (0x7D9): bit[0]=MSG_WRITE_RDY, bit[3]=DIGEST_VALID
  // kmac_status (0xFC2): bit[0]=SHA3_IDLE, bit[1]=SHA3_ABSORB, bit[2]=SHA3_SQUEEZE

  // Separate CFG (mode/strength, preserved) and CMD (auto-cleared) registers.
  // CFG is stored in two redundant copies for FI protection:
  //   cfg_lower  = {mode, strength} in bits[5:0]
  //   cfg_upper  = ~cfg_lower in bits[21:16] (inverted, offset by 16)
  logic [5:0] kmac_cfg_lower_q;     // lower copy (active config)
  logic [5:0] kmac_cfg_upper_q;     // upper copy (= ~lower, for FI detection)
  logic [31:0] kmac_ctrl_q;        // last write value (for readback)
  logic [31:0] kmac_byte_strobe_q; // byte strobe for partial writes (csr 0x7DE)

  // FI: config integrity check — upper must be bitwise inverse of lower
  logic cfg_integrity_err;
  assign cfg_integrity_err = (kmac_cfg_lower_q != ~kmac_cfg_upper_q);

  // Mode decode from cfg_lower_q: bits[5:4] — 0=SHA3, 2=SHAKE, 3=CSHAKE
  logic sha3_mode;
  assign sha3_mode = (kmac_cfg_lower_q[5:4] == 2'd0);

  // Strength decode from cfg_lower_q: bits[3:1]
  logic [8:0] digest_bits;
  always_comb begin
    unique case (kmac_cfg_lower_q[3:1])
      3'd0: digest_bits = 128;
      3'd1: digest_bits = 224;
      3'd2: digest_bits = 256;
      3'd3: digest_bits = 384;
      3'd4: digest_bits = 512;
      default: digest_bits = 256;
    endcase
  end

  // Command decode from write data when ctrl_wr=1, from reg otherwise.
  // CRITICAL: kmac_ctrl_q uses NBA, so during the write cycle it still has the old value.
  logic [5:0] kmac_cmd_eff;
  assign kmac_cmd_eff = ispr_kmac_ctrl_wr_i ? ispr_kmac_ctrl_wdata_i[5:0] : kmac_ctrl_q[5:0];

  // Command signals — raw (same-cycle) and delayed (1 cycle, matches ISS timing)
  logic cmd_start_raw, cmd_process_raw, cmd_run_raw, cmd_done_raw;
  assign cmd_start_raw   = (kmac_cmd_eff == 6'h1D);
  assign cmd_process_raw = (kmac_cmd_eff == 6'h2E);
  assign cmd_run_raw     = (kmac_cmd_eff == 6'h31);
  assign cmd_done_raw    = (kmac_cmd_eff == 6'h16);

  // Delayed by 1 cycle to match ISS kmac.step() timing
  logic cmd_start, cmd_process, cmd_run, cmd_done;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cmd_start   <= 1'b0;
      cmd_process <= 1'b0;
      cmd_run     <= 1'b0;
      cmd_done    <= 1'b0;
    end else begin
      cmd_start   <= cmd_start_raw;
      cmd_process <= cmd_process_raw;
      cmd_run     <= cmd_run_raw;
      cmd_done    <= cmd_done_raw;
    end
  end

  // wipe_configuration: asserted during StSecWipeClearing to clear internal state
  logic wipe_configuration;
  assign wipe_configuration = (st_q == StSecWipeClearing);

  // CSR write — cfg/cmd only (msg_send/byte_strobe use dedicated ports)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_cfg_lower_q <= '0;
      kmac_cfg_upper_q <= '0;
      kmac_ctrl_q      <= '0;
    end else if (sec_wipe_kmac_i || wipe_configuration) begin
      kmac_cfg_lower_q <= '0;
      kmac_cfg_upper_q <= '0;
      kmac_ctrl_q      <= '0;
    end else if (ispr_kmac_ctrl_wr_i) begin
      logic is_cmd;
      is_cmd = (ispr_kmac_ctrl_wdata_i[5:0] inside {6'h1D, 6'h2E, 6'h31, 6'h16});
      if (!is_cmd) begin
        kmac_cfg_lower_q <= ispr_kmac_ctrl_wdata_i[5:0];
        kmac_cfg_upper_q <= ispr_kmac_ctrl_wdata_i[21:16];
      end
      kmac_ctrl_q <= ispr_kmac_ctrl_wdata_i;
    end else begin
      kmac_ctrl_q[5:0] <= '0;
    end
  end

  // Byte strobe: dedicated port from IsprKmacByteStrobe
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      kmac_byte_strobe_q <= 32'hFFFF_FFFF;
    else if (st_q == StIdle)
      kmac_byte_strobe_q <= 32'hFFFF_FFFF;
    else if (ispr_kmac_byte_strobe_wr_i)
      kmac_byte_strobe_q <= ispr_kmac_ctrl_wdata_i;
  end
  assign ispr_kmac_ctrl_rdata_o = kmac_ctrl_q;

  // Status bits (YAML: kmac_status 0xFC2)
  // SHA3_IDLE[0], SHA3_ABSORB[1], SHA3_SQUEEZE[2]
  logic idle_s, absorb_s, squeeze_s;
  assign idle_s    = (st_q == StIdle);
  assign absorb_s  = (st_q == StMsgFeed) || (st_q == StPad) || (st_q == StProcessing);
  assign squeeze_s = (st_q == StSqueeze) && (process_cnt_q == '0);

  // kmac_if_status (0x7D9) bits
  logic msg_rdy_s, digest_valid_s;
  // msg_write_rdy per csr.yml: WSR is ready when in MSG_FEED, no active
  // absorption, Keccak not processing, and no run pending (one-hot constraint).
  // keccak_complete: allow back-to-back feed without a 1-cycle stall
  // after an auto-triggered keccak permutation (rate-full absorb).
  assign msg_rdy_s       = (st_q == StMsgFeed) && !absorb_active &&
                           (!absorb_hold_q || keccak_complete) &&
                           !keccak_run_pending_q &&
                           !process_pending_q;
  // DIGEST_VALID: word available and not yet fully read.
  // Gated with (st_d == StSqueeze) to prevent false-1 during state transitions
  // (e.g. RUN where st_q is still StSqueeze but we're leaving for StProcessing).
  assign digest_valid_s  = (st_q == StSqueeze) && (st_d == StSqueeze) &&
                           !both_shares_read && (sqz_word_idx < digest_words);

  // kmac_status (0xFC2): bit[0]=SHA3_IDLE, bit[1]=SHA3_ABSORB, bit[2]=SHA3_SQUEEZE
  logic [31:0] kmac_status_q;
  always_comb begin
    kmac_status_q       = '0;
    kmac_status_q[0]    = idle_s;
    kmac_status_q[1]    = absorb_s;
    kmac_status_q[2]    = squeeze_s;
  end
  // if_status: msg_write_rdy[0], cmd_sequence_err[1], wsr_write_err[2], digest_valid[3]
  logic [31:0] kmac_if_status;
  always_comb begin
    kmac_if_status = '0;
    kmac_if_status[0] = msg_rdy_s;               // MSG_WRITE_RDY (properly gated)
    kmac_if_status[1] = cmd_sequence_err_q;      // CMD_SEQUENCE_ERROR (W1C sticky)
    kmac_if_status[2] = wsr_write_err_q;         // WSR_WRITE_ERROR (W1C sticky)
    kmac_if_status[3] = digest_valid_s;          // DIGEST_VALID (per YAML)
  end
  assign ispr_kmac_if_status_rdata_o = kmac_if_status;
  assign ispr_kmac_status_rdata_o = kmac_status_q;

  ////////////////////////////////////////////////////////////////////////////
  // Sticky W1C error bits (FI hardening: error latched until SW clears)
  ////////////////////////////////////////////////////////////////////////////
  logic cmd_sequence_err_q, cmd_sequence_err_d;
  logic wsr_write_err_q,   wsr_write_err_d;

  logic clear_cmd_sequence_err;
  logic clear_wsr_write_err;

  // W1C clear: SW writes 1 to the corresponding bit in kmac_intr (0x7DA).
  // bit[0]: clear KMAC_ERROR (kmac_intr)
  // bit[1]: clear CMD_SEQUENCE_ERROR (kmac_if_status)
  // bit[2]: clear WSR_WRITE_ERROR    (kmac_if_status)
  assign clear_cmd_sequence_err = ispr_kmac_intr_wr_i && ispr_kmac_ctrl_wdata_i[1];
  assign clear_wsr_write_err    = ispr_kmac_intr_wr_i && ispr_kmac_ctrl_wdata_i[2];

  // Sticky error update: sec_wipe clears, violation sets, W1C clears
  assign cmd_sequence_err_d = sec_wipe_kmac_i        ? 1'b0 :
                              unexpected_cmd          ? 1'b1 :
                              clear_cmd_sequence_err  ? 1'b0 :
                                                       cmd_sequence_err_q;

  assign wsr_write_err_d = sec_wipe_kmac_i            ? 1'b0 :
                           (wsr_write_violation ||
                            cfg_write_violation ||
                            strb_write_violation)      ? 1'b1 :
                           clear_wsr_write_err         ? 1'b0 :
                                                         wsr_write_err_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cmd_sequence_err_q <= 1'b0;
      wsr_write_err_q    <= 1'b0;
    end else begin
      cmd_sequence_err_q <= cmd_sequence_err_d;
      wsr_write_err_q    <= wsr_write_err_d;
    end
  end

  // kmac_intr (0x7DA): bit[0]=KMAC_ERROR (W1C per csr.yml)
  // Software writes 1 to bit 0 to clear.  Set by HW on any error.
  logic [31:0] kmac_intr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_intr_q <= '0;
    end else if (sec_wipe_kmac_i) begin
      kmac_intr_q <= '0;
    end else begin
      if (kmac_state_err_o || cmd_sequence_err_q || wsr_write_err_q || cfg_integrity_err)
        kmac_intr_q[0] <= 1'b1;
      else if (ispr_kmac_intr_wr_i && ispr_kmac_ctrl_wdata_i[0])
        kmac_intr_q[0] <= 1'b0;
    end
  end
  assign ispr_kmac_intr_rdata_o = kmac_intr_q;

  // kmac_error (0xFC3): bits[7:0]=ERROR_CODE (read-only per csr.yml)
  // Sticky: latches the first error code. Cleared by sec_wipe.
  logic [31:0] kmac_error_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_error_q <= '0;
    end else if (sec_wipe_kmac_i) begin
      kmac_error_q <= '0;
    end else if (kmac_error_q == '0) begin
      if (kmac_state_err_o)
        kmac_error_q[7:0] <= 8'h08;            // ERR_SW_CMD_SEQUENCE (sec_wipe)
      else if (cmd_sequence_err_q)
        kmac_error_q[7:0] <= 8'h08;            // ERR_SW_CMD_SEQUENCE
      else if (wsr_write_err_q)
        kmac_error_q[7:0] <= 8'h01;            // ERR_SW_MSG_WRITE
    end
  end
  assign ispr_kmac_error_rdata_o = kmac_error_q;

  ////////////////////////////////////////////////////////////////////////////
  // URND-based masking (SCA countermeasure — same pattern as MAI)
  ////////////////////////////////////////////////////////////////////////////
  localparam int unsigned KmacUrndRsvdWidth = UrndLen - ExtWLEN;
  typedef struct packed {
    logic [KmacUrndRsvdWidth-1:0] rsvd;
    logic [ExtWLEN-1:0]           urnd;
  } kmac_ispr_urnd_t;

  kmac_ispr_urnd_t kmac_ispr_urnd;
  logic            unused_kmac_urnd;

  assign kmac_ispr_urnd = urnd_data_i;
  assign unused_kmac_urnd = ^kmac_ispr_urnd.rsvd;

  ////////////////////////////////////////////////////////////////////////////
  // WSR Data Path (2-share masked transport)
  ////////////////////////////////////////////////////////////////////////////
  logic [ExtWLEN-1:0] kmac_data_s0_q, kmac_data_s1_q;
  logic [ExtWLEN-1:0] kmac_data_s0_d, kmac_data_s1_d;
  logic               kmac_data_s0_wr_en, kmac_data_s1_wr_en;

  logic [WLEN-1:0]    kmac_data_s0_no_intg, kmac_data_s1_no_intg;

  // Write enables
  assign kmac_data_s0_wr_en = ispr_kmac_data_s0_wr_i | sec_wipe_kmac_data_s0_i | sqz_write_en;
  assign kmac_data_s1_wr_en = ispr_kmac_data_s1_wr_i | sec_wipe_kmac_data_s1_i | sqz_write_en;

  always_comb begin
    kmac_data_s0_d = ispr_kmac_data_s0_wdata_i;
    kmac_data_s1_d = ispr_kmac_data_s1_wdata_i;
    if (sec_wipe_kmac_data_s0_i) begin
      kmac_data_s0_d = kmac_ispr_urnd.urnd;
      kmac_data_s1_d = kmac_ispr_urnd.urnd;
    end
    if (sqz_write_en) begin
      kmac_data_s0_d = sqz_data_s0_intg;
      kmac_data_s1_d = sqz_data_s1_intg;
    end
  end

  always_ff @(posedge clk_i) begin
    if (kmac_data_s0_wr_en) kmac_data_s0_q <= kmac_data_s0_d;
    if (kmac_data_s1_wr_en) kmac_data_s1_q <= kmac_data_s1_d;
  end

  for (genvar i = 0; i < BaseWordsPerWLEN; i++) begin : g_wsr_rd
    assign ispr_kmac_data_s0_rdata_o[i*39+:39] = kmac_data_s0_q[i*39+:39];
    assign ispr_kmac_data_s1_rdata_o[i*39+:39] = kmac_data_s1_q[i*39+:39];
    assign kmac_data_s0_no_intg[i*32+:32]      = kmac_data_s0_q[i*39+:32];
    assign kmac_data_s1_no_intg[i*32+:32]      = kmac_data_s1_q[i*39+:32];
  end

  ////////////////////////////////////////////////////////////////////////////
  // Message Absorption
  ////////////////////////////////////////////////////////////////////////////
  logic                  keccak_feed_valid;
  logic [DInAddr-1:0]    keccak_feed_addr;
  logic [DInWidth-1:0]   keccak_feed_data;
  logic                  keccak_feed_ready;

  // Pre-computed & registered XOR for glitch suppression.
  // All 4 WSR words are XORed in parallel from kmac_data_s0/1_no_intg
  // (which are wire extractions from registered kmac_data_s0/1_q).
  // The result is registered BEFORE feed_word_sel selects the active word,
  // so the s0^s1 XOR glitch is isolated behind a register boundary.
  // Downstream logic (mask AND, MUX, keccak_round storage XOR) sees
  // clean registered outputs with balanced arrival times.
  logic [1:0] feed_word_sel;
  assign feed_word_sel = absorb_active ? absorb_word_cnt : '0;

  logic [DInWidth-1:0]        feed_byte_mask;
  logic [3:0][DInWidth-1:0]   pre_xor_d, pre_xor_q;

  // Parallel XOR: all 4 words computed from registered WSR data
  always_comb begin
    for (int w = 0; w < 4; w++) begin
      for (int i = 0; i < DInWidth; i++) begin
        pre_xor_d[w][i] = kmac_data_s0_no_intg[w * DInWidth + i] ^
                          kmac_data_s1_no_intg[w * DInWidth + i];
      end
    end
  end

  // Register isolates glitch from propagating to keccak_round
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      pre_xor_q <= '{default: '0};
    end else begin
      pre_xor_q <= pre_xor_d;
    end
  end

  // Byte mask + word selection from registered pre_xor_q
  always_comb begin
    feed_byte_mask = '0;
    for (int b = 0; b < (DInWidth/8); b++)
      if (kmac_byte_strobe_q[feed_word_sel * (DInWidth/8) + b])
        feed_byte_mask[b*8 +: 8] = 8'hFF;
    keccak_feed_data = pre_xor_q[feed_word_sel] & feed_byte_mask;
  end

  // Message absorption tracking
  logic [9:0] absorb_total = '0;      // total 64-bit words absorbed (all rate blocks)
  logic [9:0] absorb_rate_pos;        // position within current rate block (0..rate_words-1)
  logic [9:0] pad_words_needed;       // padding words needed in current rate block

  // Multi-word absorption: WSR write triggers up to 4-cycle absorption.
  // Byte strobe limits which words are valid (for partial final writes).
  logic [2:0] absorb_word_cnt;     // 0..3 within current WSR
  logic       absorb_active;
  logic [2:0] absorb_words_total;  // number of words to absorb (1..4)

  // Count valid words from byte_strobe (at least 1 byte valid per word)
  logic [2:0] strobe_words;
  always_comb begin
    strobe_words = '0;
    for (int w = 0; w < 4; w++) begin
      if (|kmac_byte_strobe_q[w*8 +: 8]) strobe_words = strobe_words + 1'b1;
    end
    if (strobe_words == 0) strobe_words = 4;  // default: all valid
  end

  // Start-absorption trigger: msg_send when Keccak is ready to accept data.
  // keccak_complete bypasses absorb_hold_q to avoid a 1-cycle stall after
  // an auto-triggered keccak permutation (rate-full absorb in StMsgFeed).
  logic start_absorb;
  assign start_absorb = ispr_kmac_msg_send_wr_i && !absorb_active &&
                        (!absorb_hold_q || keccak_complete) &&
                        !keccak_run_pending_q &&
                        !process_pending_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      absorb_active      <= 1'b0;
      absorb_word_cnt    <= '0;
      absorb_words_total <= 4;
    end else if (st_q != StMsgFeed && st_q != StPad) begin
      absorb_active      <= 1'b0;
      absorb_word_cnt    <= '0;
      absorb_words_total <= 4;
    end else begin
      // Start multi-word absorption on msg_send
      if (start_absorb) begin
        absorb_active      <= 1'b1;
        absorb_word_cnt    <= '0;
        absorb_words_total <= strobe_words;
      end

      // Count absorbed words; clear absorb_active when done
      if (absorb_active && keccak_feed_valid) begin
        if (absorb_word_cnt == (absorb_words_total - 1))
          absorb_active <= 1'b0;
        else
          absorb_word_cnt <= absorb_word_cnt + 1'b1;
      end
    end
  end

  // Hold absorption during keccak permutation triggered by rate-full.
  //
  // keccak_round requires valid_i and run_i to be one-hot (never both 1 in
  // the same cycle).  We use a pending flag: the cycle after the last feed
  // of a rate block we assert keccak_run alone (valid_i = 0), satisfying
  // the one-hot constraint.  absorb_hold_q clears on keccak_complete.
  logic absorb_hold_q;
  logic keccak_run_pending_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                              absorb_hold_q <= 1'b0;
    else if (st_q == StIdle)                  absorb_hold_q <= 1'b0;
    else if (keccak_complete)                 absorb_hold_q <= 1'b0;
    else if (keccak_run)                      absorb_hold_q <= 1'b1;
  end

  // Pending flag: set when the last word of a rate block is fed, cleared
  // when keccak_run is asserted (next cycle, alone without a feed).
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                              keccak_run_pending_q <= 1'b0;
    else if (st_q == StIdle)                  keccak_run_pending_q <= 1'b0;
    else if (st_d == StProcessing)            keccak_run_pending_q <= 1'b0;
    else if (keccak_run)                      keccak_run_pending_q <= 1'b0;
    // Auto-trigger only when the word at the last rate position has
    // all 8 bytes valid.  A partial word (byte_strobe not all-ones)
    // means the rate block is not truly full; padding fills the gap.
    else if (keccak_feed_valid && absorb_rate_pos == (rate_words - 1) &&
             &kmac_byte_strobe_q[feed_word_sel * 8 +: 8])
      keccak_run_pending_q <= 1'b1;
  end

  // Feed only when not holding and no run pending (one-hot with run_i).
  assign keccak_feed_valid = absorb_active && !absorb_hold_q && !keccak_run_pending_q;
  // Use position within current rate block as feed address.
  // keccak_round handles the rate-capacity boundary internally.
  assign keccak_feed_addr  = DInAddr'(absorb_rate_pos);

  // Latch cmd_process when keccak is busy (rate-full auto-trigger).
  // Cleared when entering StPad or leaving StMsgFeed.
  logic process_pending_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                              process_pending_q <= 1'b0;
    else if (st_q != StMsgFeed)               process_pending_q <= 1'b0;
    else if (st_d == StPad)                   process_pending_q <= 1'b0;
    else if (cmd_process && (absorb_hold_q || keccak_run_pending_q))
      process_pending_q <= 1'b1;
  end

  ////////////////////////////////////////////////////////////////////////////
  // SHA3 Padding
  ////////////////////////////////////////////////////////////////////////////
  // Rate (block size) in 64-bit words, derived from strength
  logic [4:0] rate_words;
  always_comb begin
    unique case (kmac_cfg_lower_q[3:1])
      3'd0: rate_words = 21;  // L128:  1344 bits
      3'd1: rate_words = 18;  // L224:  1152 bits
      3'd2: rate_words = 17;  // L256:  1088 bits
      3'd3: rate_words = 13;  // L384:   832 bits
      3'd4: rate_words =  9;  // L512:   576 bits
      default: rate_words = 17;
    endcase
  end
  // Padding fills the remainder of the current rate block.
  // absorb_rate_pos tracks position within the current block (0..rate_words-1).
  // For partial last word: first pad word overlaps, so +1.
  // When absorb_rate_pos wrapped to 0 with a partial word at the last
  // rate position (no auto-trigger), only the overlap word is needed.
  assign pad_words_needed =
    (absorb_rate_pos == 0 && last_valid_bytes != 3'd0 && absorb_total > 0)
      ? 1  // only the overlap word at the last rate position
      : rate_words - absorb_rate_pos +
        ((absorb_rate_pos > 0 && last_valid_bytes != 3'd0) ? 1 : 0);
  logic [9:0] pad_cnt;  // wide enough for max rate (21 for L128)

  // pad10*1 generator: domain suffix varies by mode (SHA3=01, SHAKE=1111)
  //
  // last_valid_bytes = offset of first invalid byte within its 64-bit word (0..7).
  //   0 = last word was full (all 8 bytes valid), pad starts at byte 0 of next word.
  //   1..7 = partial word, first pad byte overlaps this word at this byte position.
  //   3-bit holds 0..7; full word (8 valid bytes) is encoded as 0.
  logic [2:0] last_valid_bytes;
  always_comb begin
    last_valid_bytes = 3'd0;  // default: full last word (pad starts at byte 0 of next word)
    for (int b = 0; b < 32; b++)
      if (!kmac_byte_strobe_q[b]) begin
        last_valid_bytes = 3'(b % 8);
        break;
      end
  end
  logic [DInWidth-1:0] pad_word;
  always_comb begin
    pad_word = '0;
    if (pad_cnt == 0)
      pad_word = (sha3_mode ? 64'h0000_0000_0000_0006   // SHA3: 01 + pad start
                            : 64'h0000_0000_0000_001F)  // SHAKE: 1111 + pad start
                 << (last_valid_bytes * 8);
    if (pad_cnt == (pad_words_needed - 1))
      pad_word = pad_word | 64'h8000_0000_0000_0000;  // pad10*1 terminator (all modes)
  end

  // Feed padding words to Keccak during StPad state.
  // Wait until absorption is idle before starting padding.
  // Skip intermediate zero pad words: only first (0x06/0x1F) and last (0x80) are non-zero.
  logic keccak_pad_skip;
  assign keccak_pad_skip = (st_q == StPad) && (pad_cnt == 1) && (pad_words_needed > 2);
  logic keccak_pad_valid;
  assign keccak_pad_valid = (st_q == StPad) && (pad_cnt < pad_words_needed) &&
                            !absorb_active && !keccak_pad_skip;

  // Multiplex: feed msg or padding to Keccak
  logic                  keccak_feed_valid_mux;
  logic [DInAddr-1:0]    keccak_feed_addr_mux;
  logic [DInWidth-1:0]   keccak_feed_data_mux;

  assign keccak_feed_valid_mux = (keccak_feed_valid || keccak_pad_valid) && keccak_feed_ready;
  // Pad base address: partial last word → pad starts at same lane (overlap)
  logic [9:0] pad_base;
  assign pad_base = (absorb_rate_pos > 0 && last_valid_bytes != 3'd0)
                    ? (absorb_rate_pos - 1)
                    : (absorb_rate_pos == 0 && last_valid_bytes != 3'd0 && absorb_total > 0)
                      ? (rate_words - 1)
                      : absorb_rate_pos;
  assign keccak_feed_addr_mux  = keccak_feed_valid ? keccak_feed_addr :
                                 DInAddr'(pad_base + pad_cnt);
  assign keccak_feed_data_mux  = keccak_feed_valid ? keccak_feed_data :
                                 pad_word;

  ////////////////////////////////////////////////////////////////////////////
  // Keccak Round Core
  ////////////////////////////////////////////////////////////////////////////
  logic keccak_run;
  logic keccak_complete;
  logic [Width-1:0] keccak_state [Share];
  logic keccak_sparse_err, keccak_round_err, keccak_rst_err;

  // KMAC DOM masking randomness mux: EnMasking=0 → tie to 0 (test mode),
  // EnMasking=1 → forward from dedicated 800b Trivium (production SCA).
  logic                        kmac_rand_valid;
  logic [Width/2-1:0]          kmac_rand_data;
  logic                        kmac_rand_aux;
  logic                        kmac_rand_update, kmac_rand_consumed;

  if (!EnMasking) begin : gen_kmac_rand_tie_off
    // Test mode: keccak-f runs unmasked, no randomness needed.
    // Tie all rand ports to 0 and suppress advance requests.
    assign kmac_rand_valid  = 1'b0;
    assign kmac_rand_data   = '0;
    assign kmac_rand_aux    = 1'b0;
    // Unused advance signals — tie off
    logic unused_kmac_rand_update;
    logic unused_kmac_rand_consumed;
    assign unused_kmac_rand_update   = kmac_rand_update;
    assign unused_kmac_rand_consumed = kmac_rand_consumed;
  end else begin : gen_kmac_rand_connected
    // Production SCA mode: forward 800b randomness from dedicated Trivium.
    assign kmac_rand_valid  = kmac_dom_rand_valid_i;
    assign kmac_rand_data   = kmac_dom_rand_data_i;
    assign kmac_rand_aux    = kmac_dom_rand_aux_i;
  end

  // Advance the DOM PRNG when keccak_round signals consumption or update.
  assign kmac_dom_rand_advance_o = kmac_rand_update | kmac_rand_consumed;

  // data_i port is parameterized by Share. Verilator 4.210 does not support
  // '{} assignment patterns for parameterized unpacked arrays, so we use
  // Feed message only into share0 in masked mode; XORing the same plaintext
  // into both shares would cancel out: (s0^msg)^(s1^msg) = s0^s1 (no change).
  // By feeding only share0: (s0^msg)^s1 = (s0^s1)^msg — correct invariant.
  logic [DInWidth-1:0] keccak_feed_data_arr [Share];
  assign keccak_feed_data_arr[0] = keccak_feed_data_mux;
  if (Share > 1) begin : gen_feed_s1_zero
    assign keccak_feed_data_arr[1] = '0;
  end

  keccak_round #(
    .Width(Width),
    .DInWidth(DInWidth),
    .EnMasking(EnMasking),
    .ForceRandExt(1'b0)
  ) u_keccak_round (
    .clk_i,
    .rst_ni,
    .valid_i            (keccak_feed_valid_mux),
    .addr_i             (keccak_feed_addr_mux),
    .data_i             (keccak_feed_data_arr),
    .ready_o            (keccak_feed_ready),
    .run_i              (keccak_run),
    .rand_valid_i       (kmac_rand_valid),
    .rand_early_i       (1'b0),
    .rand_data_i        (kmac_rand_data),
    .rand_aux_i         (kmac_rand_aux),
    .rand_update_o      (kmac_rand_update),
    .rand_consumed_o    (kmac_rand_consumed),
    .complete_o         (keccak_complete),
    .state_o            (keccak_state),
    .lc_escalate_en_i   (lc_ctrl_pkg::Off),
    .sparse_fsm_error_o (keccak_sparse_err),
    .round_count_error_o(keccak_round_err),
    .rst_storage_error_o(keccak_rst_err),
    .clear_i            (keccak_clear ? prim_mubi_pkg::MuBi4True :
                                           prim_mubi_pkg::MuBi4False)
  );

  // Process counter — decrements in StProcessing, matches ISS KECCAK_PROCESS_CYCLES (96).
  // Only set on StPad→StProcessing. SHAKE RUN enters StProcessing from StSqueeze
  // and relies on keccak_done_q alone — exits as soon as keccak-f completes.
  logic [$clog2(ProcessCycles+1)-1:0] process_cnt_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                                    process_cnt_q <= '0;
    else if (st_q == StPad && pad_cnt == pad_words_needed)
      process_cnt_q <= ProcessCycles;  // 96, matches ISS KECCAK_PROCESS_CYCLES
    else if (process_cnt_q > 0)
      process_cnt_q <= process_cnt_q - 1'b1;
  end

  // Keccak state clear on START (reset internal state for new hash operation)
  logic keccak_clear;
  assign keccak_clear = (st_q == StIdle) && (st_d == StMsgFeed);

  // Latch keccak_complete until FSM leaves StProcessing, clear on re-entry
  logic keccak_done_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) keccak_done_q <= 1'b0;
    else if ((st_q != StProcessing) && (st_d == StProcessing))
      keccak_done_q <= 1'b0;  // entering StProcessing: reset for new keccak run
    else if (keccak_complete) keccak_done_q <= 1'b1;
    else if (st_q != StProcessing) keccak_done_q <= 1'b0;
  end

  ////////////////////////////////////////////////////////////////////////////
  // Squeeze — YAML streaming interface (64-bit words, auto-advance on read)
  ////////////////////////////////////////////////////////////////////////////
  // Per wsr.yml: digest data provided in chunks of 64 bits at a time.
  //   bits[63:0]   = current 64-bit digest word
  //   bits[255:64] = 0 (reads return zero; digest only via low word)
  // Hardware auto-advances to the next word when both shares are read.

  // Digest size in 64-bit words. SHA3: fixed per strength; SHAKE: per batch.
  logic [4:0] digest_words;
  always_comb begin
    if (!sha3_mode) begin
      digest_words = {1'b0, rate_words};  // SHAKE: full block per batch
    end else begin
      unique case (kmac_cfg_lower_q[3:1])
        3'd1: digest_words = 5'd4;   // L224
        3'd2: digest_words = 5'd4;   // L256
        3'd3: digest_words = 5'd6;   // L384
        3'd4: digest_words = 5'd8;   // L512
        default: digest_words = 5'd4;
      endcase
    end
  end

  // ISPR read tracking — auto-advance when both shares read (YAML wsr.yml)
  logic s0_read_q, s1_read_q;
  logic both_shares_read;
  assign both_shares_read = s0_read_q && s1_read_q;

  logic advance_word;
  assign advance_word = both_shares_read && (sqz_word_idx < digest_words);

  // Entering StSqueeze edge detect
  logic entering_squeeze;
  assign entering_squeeze = (st_q != StSqueeze) && (st_d == StSqueeze);

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      s0_read_q <= 1'b0;
      s1_read_q <= 1'b0;
    // Clear read flags on: entering squeeze, word advance, OR any time outside
    // StSqueeze.  st_d != StSqueeze is needed (in addition to st_q != StSqueeze)
    // because st_q uses NBA semantics — on the cycle we leave StSqueeze the old
    // st_q is still StSqueeze so st_q != StSqueeze evaluates to false.
    end else if (entering_squeeze || advance_word || (st_q != StSqueeze) || (st_d != StSqueeze)) begin
      s0_read_q <= 1'b0;
      s1_read_q <= 1'b0;
    end else if (st_q == StSqueeze) begin
      if (ispr_kmac_data_s0_rd_i) begin
        s0_read_q <= 1'b1;
      end
      if (ispr_kmac_data_s1_rd_i) begin
        s1_read_q <= 1'b1;
      end
    end
  end

  // Squeeze word index (0..digest_words-1, up to 7 for SHA3-512)
  logic [4:0] sqz_word_idx;  // up to 21 for SHAKE128
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sqz_word_idx <= '0;
    end else if (st_q != StSqueeze) begin
      sqz_word_idx <= '0;
    end else if (advance_word) begin
      sqz_word_idx <= sqz_word_idx + 1'b1;
    end
  end

  // Squeeze ready: word available and not yet fully read.
  // st_d == StSqueeze gates off squeeze during transition cycles (e.g. RUN)
  // where st_q is still StSqueeze but st_d is already StProcessing, preventing
  // a squeeze write that coincides with keccak_run corrupting the state readout.
  logic sqz_rdy;
  assign sqz_rdy = (st_q == StSqueeze) && (st_d == StSqueeze) &&
                   !both_shares_read && (sqz_word_idx < digest_words);

  // Effective word index: advance writes the NEXT word immediately
  logic [4:0] sqz_eff_idx;
  assign sqz_eff_idx = advance_word ? (sqz_word_idx + 1'b1) : sqz_word_idx;

  // Write new word to WSR when squeeze is ready, or during advance
  logic sqz_write_en;
  assign sqz_write_en = sqz_rdy ||
      (advance_word && (sqz_word_idx + 1'b1 < digest_words));

  // Extract current 64-bit word from Keccak state lane.
  // In masked mode (EnMasking=1), the Keccak state is DOM 2-share masked.
  // We must XOR share0 ^ share1 to recover the logical plaintext lane value.
  // The resulting plaintext is then re-encoded with URND masking (below)
  // for protected transport over the WSR bus interface.
  logic [63:0] sqz_word_64;
  if (EnMasking) begin : gen_sqz_unmask
    assign sqz_word_64 = keccak_state[0][sqz_eff_idx * 64 +: 64] ^
                         keccak_state[1][sqz_eff_idx * 64 +: 64];
  end else begin : gen_sqz_direct
    assign sqz_word_64 = keccak_state[0][sqz_eff_idx * 64 +: 64];
  end

  // Build 256-bit WSR plaintext: only bits[63:0] carry data (YAML spec)
  logic [WLEN-1:0] sqz_word_plain;
  assign sqz_word_plain = {{(WLEN-64){1'b0}}, sqz_word_64};

  // SCA masking: URND-based 2-share split when EnMasking=1, zero for DV.
  // Mask is latched per squeeze word: bn.wsrr reads s0 and s1 in separate
  // cycles, so the mask must stay stable between those two reads.
  logic [63:0] sqz_mask_64;
  if (EnMasking) begin : gen_sqz_mask_urnd
    logic [63:0] sqz_mask_q;
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) sqz_mask_q <= '0;
      else if (entering_squeeze || advance_word)
        sqz_mask_q <= kmac_ispr_urnd.urnd[63:0];
    end
    assign sqz_mask_64 = sqz_mask_q;
  end else begin : gen_sqz_mask_zero
    assign sqz_mask_64 = '0;
  end

  // 2-share encoding with SECDED ECC integrity bits (same as MAI pattern)
  logic [WLEN-1:0] sqz_data_s0_plain;
  logic [WLEN-1:0] sqz_data_s1_plain;
  assign sqz_data_s0_plain = {{(WLEN-64){1'b0}}, sqz_word_64 ^ sqz_mask_64};
  assign sqz_data_s1_plain = {{(WLEN-64){1'b0}}, sqz_mask_64};

  logic [ExtWLEN-1:0] sqz_data_s0_intg;
  logic [ExtWLEN-1:0] sqz_data_s1_intg;

  for (genvar i = 0; i < BaseWordsPerWLEN; i++) begin : g_sqz_intg_enc
    prim_secded_inv_39_32_enc u_s0_enc (
      .data_i(sqz_data_s0_plain[i*32+:32]),
      .data_o(sqz_data_s0_intg[i*39+:39])
    );
    prim_secded_inv_39_32_enc u_s1_enc (
      .data_i(sqz_data_s1_plain[i*32+:32]),
      .data_o(sqz_data_s1_intg[i*39+:39])
    );
  end

  ////////////////////////////////////////////////////////////////////////////
  // FSM
  ////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////
  // Secure wipe detection (latched until wipe sequence completes)
  ////////////////////////////////////////////////////////////////////////////
  logic sec_wipe_detected_q, sec_wipe_detected_d;
  logic sec_wipe_detected;
  logic sec_wipe_complete;

  // sec_wipe_kmac_i is a level signal; latch it so we don't miss a pulse
  // during an active session.
  assign sec_wipe_detected = sec_wipe_kmac_i || sec_wipe_detected_q;

  assign sec_wipe_detected_d = sec_wipe_kmac_i  ? 1'b1 :
                               sec_wipe_complete ? 1'b0 :
                                                   sec_wipe_detected_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) sec_wipe_detected_q <= 1'b0;
    else         sec_wipe_detected_q <= sec_wipe_detected_d;
  end

  logic unexpected_cmd;  // asserted when a command is issued in the wrong state
  // Use cmd_*_raw (not cmd_*) for unexpected_cmd detection.  cmd_*_raw reflects
  // what SW actually issued THIS cycle.  cmd_* is 1-cycle-delayed and can
  // persist for an extra cycle after the FSM has already transitioned, causing
  // false-positive unexpected_cmd assertions.

  always_comb begin
    st_d              = st_q;
    keccak_run        = 1'b0;
    unexpected_cmd    = 1'b0;
    sec_wipe_complete = 1'b0;

    unique case (st_q)
      StIdle: begin
        if (sec_wipe_detected) begin
          st_d = StSecWipeClearing;
        end else begin
          if (cmd_process_raw || cmd_run_raw || cmd_done_raw)
            unexpected_cmd = 1'b1;
          if (cmd_start) st_d = StMsgFeed;
        end
      end

      StMsgFeed: begin
        if (sec_wipe_detected && !absorb_active && !keccak_run_pending_q) begin
          // Gracefully end message phase: discard pending data, go to wipe
          st_d = StSecWipeClearing;
        end else begin
          if (cmd_start_raw || cmd_run_raw || cmd_done_raw)
            unexpected_cmd = 1'b1;
          if (ispr_kmac_msg_send_wr_i && cmd_process_raw)
            unexpected_cmd = 1'b1;
          // ... normal MsgFeed logic ...
          if (keccak_run_pending_q)
            keccak_run = 1'b1;
          if (process_pending_q && !absorb_hold_q && !keccak_run_pending_q) begin
            st_d = StPad;
          end else if (cmd_process) begin
            if (absorb_hold_q || keccak_run_pending_q) begin
              // defer to process_pending_q
            end else begin
              st_d = StPad;
            end
          end
        end
      end

      StPad: begin
        if (sec_wipe_detected) begin
          st_d = StSecWipeClearing;
        end else begin
          if (cmd_start_raw || cmd_process_raw || cmd_run_raw ||
              cmd_done_raw || ispr_kmac_msg_send_wr_i)
            unexpected_cmd = 1'b1;
          if (pad_cnt == pad_words_needed) begin
            keccak_run = 1'b1;
            st_d = StProcessing;
          end
        end
      end

      StProcessing: begin
        if (sec_wipe_detected && keccak_done_q) begin
          // Let keccak-f finish, then wipe. Digest will be discarded.
          st_d = StSecWipeClearing;
        end else begin
          if (cmd_start_raw || cmd_process_raw || cmd_done_raw || ispr_kmac_msg_send_wr_i)
            unexpected_cmd = 1'b1;
          if (keccak_done_q && process_cnt_q == 0)
            st_d = StSqueeze;
        end
      end

      StSqueeze: begin
        if (sec_wipe_detected) begin
          st_d = StSecWipeClearing;
        end else begin
          if (cmd_start_raw || cmd_process_raw || ispr_kmac_msg_send_wr_i)
            unexpected_cmd = 1'b1;
          if ((cmd_run_raw && !sha3_mode) || (cmd_run && !sha3_mode)) begin
            keccak_run = 1'b1;
            st_d = StProcessing;
          end else if (cmd_done)
            st_d = StIdle;
        end
      end

      StSecWipeClearing: begin
        // Clear all internal state: cfg, strb, absorb, pending flags.
        // The data WSRs (kmac_data_s0/1) are cleared externally via
        // sec_wipe_kmac_data_s0/1_i controlled by otbn_start_stop.
        st_d = StSecWipeDone;
      end

      StSecWipeDone: begin
        if (!sec_wipe_kmac_i) begin
          st_d = StIdle;
          sec_wipe_complete = 1'b1;
        end
      end

      StTermError: begin
        if (sec_wipe_detected) begin
          st_d = StSecWipeClearing;
        end else begin
          st_d = StTermError;
        end
      end

      default: begin
        // Sparse FSM violation: state register corrupted to illegal value.
        st_d = StTermError;
      end
    endcase
  end

  `PRIM_FLOP_SPARSE_FSM(u_state_regs, st_d, st_q, kmac_st_e, StIdle)

  ////////////////////////////////////////////////////////////////////////////
  // Write violation detection (FI: WSR/CFG/STRB writes in wrong state)
  ////////////////////////////////////////////////////////////////////////////
  logic wsr_write_violation;
  logic cfg_write_violation;
  logic strb_write_violation;

  // WSR data write only valid in StMsgFeed
  assign wsr_write_violation = (ispr_kmac_data_s0_wr_i || ispr_kmac_data_s1_wr_i)
                               && (st_q != StMsgFeed);

  // Only COMMAND writes (START/PROCESS/RUN/DONE opcodes) are gated by state.
  // CFG writes (mode/strength) are harmless in any state.
  logic is_cfg_write;
  assign is_cfg_write = ispr_kmac_ctrl_wr_i &&
      !(ispr_kmac_ctrl_wdata_i[5:0] inside {6'h1D, 6'h2E, 6'h31, 6'h16});

  // CFG write is always allowed (sets up next session).
  // Command writes are only valid in specific states:
  //   StIdle: START only
  //   StMsgFeed: PROCESS only (including via msg_send)
  //   StSqueeze: RUN (SHAKE) or DONE
  assign cfg_write_violation = ispr_kmac_ctrl_wr_i && !is_cfg_write &&
      !((st_q == StIdle)   && (ispr_kmac_ctrl_wdata_i[5:0] == 6'h1D)) &&
      !((st_q == StMsgFeed) && (ispr_kmac_ctrl_wdata_i[5:0] == 6'h2E)) &&
      !((st_q == StSqueeze) && (ispr_kmac_ctrl_wdata_i[5:0] inside {6'h31, 6'h16}));

  // STRB write only valid in StMsgFeed
  assign strb_write_violation = ispr_kmac_byte_strobe_wr_i && (st_q != StMsgFeed);

  logic [7:0] msg_send_cnt;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) msg_send_cnt <= '0;
    else if (st_q == StIdle) msg_send_cnt <= '0;
    else if (ispr_kmac_msg_send_wr_i) msg_send_cnt <= msg_send_cnt + 1'b1;
  end

  // KMAC event trace
  always_ff @(posedge clk_i) begin
    if (st_q != st_d)
      $display("[KMAC] t=%0t st %0d->%0d  abs=%0d(rp=%0d)  pad=%0d/%0d  k_run=%0d  k_done=%0d  msgs=%0d  pcnt=%0d",
               $time, st_q, st_d, absorb_total, absorb_rate_pos,
               pad_cnt, pad_words_needed, keccak_run, keccak_done_q, msg_send_cnt,
               process_cnt_q);
    if (ispr_kmac_msg_send_wr_i)
      $display("[KMAC] t=%0t MSG_SEND received  msgs=%0d",
               $time, msg_send_cnt);
    if (keccak_feed_valid_mux)
      $display("[KMAC] t=%0t FEED  addr=%0d  data=0x%016x  src=%s",
               $time, keccak_feed_addr_mux, keccak_feed_data_mux,
               keccak_feed_valid ? "msg" : "pad");
    if (sqz_write_en && st_q == StSqueeze)
      $display("[KMAC] t=%0t SQUEEZE word[%0d]=0x%016x  rdy=%0d both=%0d adv=%0d dv=%0d",
               $time, sqz_eff_idx, sqz_word_64, sqz_rdy, both_shares_read,
               advance_word, digest_valid_s);
    if (keccak_run)
      $display("[KMAC] t=%0t KECCAK_RUN  st=%0d  pcnt=%0d  state_lane0=0x%016x",
               $time, st_q, process_cnt_q, keccak_state[0][63:0]);
    if (keccak_complete)
      $display("[KMAC] t=%0t KECCAK_DONE  st=%0d  pcnt=%0d  done_q=%0d  state_lane0=0x%016x",
               $time, st_q, process_cnt_q, keccak_done_q, keccak_state[0][63:0]);
    // // Track rand_valid during StProcessing to see if keccak_round is stuck
    // if (st_q == StProcessing && process_cnt_q > 0)
    //   $display("[KMAC] t=%0t PROC  pcnt=%0d  rand_v=%0d  done_q=%0d",
    //            $time, process_cnt_q, kmac_dom_rand_valid_i, keccak_done_q);
    // if (st_q == StSqueeze && st_d == StSqueeze && digest_valid_s == 0)
    //   $display("[KMAC] t=%0t ** DV=0 in SQUEEZE: both=%0d  sqz=%0d  s0_rd=%0d  s1_rd=%0d  sqz_rdy=%0d",
    //            $time, both_shares_read, sqz_word_idx, s0_read_q, s1_read_q, sqz_rdy);
    // // CSR 0x7D9 read tracking — show when if_status is sampled
    // if (st_q == StProcessing || st_q == StSqueeze)
    //   $display("[KMAC] t=%0t STATUS  st=%0d  st_d=%0d  dv=%0d  pcnt=%0d  done_q=%0d  idle=%0d absorb=%0d squeeze=%0d",
    //            $time, st_q, st_d, digest_valid_s, process_cnt_q, keccak_done_q,
    //            idle_s, absorb_s, squeeze_s);
  end


  // Pad counter
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                                    pad_cnt <= '0;
    else if (keccak_pad_skip)                        pad_cnt <= pad_words_needed - 1;
    else if (keccak_pad_valid)                       pad_cnt <= pad_cnt + 1'b1;
    else if (st_q != StPad)                          pad_cnt <= '0;
  end

  // Total absorbed words (across all WSRs, up to rate_words)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                           absorb_total <= '0;
    else if (st_q == StIdle)               absorb_total <= '0;
    else if (keccak_feed_valid)            absorb_total <= absorb_total + 1'b1;
  end

  // Position within current rate block (0..rate_words-1).  Wraps when the
  // keccak_round module internally triggers a permutation.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)                              absorb_rate_pos <= '0;
    else if (st_q == StIdle)                  absorb_rate_pos <= '0;
    else if (keccak_feed_valid) begin
      if (absorb_rate_pos == (rate_words - 1))
        absorb_rate_pos <= '0;  // keccak_round triggers internal permutation
      else
        absorb_rate_pos <= absorb_rate_pos + 1'b1;
    end
  end

  ////////////////////////////////////////////////////////////////////////////
  // Secure wipe error
  ////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////
  // Secure wipe error (kmac_state_err_o → controller)
  // This signal goes to the OTBN controller and can stall/halt the processor.
  // Only secure wipe errors trigger this path.
  // Sticky W1C errors (cmd_sequence, wsr_write) only feed kmac_intr + kmac_if_status.
  ////////////////////////////////////////////////////////////////////////////
  assign kmac_state_err_o = (sec_wipe_kmac_data_s0_i | sec_wipe_kmac_data_s1_i) &
                             ~sec_wipe_running_i;

  ////////////////////////////////////////////////////////////////////////////
  // Assertions
  ////////////////////////////////////////////////////////////////////////////
  `ASSERT_INIT(KeccakWidthValid_A, Width == 1600)

endmodule
