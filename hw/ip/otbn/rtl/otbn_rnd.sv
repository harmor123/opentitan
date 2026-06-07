// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

/**
 * OTBN random number coordination
 *
 * This module implements the RND, RND_PREFETCH and URND CSRs/WSRs. The EDN (entropy distribution
 * network) provides the bits for random numbers. RND gives direct access to EDN bits. URND provides
 * bits from a PRNG that is seeded with bits from the EDN.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////
// IMPORTANT NOTE:                                                                                //
//                                   DO NOT USE THIS BLINDLY!                                     //
//                                                                                                //
// This is an initial prototype of the random number functionality in OTBN. Details are still     //
// under discussion and subject to change. It has not yet been verified this provides the         //
// necessary guarantees required for the various uses of random numbers in OTBN software.         //
////////////////////////////////////////////////////////////////////////////////////////////////////

module otbn_rnd import otbn_pkg::*;
#(
  parameter urnd_prng_seed_t       RndCnstUrndPrngSeed      = RndCnstUrndPrngSeedDefault
) (
  input logic clk_i,
  input logic rst_ni,

  input  logic opn_start_i,
  input  logic opn_end_i,

  input  logic            rnd_req_i,
  input  logic            rnd_prefetch_req_i,
  output logic            rnd_valid_o,
  output logic [WLEN-1:0] rnd_data_o,
  output logic            rnd_rep_err_o,
  output logic            rnd_fips_err_o,

  // Request URND PRNG reseed from the EDN
  input  logic               urnd_reseed_req_i,
  // Acknowledge URND PRNG reseed from the EDN
  output logic               urnd_reseed_ack_o,
  // When asserted PRNG state advances. It is permissible to advance the state whilst
  // reseeding.
  input  logic               urnd_advance_i,
  // URND data from PRNG
  output logic [UrndLen-1:0] urnd_data_o,
  // URND lockup state detected
  output logic               urnd_all_zero_o,

  // Entropy distribution network (EDN)
  output logic                    edn_rnd_req_o,
  input  logic                    edn_rnd_ack_i,
  input  logic [EdnDataWidth-1:0] edn_rnd_data_i,
  input  logic                    edn_rnd_fips_i,
  input  logic                    edn_rnd_err_i,

  output edn_pkg::edn_req_t       edn_urnd_o,
  input  edn_pkg::edn_rsp_t       edn_urnd_i,

  // KMAC DOM masking — dedicated 800b Trivium (production SCA countermeasure)
  // Seed shared with URND Trivium (same EDN bus, same seed_en moment).
  // Advanced externally by otbn_kmac when keccak_round consumes randomness.
  output logic                        kmac_dom_rand_valid_o,
  output logic [KmacDomWidth-1:0]     kmac_dom_rand_data_o,
  output logic                        kmac_dom_rand_aux_o,
  input  logic                        kmac_dom_rand_advance_i
);

  logic rnd_valid_q, rnd_valid_d;
  logic [WLEN-1:0] rnd_data_q, rnd_data_d;
  logic rnd_fips_d, rnd_fips_q;
  logic rnd_err_d, rnd_err_q;
  logic rnd_data_en;
  logic rnd_req_complete;
  logic edn_rnd_req_complete;
  logic edn_rnd_req_start;

  logic edn_rnd_req_q, edn_rnd_req_d;

  logic rnd_req_queued_d, rnd_req_queued_q;
  logic edn_rnd_data_ignore_d, edn_rnd_data_ignore_q;

  logic urnd_reseed_req_q;
  logic urnd_reseed_ack_d, urnd_reseed_ack_q;
  logic seed_en_d, seed_en_q;

  logic [UrndLen-1:0] urnd_data_d, urnd_data_q;

  ////////////////////////
  // RND Implementation //
  ////////////////////////

  assign rnd_req_complete = rnd_req_i & rnd_valid_o;
  assign edn_rnd_req_complete = edn_rnd_req_o & edn_rnd_ack_i;

  assign rnd_data_en = edn_rnd_req_complete & ~edn_rnd_data_ignore_q;

  // RND becomes valid when EDN request completes and provides new bits. Valid is cleared when OTBN
  // starts a new run (opn_start_i) or when OTBN reads RND (rnd_req_complete).
  assign rnd_valid_d =
      opn_start_i || rnd_req_complete                ? 1'b0 :
      edn_rnd_req_complete && !edn_rnd_data_ignore_q ? 1'b1 : rnd_valid_q;
  assign rnd_data_d = edn_rnd_data_i;
  assign rnd_fips_d = edn_rnd_fips_i;
  assign rnd_err_d = edn_rnd_err_i;

  // Start an EDN request when there is a prefetch or an attempt at reading RND when RND data is
  // not available. Signalling `edn_rnd_req_start` whilst there is an outstanding request is
  // harmless. However, a prefetch may still be outstanding from the last OTBN run which may have
  // used a different configuration for EDN, CSRNG or the entropy source. At the start of a new
  // OTBN run, RND data is thus always invalidated and outstanding prefetches are marked such that
  // the RND data returned for the first prefetch is thrown away. When throwing away data, we need
  // to keep requesting RND data from EDN if another request got queued in the meantime.
  assign edn_rnd_req_start = (rnd_prefetch_req_i | rnd_req_i | rnd_req_queued_q) & ~rnd_valid_q;

  // When seeing a wipe with an outstanding request (which must have been a prefetch), we are going
  // to ignore the RND data that comes back from that request. Any RND data returned clears the
  // ignore status.
  assign edn_rnd_data_ignore_d =
      opn_start_i && edn_rnd_req_q ? 1'b1 :
      edn_rnd_req_complete         ? 1'b0 : edn_rnd_data_ignore_q;

  // rnd_req_queued_q shows that there's an outstanding RND prefetch whose result we are going to
  // ignore and also another request pending. Once the prefetch is done, we want to send out that
  // second request.
  //
  // The signal is set if we get a request (edn_rnd_req_start) when we're ignoring the current
  // prefetch (edn_rnd_data_ignore_q). It should be cleared when we actually start a request when
  // we're not ignoring a prefetch. It should also be cleared when finishing an operation. If that
  // happens, we were waiting to send a second prefetch and it turns out that no-one actually needed
  // the result.
  assign rnd_req_queued_d =
      opn_end_i             ? 1'b0              :
      edn_rnd_data_ignore_q ? edn_rnd_req_start :
      edn_rnd_req_start     ? 1'b0              : rnd_req_queued_q;

  // Assert `edn_rnd_req_o` when a request is started and keep it asserted until the request is
  // done.
  assign edn_rnd_req_d = (edn_rnd_req_q | edn_rnd_req_start) & ~edn_rnd_req_complete;

  assign edn_rnd_req_o = edn_rnd_req_q;

  always_ff @(posedge clk_i) begin
    if (rnd_data_en) begin
      rnd_data_q <= rnd_data_d;
      rnd_fips_q <= rnd_fips_d;
      rnd_err_q  <= rnd_err_d;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rnd_valid_q            <= 1'b0;
      rnd_req_queued_q       <= 1'b0;
      edn_rnd_req_q          <= 1'b0;
      edn_rnd_data_ignore_q  <= 1'b0;
    end else begin
      rnd_valid_q            <= rnd_valid_d;
      rnd_req_queued_q       <= rnd_req_queued_d;
      edn_rnd_req_q          <= edn_rnd_req_d;
      edn_rnd_data_ignore_q  <= edn_rnd_data_ignore_d;
    end
  end

  assign rnd_valid_o = rnd_valid_q;
  assign rnd_data_o  = rnd_data_q;

  // SEC_CM: RND.BUS.CONSISTENCY
  // SEC_CM: RND.RNG.DIGEST
  // Detect and forward RND error conditions.
  assign rnd_rep_err_o = rnd_req_complete & rnd_err_q;
  assign rnd_fips_err_o = rnd_req_complete & ~rnd_fips_q;

  /////////////////////////
  // PRNG Implementation //
  /////////////////////////

  prim_trivium #(
    .BiviumVariant(1'b1),
    .OutputWidth(UrndLen),
    .StrictLockupProtection(1'b1),
    .SeedType(prim_trivium_pkg::SeedTypeStatePartial),
    .PartialSeedWidth(edn_pkg::ENDPOINT_BUS_WIDTH),
    .RndCnstTriviumLfsrSeed(RndCnstUrndPrngSeed)
  ) u_prim_trivium (
    .clk_i,
    .rst_ni,
    .en_i                (urnd_advance_i),
    .allow_lockup_i      (1'b0),
    .seed_en_i           (seed_en_q),
    .seed_done_o         (urnd_reseed_ack_d),
    .seed_req_o          (edn_urnd_o.edn_req),
    .seed_ack_i          (edn_urnd_i.edn_ack),
    .seed_key_i          ('0), // Not connected
    .seed_iv_i           ('0), // Not connected
    .seed_state_full_i   ('0), // Not connected
    .seed_state_partial_i(edn_urnd_i.edn_bus),
    .key_o               (urnd_data_d),
    .err_o               (urnd_all_zero_o)
  );

  // Buffer Bivium's output to relax timing and to prevent glitching on the URND signals.
  always_ff @(posedge clk_i) begin : proc_bivium_output_buffer
    urnd_data_q <= urnd_data_d;
  end
  assign urnd_data_o = urnd_data_q;

  // Signal urnd_reseed_req_i is high even during reset. Ensure we do not start until
  // reset has been completed
  always_ff @(posedge clk_i or negedge rst_ni) begin : proc_gate_seed_en
    if (~rst_ni) begin
      urnd_reseed_req_q <= 1'b0;
      seed_en_q         <= 1'b0;
    end else begin
      urnd_reseed_req_q <= urnd_reseed_req_i;
      seed_en_q         <= seed_en_d;
    end
  end
  assign seed_en_d = !urnd_reseed_req_q & urnd_reseed_req_i;

  // The logic around the previous PRNG (xoshiro256pp) has acknowledged the reseeding
  // operation one cycle after fetching the seed data from EDN. This cut emulates
  // this behavior.
  always_ff @(posedge clk_i or negedge rst_ni) begin : proc_delay_reseed_ack
    if (~rst_ni) begin
      urnd_reseed_ack_q <= 1'b0;
    end else begin
      urnd_reseed_ack_q <= urnd_reseed_ack_d;
    end
  end
  assign urnd_reseed_ack_o = urnd_reseed_ack_q;

  // =====================================================================
  // KMAC DOM Masking — Dedicated 800b Trivium (Plan B2)
  // =====================================================================
  // Separate PRNG instance for keccak-f χ-step DOM masking.
  // Shares the EDN seed with the URND Trivium (same seed_en_q moment,
  // same edn_urnd_i.edn_bus data).  Does NOT initiate independent EDN
  // requests — seeding is gated by the existing URND seed FSM.
  //
  // Output: 800 bits/cycle fresh randomness for keccak_round.rand_data_i.
  // Advanced by otbn_kmac via kmac_dom_rand_advance_i when keccak_round
  // signals rand_update_o or rand_consumed_o.

  logic [KmacDomWidth-1:0] kmac_dom_prng_data;
  logic [KmacDomWidth-1:0] kmac_dom_prng_permuted;

  // Independent self-seed for KMAC DOM Trivium — avoids deadlock with
  // main URND Trivium (which waits for urnd_advance before seed_done).
  logic [2:0] kmac_dom_seed_cnt;
  logic       kmac_dom_seed_en;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_dom_seed_cnt <= '0;
      kmac_dom_seed_en  <= 1'b0;
    end else if (kmac_dom_seed_cnt < 3'd4) begin
      kmac_dom_seed_cnt <= kmac_dom_seed_cnt + 1'b1;
      kmac_dom_seed_en  <= (kmac_dom_seed_cnt == 3'd2);
    end else begin
      kmac_dom_seed_en <= 1'b0;
    end
  end

  logic kmac_dom_seed_done;
  prim_trivium #(
    .BiviumVariant         (1'b1),
    .OutputWidth           (KmacDomWidth),
    .StrictLockupProtection(1'b1),
    .SeedType              (prim_trivium_pkg::SeedTypeStatePartial),
    .PartialSeedWidth      (edn_pkg::ENDPOINT_BUS_WIDTH)
  ) u_kmac_dom_trivium (
    .clk_i,
    .rst_ni,
    .en_i                (kmac_dom_rand_advance_i),
    .allow_lockup_i      (1'b0),
    .seed_en_i           (seed_en_q || kmac_dom_seed_en),
    .seed_done_o         (kmac_dom_seed_done),
    .seed_req_o          (),
    .seed_ack_i          (1'b1),
    .seed_key_i          ('0),
    .seed_iv_i           ('0),
    .seed_state_full_i   ('0),
    .seed_state_partial_i(edn_urnd_i.edn_bus),
    .key_o               (kmac_dom_prng_data),
    .err_o               ()
  );

  // LFSR permutation — identical to kmac_pkg.sv RndCnstLfsrPermDefault
  // Generated with: util/design/gen-lfsr-seed.py --width 800 --seed 3369807298
  // Pure combinational — 800 wires, 0 gates.
  localparam logic [KmacDomWidth-1:0][$clog2(KmacDomWidth)-1:0] KmacDomLfsrPerm = {
      64'hb1a3e87aeb4e69f0,
      256'h2d8a6ee2c9ac567b2aa401a639a2a8ea2553614c0a8daf672c06546fc0d35267,
      256'hc4572024bc116458dd0f1c10a8aef5c4ad9a788968d0d7ca7345c6b8f277a5d3,
      256'hec5da20f261826ed3c8992724e70db897060be51b07a96902e14a42d12d320f8,
      256'h187049b6c25f35d0e485cc4b9ef01dad2865b5e558926f380718b74394fe0f82,
      256'hd5395a7d0aa4845af814e8681107a4c793758572c9467493bf1248a48f1b40c2,
      256'h09319b55111d0401819685a43a06f0da441021a8c220b14f01d44e49c1683a82,
      256'hafeb980964aa050641f4205131d9d4741eb5dd658e603b8ed438cb1096628d42,
      256'h62c9d75ced78ed09a3ddbb60f533eef10aa5a54b478d61a06a4b326eb3402105,
      256'hc27d562c6d91b48440d6d06e543be9871628a4aa9b3d2e51fa0ac2eb89a17f6d,
      256'h207ad96caf25d1fcffab210c1aff12252346fe4d56a7cd9b8605c7fa638895a9,
      256'h60158cd3a1ce4f2f6cf5d48579ac14b1e5219ca8914e0507b635dc712554f6bb,
      256'h0ae412943a7596f4644a0c13646adc91d02c406a10d232791d3de9919eec5424,
      256'haa2cac5f556c15c647eb29365062daf6aa848e10b3f665abccca713036d9f1cb,
      256'h1c9bd4aaeb19c5ac01b1805e0d5479860870da49a55e8f386ca8232c728e2f61,
      256'h3007aa420758818e5312401372eaa00d21c70c7e1158d2e08a1b6ac0b820cb67,
      256'hf0ba4b5c0865ff04f0f9d0175817c65d81918e43e14b2f83d574bfa9c6e6deae,
      256'h64c22c2974a1d5c55e2367004b249d5a02fc566685ea33b6f73aaa0244b34412,
      256'hb1a12230adb1748dc1d956f9f10c8e1aa52f4702e06a16680d92226c830ec4ce,
      256'h4c2eead21f08c387c3f1de89eb33b983c748e848f68b54f256715221177c5a4a,
      256'h0a47d82741955626755ba1cc24e2ba40504111b9e26136be714c5bc0d330c3f7,
      256'h75e863de763270a993890d633c6897218e151943edd8b79ae145cf564b774613,
      256'h0b0a76c40e7e84c876640dc78260c09a85e92e5ab56c22c0e72a8669fe88ba10,
      256'h8b99e437c776f0cea0d144f285b6ab7259e12284f380ae3410171cd6a8b04415,
      256'he95081c8c57e3e526ad5b38019a5c1b5505540462157e7c7e68e6a6a16ac460a,
      256'h5d5578da28092c7cc927cb9c0ed614a79b0e32b4c5b6a269a40743bef42b5e29,
      256'hd9a75ecb5548a29e9d34ddda07c8404aabbf5479456731ece3785f6090c3f862,
      256'h6eb1a5119e8b8e56b1455d820b46e20e15bb7d185a636b10ab8565732c59a302,
      256'h329925186604edbd5029a9f865268e90003b5b69d3e99240c3432291a60c62a4,
      256'hebad1ed028cd021b27260db22089e0c44481b1a4c120134ac63dc52fbc4cafb2,
      256'he065add2665fb361665267b53024329d96587d661f724171155ee73a3f0c47a8,
      256'h149751a5903c8bbcaf1782e415dfda531eb2af67c25e190330a12000e1fbb9cd
  };

  for (genvar i = 0; i < KmacDomWidth; i++) begin : gen_kmac_dom_perm
    assign kmac_dom_prng_permuted[i] =
        kmac_dom_prng_data[KmacDomLfsrPerm[i]];
  end

  // Buffer register — prevents glitches from the unrolled Trivium
  // combinatorial cloud from propagating into keccak_round's DOM multipliers.
  logic [KmacDomWidth-1:0] kmac_dom_rand_data_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_dom_rand_data_q <= '0;
    end else if (kmac_dom_rand_advance_i) begin
      kmac_dom_rand_data_q <= kmac_dom_prng_permuted;
    end
  end

  // Outputs
  // Valid after KMAC DOM Trivium completes its own seeding
  logic kmac_dom_rand_valid_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) kmac_dom_rand_valid_q <= 1'b0;
    else if (kmac_dom_seed_done) kmac_dom_rand_valid_q <= 1'b1;
  end
  assign kmac_dom_rand_valid_o = kmac_dom_rand_valid_q;
  assign kmac_dom_rand_data_o  = kmac_dom_rand_data_q;
  assign kmac_dom_rand_aux_o   = kmac_dom_rand_data_q[KmacDomWidth-1];

  // Unused signals
  logic unused_trivium;
  assign unused_trivium = ^edn_urnd_i.edn_fips;

  `ASSERT(RndClearOnReqComplete_A, rnd_req_complete |=> ~rnd_valid_q)
  `ASSERT(UrndNoReseedOnReset_A, ~rst_ni === ~seed_en_q, clk_i, rst_ni)
endmodule
