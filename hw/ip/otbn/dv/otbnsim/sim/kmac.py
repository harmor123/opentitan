# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any, Optional
from enum import Enum, auto, unique
from Crypto.Hash import SHAKE128, SHAKE256, SHA3_224, SHA3_256, SHA3_384, SHA3_512
import secrets
from .csr import CSRFile
from .wsr import WSRFile

# Timing constants (masked defaults; instance attributes override when en_sca_masking=False)
KECCAK_ROUNDS = 24
KECCAK_ROUND_CYCLES = 4  # per RTL CyclesPerRound when EnMasking=1
KECCAK_PROCESS_CYCLES = KECCAK_ROUNDS * KECCAK_ROUND_CYCLES  # 96
KECCAK_ABSORB_CYCLES = 25

# Data sizes
KMAC_WORD_BITS = 64
KMAC_WORD_BYTES = 8
KMAC_WSR_BITS = 256
KMAC_WSR_BYTES = KMAC_WSR_BITS // 8
KMAC_WSR_WORDS = KMAC_WSR_BITS // KMAC_WORD_BITS

# Error codes
KMAC_ERR_UNEXPECTED_MODE_STRENGTH = 0x6
KMAC_ERR_SW_CMD_SEQUENCE = 0x8


@unique
class KmacMode(Enum):
    """KMAC modes."""
    SHA3 = 0x0
    SHAKE = 0x2
    CSHAKE = 0x3
    INVALID = -1  # Internal use only for unknown values

    @classmethod
    def _missing_(cls, value: object) -> "KmacMode":
        """Map any unknown integer value to INVALID."""
        return cls.INVALID


@unique
class KmacStrength(Enum):
    """Kmac strengths."""
    L128 = 0x0
    L224 = 0x1
    L256 = 0x2
    L384 = 0x3
    L512 = 0x4
    INVALID = -1  # Internal use only for unknown values

    @classmethod
    def _missing_(cls, value: object) -> "KmacStrength":
        """Map any unknown integer value to INVALID."""
        return cls.INVALID


# Create a tuple key using the Enums
MODE_STRENGTH_TABLE = {
    # (Mode, Strength): (Implementation Class, Bit Width)
    (KmacMode.SHA3, KmacStrength.L224): (SHA3_224, 224),
    (KmacMode.SHA3, KmacStrength.L256): (SHA3_256, 256),
    (KmacMode.SHA3, KmacStrength.L384): (SHA3_384, 384),
    (KmacMode.SHA3, KmacStrength.L512): (SHA3_512, 512),
    (KmacMode.SHAKE, KmacStrength.L128): (SHAKE128, 128),
    (KmacMode.SHAKE, KmacStrength.L256): (SHAKE256, 256),
    # cSHAKE usually shares the SHAKE implementations but with customization strings
    (KmacMode.CSHAKE, KmacStrength.L128): (SHAKE128, 128),
    (KmacMode.CSHAKE, KmacStrength.L256): (SHAKE256, 256),
}


@unique
class KmacCmd(Enum):
    """Kmac commands."""
    NONE = 0x00
    START = 0x1d
    PROCESS = 0x2e
    RUN = 0x31
    DONE = 0x16
    INVALID = -1  # Internal use only for unknown values

    @classmethod
    def _missing_(cls, value: object) -> "KmacCmd":
        """Map any unknown integer value to INVALID."""
        return cls.INVALID


class KmacState(Enum):
    IDLE = auto()
    MSG_FEED = auto()
    PROCESSING = auto()
    ABSORBED = auto()
    SQUEEZING = auto()


class Counter():
    """A hardware-like counter model with separate Next (D) and Current (Q) states.

    This prevents updates within a cycle from taking effect until end_cycle() is called.
    This class also asserts that the counter value always stays between 0 and the max value.
    """

    def __init__(self, max_val: Optional[int] = None) -> None:
        # Assign the counter boundaries
        self._max_val = max_val
        # Initialize counter values
        self.reset()

    def _check_bounds(self, val: int) -> None:
        # Only check max if it is not None
        if self._max_val is not None:
            assert val <= self._max_val
        assert val >= 0

    def reset(self) -> None:
        # Initialize state to the minimum value
        self._next_val = 0
        self._curr_val = 0

    @property
    def value(self) -> int:
        """Returns the current counter value."""
        return self._curr_val

    def set_next(self, val: int) -> None:
        """Sets the next value directly."""
        self._check_bounds(val)
        self._next_val = val

    def increment(self, step: int = 1) -> int:
        """Calculates D = Q + step."""
        self._next_val = self._curr_val + step
        return self._next_val

    def decrement(self, step: int = 1) -> int:
        """Calculates D = Q - step."""
        self._next_val = self._curr_val - step
        return self._next_val

    def end_cycle(self) -> None:
        """Commits the next value to the current state."""
        # Verify the transition is legal before updating state
        self._check_bounds(self._next_val)
        self._curr_val = self._next_val


@dataclass
class Kmac():
    '''A model of the KMAC HW IP.
    '''
    # Declare the variable types.
    _csrs: CSRFile
    _wsrs: WSRFile
    _state: KmacState
    _state_next: KmacState
    _kmac_msg_send_words_left: Counter
    _keccak_round_ctr: Counter
    _keccak_absorbed_cnt: Counter
    _keccak_squeezed_cnt: Counter
    _sha3_digest: bytes
    _keccak_state: Any
    _keccak_rate_words: int
    _keccak_cap_bits: int
    _flush_cycle: bool
    _err_sw_cmd_seq: bool
    _err_sw_mode_strength: bool
    _en_sca_masking: bool = True  # URND masking for squeeze (False = zero mask for DV)
    _absorbed_msg_bytes: bytearray = bytearray()  # buffer of absorbed msg bytes for SHAKE RUN
    _skip_absorb_decrement: bool = False  # skip decrement after PROCESS set_next

    def __init__(self, csrs: CSRFile, wsrs: WSRFile, en_sca_masking: bool = True) -> None:
        self._en_sca_masking = en_sca_masking
        self._keccak_round_cycles = 4 if en_sca_masking else 1
        self._keccak_process_cycles = KECCAK_ROUNDS * self._keccak_round_cycles  # 96 or 24
        self._keccak_absorb_cycles = self._keccak_process_cycles + 1  # 97 or 25
        self.on_start(csrs, wsrs)
        self._reset_state()

    def on_start(self, csrs: CSRFile, wsrs: WSRFile) -> None:
        self._csrs = csrs
        self._wsrs = wsrs

    def step(self) -> None:
        """Advance the KMAC state by one cycle."""

        # Check if KMAC_DATA_S0/1 were accessed in the last cycle.
        self._step_kmac_data()

        # Squeeze BEFORE FSM step: RUN detection in _step_fsm clears
        # DIGEST_VALID, and _squeeze runs first so it doesn't re-set it.
        if self._csrs.KMAC_STATUS.is_squeezing():
            self._squeeze()

        # Advance the KMAC FSM.
        self._step_fsm()

        # Update KMAC error status based on FSM-detected conditions
        self._update_kmac_error()

        # Decrement Keccak counter if Keccak is running,
        # unless a set_next just happened (skip one decrement).
        if self._keccak_round_ctr.value and not self._skip_absorb_decrement:
            self._keccak_round_ctr.decrement()
        self._skip_absorb_decrement = False

        # csrrs reads CSR before _step_fsm updates it — 1-cycle skew.
        # Pre-set SQUEEZE when counter is about to hit 0 so Phase 2 sees it.
        if (self._state == KmacState.SQUEEZING and
                not self._keccak_round_ctr._next_val):
            self._csrs.KMAC_STATUS.set_squeeze()

        # Decrement absorption delay counter (simulates RTL's 4-cycle WSR feed).
        if self._kmac_msg_send_words_left.value:
            self._kmac_msg_send_words_left.decrement()

        # MSG write ready: always 1 in MSG_FEED.
        kmac_msg_send = self._csrs.KMAC_MSG_SEND.read_unsigned()
        if kmac_msg_send and self._csrs.KMAC_MSG_SEND._pending_write:
            kmac_msg_send = 0
        self._csrs.KMAC_IF_STATUS.update_msg_write_rdy(
            self._state == KmacState.MSG_FEED and not kmac_msg_send
            and not self._kmac_msg_send_words_left.value
            and not self._keccak_round_ctr.value)

        return

    def end_cycle(self) -> None:
        # Commit state transition
        self._state = self._state_next
        self._keccak_round_ctr.end_cycle()
        self._keccak_absorbed_cnt.end_cycle()
        self._keccak_squeezed_cnt.end_cycle()
        self._kmac_msg_send_words_left.end_cycle()

        # Detect new msg_send after CSR commit (same-cycle as RTL).
        kmac_msg_send = self._csrs.KMAC_MSG_SEND.read_unsigned()
        if kmac_msg_send:
            if self._state == KmacState.MSG_FEED:
                byte_strobe = self._csrs.KMAC_BYTE_STROBE.read_unsigned()
                words = KMAC_WSR_WORDS
                if byte_strobe != 0 and byte_strobe != 0xFFFFFFFF:
                    words = 0
                    for w in range(KMAC_WSR_WORDS):
                        if (byte_strobe >> (w * 8)) & 0xFF:
                            words += 1
                    if words == 0:
                        words = KMAC_WSR_WORDS
                # Absorb immediately (Python SHA3 handles multi-rate correctly).
                # Commit absorb_cnt after each word so rate-full detection
                # accumulates correctly (Counter.increment uses _curr_val
                # which only updates at end_cycle).
                ctr_before = self._keccak_round_ctr.value
                for i in range(words):
                    self._absorb(i)
                    self._keccak_absorbed_cnt.end_cycle()
                # If rate filled, extend keccak counter for RTL serial absorption.
                ctr_after = self._keccak_round_ctr.value
                if ctr_after > ctr_before and words > 1:
                    self._keccak_round_ctr.set_next(ctr_after + words - 1)
                    self._keccak_round_ctr.end_cycle()
                # Signal absorption delay: RTL feeds 1 word/cycle.
                self._kmac_msg_send_words_left.set_next(words)
                self._kmac_msg_send_words_left.end_cycle()
            else:
                self._csrs.KMAC_IF_STATUS.set_msg_send_error()

    def _step_kmac_data(self) -> None:
        # WSR write error detection only (msg_send triggers absorption per YAML)
        if (self._wsrs.KMAC_DATA.shares_dirty() and
                not self._csrs.KMAC_IF_STATUS.get_msg_write_rdy()):
            self._csrs.KMAC_IF_STATUS.set_msg_write_error()

        # Reset dirty bits each cycle
        self._wsrs.KMAC_DATA.clean_shares()

        # Invalidate digest data if both shares were read
        if self._wsrs.KMAC_DATA.all_shares_read():
            self._csrs.KMAC_IF_STATUS.clr_digest_valid()
            self._wsrs.KMAC_DATA.mark_all_unread()

    def _check_cmd(self, command: Optional[KmacCmd], allowed: set[KmacCmd]) -> None:
        if command not in allowed:
            self._csrs.KMAC_INTR.set_error()
            self._err_sw_cmd_seq = True

    def _step_fsm(self) -> None:
        self._state_next = self._state
        # Flush cycle is only True one cycle after the done command.
        self._flush_cycle_next = False
        # Set command/config error checker signals to false by default.
        # err_sw_cmd_seq might be set to True in _check_cmd().
        self._err_sw_cmd_seq = False
        # err_sw_mode_strength might be set to True in _start().
        self._err_sw_mode_strength = False
        # Get the next command.
        command = KmacCmd(self._csrs.KMAC_CMD.read_unsigned())
        # Get cfg mode.
        mode = KmacMode(self._csrs.KMAC_CFG.get_mode())

        # This state machine simulates the FSM inside kmac_errchk.sv.
        match self._state:
            case KmacState.IDLE:
                self._check_cmd(command, {KmacCmd.NONE, KmacCmd.START})

                if not self._flush_cycle:
                    self._csrs.KMAC_STATUS.set_idle()
                    if command == KmacCmd.START:
                        self._state_next = self._start()

            case KmacState.MSG_FEED:
                self._check_cmd(command, {KmacCmd.NONE, KmacCmd.PROCESS})
                self._csrs.KMAC_STATUS.set_absorb()
                if command == KmacCmd.PROCESS:
                    # rem = ongoing keccak + pad cycles for current rate block.
                    # _calc_pad_cycles replaces the hardcoded rem=17 hack.
                    rem = self._keccak_round_ctr.value + self._calc_pad_cycles(mode)
                    self._keccak_round_ctr.set_next(self._keccak_process_cycles + rem + 1)
                    self._state_next = KmacState.PROCESSING
                    self._skip_absorb_decrement = True

            case KmacState.PROCESSING:
                self._check_cmd(command, {KmacCmd.NONE})
                if not self._keccak_round_ctr.value and not self._kmac_msg_send_words_left.value:
                    self._state_next = KmacState.ABSORBED
                    self._csrs.KMAC_STATUS.set_squeeze()

            case KmacState.ABSORBED:
                self._check_cmd(command, {KmacCmd.NONE, KmacCmd.RUN, KmacCmd.DONE})
                self._csrs.KMAC_STATUS.set_squeeze()

                if command == KmacCmd.RUN and mode != KmacMode.SHA3:
                    self._state_next = KmacState.SQUEEZING
                    # Immediately reflect ABSORB status — csrrs reads CSR
                    # before _step_fsm updates it in the next cycle.
                    self._csrs.KMAC_STATUS.set_absorb()
                    # Clear stale DIGEST_VALID from old auto-advance word
                    self._csrs.KMAC_IF_STATUS.clr_digest_valid()
                    # +1: keccak_done_q register delay in RTL StProcessing
                    self._keccak_round_ctr.set_next(self._keccak_process_cycles + 1)
                    # Discard remaining bytes in current block to force keccak-f.
                    # Only needed when position is not at a block boundary.
                    pos_bytes = self._keccak_squeezed_cnt.value // 8
                    rate_bytes = self._keccak_rate_words * KMAC_WORD_BYTES
                    pos_in_block = pos_bytes % rate_bytes
                    if pos_in_block != 0:
                        self._keccak_state.read(rate_bytes - pos_in_block)
                    self._keccak_squeezed_cnt.set_next(0)
                elif command == KmacCmd.DONE:
                    self._state_next = KmacState.IDLE
                    self._flush_cycle_next = True
                    self._done()

            case KmacState.SQUEEZING:
                self._check_cmd(command, {KmacCmd.NONE})
                self._csrs.KMAC_STATUS.set_absorb()

                if not self._keccak_round_ctr.value:
                    self._state_next = KmacState.ABSORBED
                    self._keccak_squeezed_cnt.set_next(0)
        return

    def _calc_pad_cycles(self, mode: KmacMode) -> int:
        """Calculate pad cycles for the current rate block.

        RTL optimization: only first (0x06/0x1F) and last (0x80) pad words
        are non-zero; intermediate zero words are skipped via pad_cnt jump.
        """
        pos = self._keccak_absorbed_cnt.value
        msg_len = len(self._absorbed_msg_bytes)

        if msg_len == 0 and mode == KmacMode.SHA3:
            pad_words = self._keccak_rate_words
        elif msg_len == 0 and mode != KmacMode.SHA3:
            # FIPS 202: SHAKE empty also requires pad10*1 filling the entire rate block
            # (domain suffix 1111 → 0x1F instead of 01 → 0x06)
            pad_words = self._keccak_rate_words
        elif pos == 0:
            pad_words = self._keccak_rate_words
        else:
            pad_words = self._keccak_rate_words - pos
            # Partial last word: first pad word overlaps same lane
            if (msg_len % 8) != 0:
                pad_words += 1

        # Skip intermediate zero words: first feed + jump + last feed = 3 cycles
        if pad_words > 2:
            return 3
        return pad_words

    def _start(self) -> KmacState:
        # Get cfg mode and kStrength.
        mode = KmacMode(self._csrs.KMAC_CFG.get_mode())
        strength = KmacStrength(self._csrs.KMAC_CFG.get_kstrength())

        # Validate supported mode/strength combos
        entry = MODE_STRENGTH_TABLE.get((mode, strength))

        if entry is None:
            self._csrs.KMAC_INTR.set_error()
            self._err_sw_mode_strength = True
            return KmacState.IDLE

        # Instantiate state object
        constructor, cap_bits = entry
        self._keccak_state = constructor.new()
        self._keccak_rate_words = (1600 - 2 * cap_bits) // KMAC_WORD_BITS
        self._keccak_cap_bits = cap_bits
        self._absorbed_msg_bytes = bytearray()
        # Reset all counters for new operation
        self._keccak_round_ctr.reset()
        self._keccak_absorbed_cnt.reset()
        self._keccak_squeezed_cnt.reset()

        return KmacState.MSG_FEED

    def _absorb(self, index: int) -> None:
        """Absorb one 64-bit word into the Keccak state.
        """
        if not (0 <= index < 4):
            raise ValueError(f"Word index {index} out of range [0..3].")

        # Select word: index 0 = least-significant 64 bits.
        shift = index * KMAC_WORD_BITS
        word_mask = (1 << KMAC_WORD_BITS) - 1

        # Determine how many bytes are valid for this word from BYTE_STROBE.
        num_bytes = self._get_num_bytes_from_byte_strobe(index)

        # Unmask the data shares and extract this word.
        share0 = self._wsrs.KMAC_DATA.get_unsigned(0)
        share1 = self._wsrs.KMAC_DATA.get_unsigned(1)
        data_unmasked = share0 ^ share1
        data_word = (data_unmasked >> shift) & word_mask

        # Convert to bytes (little-endian) and absorb.
        data_bytes = data_word.to_bytes(num_bytes, byteorder="little")
        self._keccak_state.update(data_bytes)
        self._absorbed_msg_bytes.extend(data_bytes)

        # Track absorbed words.  When rate is full, start keccak counter.
        # The counter blocks decrement in step() (_skip_absorb_decrement)
        # so the value set here is preserved for one cycle.
        # Auto-trigger only when the word at the last rate position has
        # all 8 bytes valid.  A partial word (num_bytes < 8) at the block
        # boundary means the rate block is not truly full — padding fills
        # the gap without an extra keccak permutation.
        if self._keccak_absorbed_cnt.increment() >= self._keccak_rate_words:
            if num_bytes == KMAC_WORD_BYTES:
                self._keccak_round_ctr.set_next(self._keccak_absorb_cycles)
                self._keccak_round_ctr.end_cycle()  # commit immediately
                self._keccak_absorbed_cnt.set_next(0)
                self._skip_absorb_decrement = True
            # else: partial word at last position; leave absorbed_cnt
            # at rate_words so _calc_pad_cycles detects the partial fill

    def _squeeze(self) -> None:
        """Squeeze one 64-bit word of digest into KMAC_DATA[63:0] per YAML wsr.yml.

        YAML spec: digest data provided in chunks of 64 bits at a time.
        bits[63:0]   = current 64-bit digest word
        bits[255:64] = 0 (software reads zero from upper bits)
        Hardware auto-advances when both shares have been read.
        """

        # Only squeeze in ABSORBED (not during keccak processing in SQUEEZING).
        if self._state != KmacState.ABSORBED:
            return

        # Stop if Keccak is still processing.
        if self._keccak_round_ctr.value:
            return

        # Stop if KMAC_DATA is already valid.
        if self._csrs.KMAC_IF_STATUS.get_digest_valid():
            return

        mode = KmacMode(self._csrs.KMAC_CFG.get_mode())
        if mode == KmacMode.SHA3:
            # Stop if we've already squeezed the full digest.
            if self._keccak_squeezed_cnt.value >= self._keccak_cap_bits:
                return

            # Initialize digest buffer on first squeeze.
            if not self._keccak_squeezed_cnt.value:
                digest = self._keccak_state.digest()
                self._sha3_digest = digest

            # Pop next 64-bit word from digest buffer.
            chunk = self._sha3_digest[:KMAC_WORD_BYTES]
            self._sha3_digest = self._sha3_digest[KMAC_WORD_BYTES:]

        else:
            # (CSHAKE/)SHAKE: unlimited output.
            # Stop if the software needs to issue RUN for more data.
            if self._keccak_squeezed_cnt.value >= self._keccak_rate_words * KMAC_WORD_BITS:
                return

            chunk = self._keccak_state.read(KMAC_WORD_BYTES)

        # Write one 64-bit word into KMAC_DATA[63:0] only (bits[255:64] = 0).
        value = int.from_bytes(chunk, byteorder="little")
        self._write_digest(value)

        # Advance squeezed bit counter by one 64-bit word.
        self._keccak_squeezed_cnt.increment(step=KMAC_WORD_BITS)

    def _done(self) -> None:
        """Handle DONE command — transition to IDLE without resetting registers.

        RTL behaviour: FSM StSqueeze→StIdle immediately on DONE.
        kmac_status transitions from squeeze(0x04) to idle(0x01) on the
        next clock edge. The RTL does NOT clear cfg/mode/keccak state.
        """
        self._state = KmacState.IDLE
        self._keccak_squeezed_cnt.set_next(0)
        self._csrs.KMAC_STATUS.set_idle()
        self._csrs.KMAC_IF_STATUS.clr_digest_valid()

    def _get_num_bytes_from_byte_strobe(self, index: int) -> int:
        """Extracts the strobe bits corresponding to a specific word index
        and calculates the number of bytes that need to be absorbed.

        The BYTE_STROBE CSR must contain a value with contiguous ones starting
        from the LSB (e.g., 00111 is valid, 00101 is invalid).
        If the strobe is non-contiguous, the HW treats it as 0 (no bytes valid).
        Returns 8 (full 64-bit word) when no strobe is configured (default=0).
        """
        byte_strobe = self._csrs.KMAC_BYTE_STROBE.read_unsigned()

        # Default: no strobe set → full 8 bytes per word
        if byte_strobe == 0:
            return 8

        # Check validity: Must be contiguous ones starting at LSB (2^k - 1).
        if (byte_strobe & (byte_strobe + 1)) != 0:
            return 0

        # Calculate shift/mask to extract bits for this specific word.
        shift = index * KMAC_WORD_BYTES
        strobe_mask = (1 << KMAC_WORD_BYTES) - 1

        # Extract the slice and return the number of bytes.
        word_strobe_slice = (byte_strobe >> shift) & strobe_mask
        num_bytes = word_strobe_slice.bit_count()
        return num_bytes

    def _update_kmac_error(self) -> None:
        """Update KMAC error code based on detected software error conditions."""
        code = None
        if self._err_sw_cmd_seq:
            code = KMAC_ERR_SW_CMD_SEQUENCE
        elif self._err_sw_mode_strength:
            code = KMAC_ERR_UNEXPECTED_MODE_STRENGTH

        if code is not None:
            self._csrs.KMAC_ERROR.write_error(code)

    def _write_digest(self, data: int) -> None:
        """Write one 64-bit digest word into KMAC_DATA shares (bits[63:0] only).

        YAML wsr.yml: digest data in bits[63:0]; bits[255:64] = 0 for reads.
        Uses ISS URND for 2-share masking (same seed as RTL → masks match).
        """
        if not (0 <= data < (1 << KMAC_WORD_BITS)):
            raise RuntimeError(f"Data value {hex(data)} doesn't fit in "
                               f"{KMAC_WORD_BITS} unsigned bits.")

        if self._en_sca_masking:
            # Use ISS URND PRNG current-cycle value (matches RTL continuous wire)
            urnd_val = self._wsrs.URND.read_current_cycle()
            rand64 = urnd_val & ((1 << KMAC_WORD_BITS) - 1)
            share0 = data ^ rand64
            share1 = rand64
        else:
            share0 = data
            share1 = 0

        # Set the two shares (only low 64 bits carry digest data).
        self._wsrs.KMAC_DATA.set_unsigned(share_idx=0, value=share0)
        self._wsrs.KMAC_DATA.set_unsigned(share_idx=1, value=share1)

        # Mark the data as valid.
        self._csrs.KMAC_IF_STATUS.set_digest_valid()

        # Reset read flags since new data has been written.
        self._data_share_read = [False, False]

    def _reset_state(self) -> None:
        """Initialize or reset internal state to defaults."""
        #############################
        # KMAC/OTBN REGISTER VALUES #
        #############################

        # KMAC_STATUS CSR
        self._csrs.KMAC_STATUS.on_start()

        # KMAC_IF_STATUS CSR
        self._csrs.KMAC_IF_STATUS.on_start()

        # KMAC_INTR CSR
        self._csrs.KMAC_INTR.on_start()

        # KMAC_ERROR CSR
        self._csrs.KMAC_ERROR.on_start()

        # Writable KMAC CFG CSR
        self._csrs.KMAC_CFG.on_start()

        # BYTE_STROBE CSR
        self._csrs.KMAC_BYTE_STROBE.on_start()

        # KMAC_DATA WSRs
        self._wsrs.KMAC_DATA.set_unsigned(share_idx=0, value=0)
        self._wsrs.KMAC_DATA.set_unsigned(share_idx=1, value=0)

        #############################
        # KMAC MODEL CONTROL VALUES #
        #############################
        # Kmac FSM state variables
        self._state = KmacState.IDLE
        self._state_next = KmacState.IDLE
        # Number of words Keccak has left to absorb per kmac_msg_send command.
        self._kmac_msg_send_words_left = Counter(max_val=KMAC_WSR_WORDS)
        # Keccak round counter to keep track how long until the Keccak round is over.
        # A Keccak round takes KECCAK_ROUND_CYCLES cycles.
        self._keccak_round_ctr = Counter(max_val=self._keccak_process_cycles + self._keccak_absorb_cycles + 64)
        # Count of absorbed words, used to determine when Keccak should start processing.
        self._keccak_absorbed_cnt = Counter()
        # Count of squeezed words, used to determine how much data is left to squeeze.
        self._keccak_squeezed_cnt = Counter()
        # In SHA3 mode, Crypto.Hash returns the whole digest at once.
        # This variable stores the whole digest.
        self._sha3_digest = bytes()
        # Instance of a Keccak-based hash (SHA3, SHAKE, or cSHAKE) from the crypto.hash library.
        self._keccak_state = None
        # Rate of the Keccak sponge in 64 bit words.
        self._keccak_rate_words = 0
        # Capacity of the Keccak sponge in bits.
        self._keccak_cap_bits = 0
        # When the FSM returns to IDLE the SHA3 is still in the FLUSH state for 1 cycle.
        self._flush_cycle = False
        # Error signals
        self._err_sw_cmd_seq = False
        self._err_sw_mode_strength = False
        # Track whether each data share has been read since the last write.
        self._data_share_read = [False, False]
        # Buffer of absorbed message bytes (used to recreate SHAKE sponge on RUN).
        self._absorbed_msg_bytes = bytearray()
