# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from typing import Dict, Iterator, Optional
import sys
import os

from .constants import ErrBits
from .flags import FlagReg
from .isa import (OTBNInsn, RV32RegReg, RV32RegImm,
                  RV32ImmShift, insn_for_mnemonic, logical_byte_shift,
                  bit_shift,
                  extract_quarter_word, extract_sub_word)
from .state import OTBNState
from .wsr import _HAS_ACCH

DEBUG_MEM = False
DEBUG_BRANCH = False
DEBUG_ARITH = False
DEBUG_KMAC = False
DEBUG_FLOW = False

STACK_BENCH = False
STACK_SIZE = 20000

# For stack benchmarking, STACK_BENCH, STACK_SIZE and REPO_TOP is passed from --action_env.
if os.environ.get('STACK_BENCH', '0') == '1':
    STACK_BENCH = True
STACK_SIZE = int(os.environ.get('STACK_SIZE', '20000'))
REPO_TOP = os.environ.get('REPO_TOP', '/home/dev/src')

def eprint(text):
    print(text, file=sys.stderr)


def cmod(n, q):
    t = n % q
    # if t > floor(q / 2):
    #     t -= q
    return t


def cmod_single(n, q):
    if n < 0:
        return n + q
    elif n >= q:
        return n - q
    else:
        return n


class ADD(RV32RegReg):
    insn = insn_for_mnemonic('add', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 + val2) & ((1 << 32) - 1)
        if DEBUG_ARITH or (STACK_BENCH and self.grd == 2):
            eprint(f"add {val1} + {val2} = {result}")

        if STACK_BENCH and self.grd == 2:
            with open(f"{REPO_TOP}/stack_benchmark.txt", "r") as f:
                try:
                    prev_min = int(f.readline(), 10)
                except ValueError:
                    prev_min = 0
            print(f"result: {result} ")
            print(f"prev_min: {prev_min} ")
            print(f"STACK_SIZE - result: {STACK_SIZE - result}")
            if (STACK_SIZE - result) > prev_min:
                with open(f"{REPO_TOP}/stack_benchmark.txt", "w") as f:
                    f.write(str(STACK_SIZE - result))

        state.gprs.get_reg(self.grd).write_unsigned(result)


class ADDI(RV32RegImm):
    insn = insn_for_mnemonic('addi', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 + self.imm) & ((1 << 32) - 1)
        if DEBUG_ARITH or (STACK_BENCH and self.grd == 2):
            eprint(f"addi {val1} + {self.imm} = {result}")

        if STACK_BENCH and self.grd == 2 and self.imm != 0:
            with open(f"{REPO_TOP}/stack_benchmark.txt", "r") as f:
                try:
                    prev_min = int(f.readline(), 10)
                except ValueError:
                    prev_min = 0
            print(f"result: {result} ")
            print(f"prev_min: {prev_min} ")
            print(f"STACK_SIZE - result: {STACK_SIZE - result}")
            if (STACK_SIZE - result) > prev_min:
                with open(f"{REPO_TOP}/stack_benchmark.txt", "w") as f:
                    f.write(str(STACK_SIZE - result))

        state.gprs.get_reg(self.grd).write_unsigned(result)


class LUI(OTBNInsn):
    insn = insn_for_mnemonic('lui', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.imm = op_vals['imm']

    def execute(self, state: OTBNState) -> None:
        state.gprs.get_reg(self.grd).write_unsigned(self.imm << 12)


class SUB(RV32RegReg):
    insn = insn_for_mnemonic('sub', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 - val2) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"sub {val1} - {val2} = {result}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SLL(RV32RegReg):
    insn = insn_for_mnemonic('sll', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = (val1 << val2) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"sll {hex(val1)} << {(val2)} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SLLI(RV32ImmShift):
    insn = insn_for_mnemonic('slli', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        result = (val1 << self.shamt) & ((1 << 32) - 1)
        if DEBUG_ARITH:
            eprint(f"slli {hex(val1)} << {self.shamt} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRL(RV32RegReg):
    insn = insn_for_mnemonic('srl', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        if DEBUG_ARITH:
            eprint(f"srl {hex(val1)} >> {(val2)} = {hex((result) & ((1 << 32) - 1))}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRLI(RV32ImmShift):
    insn = insn_for_mnemonic('srli', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        result = val1 >> self.shamt
        if DEBUG_ARITH:
            eprint(f"srli {hex(val1)} >> {self.shamt} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class SRA(RV32RegReg):
    insn = insn_for_mnemonic('sra', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_signed()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned() & 0x1f
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        if DEBUG_ARITH:
            eprint(f"sra {hex(val1)} >> {val2} = {hex(result)}")
        state.gprs.get_reg(self.grd).write_signed(result)


class SRAI(RV32ImmShift):
    insn = insn_for_mnemonic('srai', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_signed()
        val2 = self.shamt
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 >> val2
        state.gprs.get_reg(self.grd).write_signed(result)


class AND(RV32RegReg):
    insn = insn_for_mnemonic('and', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 & val2
        if DEBUG_ARITH:
            eprint(f"and {hex(val1)} & {hex(val2)} = {hex(val1 & val2)}")
        state.gprs.get_reg(self.grd).write_unsigned(result)


class ANDI(RV32RegImm):
    insn = insn_for_mnemonic('andi', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_ARITH:
            eprint(f"andi {hex(val1)} & {hex(val2)} = {hex(val1 & val2)}")
        result = val1 & val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class OR(RV32RegReg):
    insn = insn_for_mnemonic('or', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_ARITH:
            eprint(f"or {hex(val1)} | {hex(val2)} = {hex(val1 | val2)}")
        result = val1 | val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class ORI(RV32RegImm):
    insn = insn_for_mnemonic('ori', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 | val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class XOR(RV32RegReg):
    insn = insn_for_mnemonic('xor', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 ^ val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class XORI(RV32RegImm):
    insn = insn_for_mnemonic('xori', 3)

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = self.to_2s_complement(self.imm)
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        result = val1 ^ val2
        state.gprs.get_reg(self.grd).write_unsigned(result)


class LW(OTBNInsn):
    insn = insn_for_mnemonic('lw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        # LW executes over two cycles. On the first cycle, we read the base
        # address, compute the load address and check it for correctness, then
        # perform the load itself, returning the result.
        #
        # On the second cycle, we write the result to the destination register.

        base = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        addr = (base + self.offset) & ((1 << 32) - 1)

        if not state.dmem.is_valid_32b_addr(addr):
            if DEBUG_MEM:
                print(f"lw {base} {self.offset}: failed", file=sys.stderr)
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            return None

        result, valid = state.dmem.load_u32(addr)

        # Stall for a single cycle for memory to respond
        yield None

        if DEBUG_MEM:
            print(f"lw {base} {self.offset}", file=sys.stderr)

        if not valid:
            state.stop_at_end_of_cycle(ErrBits.DMEM_INTG_VIOLATION)
            return None

        if DEBUG_MEM:
            print(f"\t{format(result, '08x')}", file=sys.stderr)

        state.gprs.get_reg(self.grd).write_unsigned(result)
        return None


class SW(OTBNInsn):
    insn = insn_for_mnemonic('sw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']

    def execute(self, state: OTBNState) -> None:
        base = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (base + self.offset) & ((1 << 32) - 1)
        value = state.gprs.get_reg(self.grs2).read_unsigned()
        if DEBUG_MEM:
            print(f"sw {base} {self.offset}: {format(value, '08x')}", file=sys.stderr)
        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if not state.dmem.is_valid_32b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return

        state.dmem.store_u32(addr, value)


class BEQ(OTBNInsn):
    insn = insn_for_mnemonic('beq', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs1 = op_vals['grs1']
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_BRANCH:
            eprint(f"Branch: {val1} ?== {val2} to {self.offset}")
        tgt_pc = self.offset & ((1 << 32) - 1)
        if val1 == val2:
            if DEBUG_BRANCH:
                eprint("taken")
            if not state.is_pc_valid(tgt_pc):
                state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
            else:
                state.set_next_pc(tgt_pc)
        else:
            if DEBUG_BRANCH:
                eprint("not taken")


class BNE(OTBNInsn):
    insn = insn_for_mnemonic('bne', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs1 = op_vals['grs1']
        self.grs2 = op_vals['grs2']
        self.offset = op_vals['offset']

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        val2 = state.gprs.get_reg(self.grs2).read_unsigned()

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return
        if DEBUG_BRANCH:
            eprint(f"Branch: {val1} ?!= {val2} to {self.offset}")
        tgt_pc = self.offset & ((1 << 32) - 1)
        if val1 != val2:
            if DEBUG_BRANCH:
                eprint("taken")
            if not state.is_pc_valid(tgt_pc):
                state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
            else:
                state.set_next_pc(tgt_pc)
        else:
            if DEBUG_BRANCH:
                eprint("not taken")


class JAL(OTBNInsn):
    insn = insn_for_mnemonic('jal', 2)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.offset = op_vals['offset']

    def execute(self, state: OTBNState) -> None:
        mask32 = ((1 << 32) - 1)
        link_pc = (state.pc + 4) & mask32
        state.gprs.get_reg(self.grd).write_unsigned(link_pc)
        if DEBUG_FLOW:
            eprint(f"jal {self.offset}")
        next_pc = self.offset & mask32
        if not state.is_pc_valid(next_pc):
            state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
        else:
            state.set_next_pc(next_pc)


class JALR(OTBNInsn):
    insn = insn_for_mnemonic('jalr', 3)
    affects_control = True
    has_fetch_stall = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grs1 = op_vals['grs1']
        self.offset = op_vals['offset']

    def execute(self, state: OTBNState) -> None:
        val1 = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        mask32 = ((1 << 32) - 1)
        link_pc = (state.pc + 4) & mask32

        state.gprs.get_reg(self.grd).write_unsigned(link_pc)

        next_pc = (val1 + self.offset) & mask32
        if not state.is_pc_valid(next_pc):
            state.stop_at_end_of_cycle(ErrBits.BAD_INSN_ADDR)
        else:
            state.set_next_pc(next_pc)


class CSRRS(OTBNInsn):
    insn = insn_for_mnemonic('csrrs', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.csr = op_vals['csr']
        self.grs1 = op_vals['grs1']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        if not state.csrs.check_idx(self.csr):
            # Invalid CSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        bits_to_set = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        if self.csr == 0xfc0:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        # At this point, the CSR is ready. Read, update and write back to grs1.
        old_val = state.read_csr(self.csr)
        new_val = old_val | bits_to_set
        state.gprs.get_reg(self.grd).write_unsigned(old_val)
        if self.grs1 != 0:
            state.write_csr(self.csr, new_val)

        return None


class CSRRW(OTBNInsn):
    insn = insn_for_mnemonic('csrrw', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.csr = op_vals['csr']
        self.grs1 = op_vals['grs1']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        # eprint("csrrw")
        if not state.csrs.check_idx(self.csr):
            # Invalid CSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        new_val = state.gprs.get_reg(self.grs1).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return None

        if self.csr == 0xfc0 and self.grd != 0:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        # At this point, the CSR is either ready or unneeded. Read it if
        # necessary and write to grd, then overwrite with new_val.

        if self.grd != 0:
            old_val = state.read_csr(self.csr)
            state.gprs.get_reg(self.grd).write_unsigned(old_val)

        state.write_csr(self.csr, new_val)
        return None


class ECALL(OTBNInsn):
    insn = insn_for_mnemonic('ecall', 0)

    def execute(self, state: OTBNState) -> None:
        # Set INTR_STATE.done and STATUS, reflecting the fact we've stopped.
        state.stop_at_end_of_cycle(err_bits=0)


class LOOP(OTBNInsn):
    insn = insn_for_mnemonic('loop', 2)
    affects_control = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs = op_vals['grs']
        self.bodysize = op_vals['bodysize']

    def execute(self, state: OTBNState) -> None:
        num_iters = state.gprs.get_reg(self.grs).read_unsigned()
        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            return

        if num_iters == 0:
            state.stop_at_end_of_cycle(ErrBits.LOOP)
        else:
            state.loop_start(num_iters, self.bodysize)


class LOOPI(OTBNInsn):
    insn = insn_for_mnemonic('loopi', 2)
    affects_control = True

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.iterations = op_vals['iterations']
        self.bodysize = op_vals['bodysize']

    def execute(self, state: OTBNState) -> None:
        if DEBUG_FLOW:
            eprint("LOOPI")
        if self.iterations == 0:
            state.stop_at_end_of_cycle(ErrBits.LOOP)
        else:
            state.loop_start(self.iterations, self.bodysize)


class BNADD(OTBNInsn):
    insn = insn_for_mnemonic('bn.add', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a + b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.add 0x{format(a, '064x')} + 0x{format(b, '064x')} = "
                   f"{format(a+b, '064x')} = {format(masked_result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDC(OTBNInsn):
    insn = insn_for_mnemonic('bn.addc', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        carry = int(state.csrs.flags[self.flag_group].C)
        full_result = a + b_shifted + carry
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDI(OTBNInsn):
    insn = insn_for_mnemonic('bn.addi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.imm = op_vals['imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        b = self.imm

        full_result = a + b
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        if DEBUG_ARITH:
            eprint(f"bn.addi {format(a, '064x')} + {b} = {format(a+b, '064x')} = "
                   f"{format(masked_result, '064x')}")
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNADDM(OTBNInsn):
    insn = insn_for_mnemonic('bn.addm', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()

        result = a + b

        if result >= mod_val:
            result -= mod_val

        result = result & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"bn.addm 0x{format(a, '064x')} + 0x{format(b, '064x')} = "
                   f"{format(a+b, '064x')} = {format(result, '064x')}")
            if result >= mod_val:
                eprint("incomplete reduction")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNADDV(OTBNInsn):
    insn = insn_for_mnemonic('bn.addv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()
        red = True if self.type > 1 else False
        size = 32 if (self.type % 2 == 0) else 16
        mod_val = extract_sub_word(mod_val, size, 0)
        result = 0

        for i in range(256 // size - 1, -1, -1):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            resulti = ai + bi
            if red:
                resulti = cmod_single(resulti, mod_val)
            if DEBUG_ARITH:
                eprint(f"addvm {ai} + {bi} = {ai + bi} = {resulti}")
            result <<= size
            result |= (resulti & ((1 << size) - 1))

        result = result & ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNMULQACC(OTBNInsn):
    insn = insn_for_mnemonic('bn.mulqacc', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)

        truncated = acc & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"mulqacc {a_qw} * {b_qw} = {truncated}")

        state.wsrs.ACC.write_unsigned(truncated)


class BNMULQACCWO(OTBNInsn):
    insn = insn_for_mnemonic('bn.mulqacc.wo', 8)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)

        truncated = acc & ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(truncated)
        state.wsrs.ACC.write_unsigned(truncated)
        if DEBUG_ARITH:
            eprint(f"mulqacc.wo {a_qw} * {b_qw} = {truncated}")
        state.set_mlz_flags(self.flag_group, truncated)


class BNMULQACCSO(OTBNInsn):
    insn = insn_for_mnemonic('bn.mulqacc.so', 9)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.zero_acc = op_vals['zero_acc']
        self.wrd = op_vals['wrd']
        self.wrd_hwsel = op_vals['wrd_hwsel']
        self.wrs1 = op_vals['wrs1']
        self.wrs1_qwsel = op_vals['wrs1_qwsel']
        self.wrs2 = op_vals['wrs2']
        self.wrs2_qwsel = op_vals['wrs2_qwsel']
        self.acc_shift_imm = op_vals['acc_shift_imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        a_qw = extract_quarter_word(a, self.wrs1_qwsel)
        b_qw = extract_quarter_word(b, self.wrs2_qwsel)

        mul_res = a_qw * b_qw

        acc = state.wsrs.ACC.read_unsigned()
        if self.zero_acc:
            acc = 0

        acc += (mul_res << self.acc_shift_imm)
        truncated = acc & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"mulqacc.so {a_qw} * {b_qw} = {truncated}")

        # Split the result into low and high parts
        lo_part = truncated & ((1 << 128) - 1)
        hi_part = truncated >> 128

        # Shift out the low part of the result
        hw_shift = 128 * self.wrd_hwsel
        hw_mask = ((1 << 128) - 1) << hw_shift
        old_wrd = state.wdrs.get_reg(self.wrd).read_unsigned()
        new_wrd = (old_wrd & ~hw_mask) | (lo_part << hw_shift)
        state.wdrs.get_reg(self.wrd).write_unsigned(new_wrd)

        # Write back the high part of the result
        state.wsrs.ACC.write_unsigned(hi_part)

        old_flags = state.csrs.flags[self.flag_group]
        if self.wrd_hwsel:
            new_flags = FlagReg(C=old_flags.C,
                                M=bool((lo_part >> 127) & 1),
                                L=old_flags.L,
                                Z=old_flags.Z and lo_part == 0)
        else:
            new_flags = FlagReg(C=old_flags.C,
                                M=old_flags.M,
                                L=bool(lo_part & 1),
                                Z=lo_part == 0)
        state.set_flags(self.flag_group, new_flags)


class BNSUB(OTBNInsn):
    insn = insn_for_mnemonic('bn.sub', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a - b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.sub 0x{format(a, '064x')} - 0x{format(b, '064x')} = "
                   f"{format(a-b, '064x')} = {format(masked_result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBB(OTBNInsn):
    insn = insn_for_mnemonic('bn.subb', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)
        borrow = int(state.csrs.flags[self.flag_group].C)

        full_result = a - b_shifted - borrow
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBI(OTBNInsn):
    insn = insn_for_mnemonic('bn.subi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.imm = op_vals['imm']
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        b = self.imm

        full_result = a - b
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.wdrs.get_reg(self.wrd).write_unsigned(masked_result)
        state.set_flags(self.flag_group, flags)


class BNSUBM(OTBNInsn):
    insn = insn_for_mnemonic('bn.subm', 3)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()

        result = a - b
        if result < 0:
            result += mod_val

        result = result & ((1 << 256) - 1)

        if DEBUG_ARITH:
            eprint(f"bn.subm 0x{format(a, '064x')} - 0x{format(b, '064x')} = "
                   f"{format(a-b, '064x')} = {format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSUBV(OTBNInsn):
    insn = insn_for_mnemonic('bn.subv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mod_val = state.wsrs.MOD.read_unsigned()
        red = True if self.type > 1 else False
        size = 32 if (self.type % 2 == 0) else 16
        mod_val = extract_sub_word(mod_val, size, 0)
        result = 0

        for i in range(256 // size - 1, -1, -1):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            resulti = ai - bi
            if red:
                resulti = cmod_single(resulti, mod_val)
            if DEBUG_ARITH:
                eprint(f"subvm {ai} - {bi} = {ai - bi} = {resulti}")
            result <<= size
            result |= (resulti & ((1 << size) - 1))

        result &= ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNAND(OTBNInsn):
    insn = insn_for_mnemonic('bn.and', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a & b_shifted

        if DEBUG_ARITH:
            eprint(f"bn.and {format(a,'064x')} & {format(b_shifted, '064x')} = "
                   f"{format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNOR(OTBNInsn):
    insn = insn_for_mnemonic('bn.or', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a | b_shifted

        if DEBUG_ARITH:
            eprint(f"bn.or {format(a,'064x')} & {format(b_shifted, '064x')} = "
                   f"{format(result, '064x')}")

        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNNOT(OTBNInsn):
    insn = insn_for_mnemonic('bn.not', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs).read_unsigned()
        a_shifted = logical_byte_shift(a, self.shift_type, self.shift_bytes)

        result = a_shifted ^ ((1 << 256) - 1)
        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNXOR(OTBNInsn):
    insn = insn_for_mnemonic('bn.xor', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        result = a ^ b_shifted
        if DEBUG_ARITH:
            eprint(f"bn.xor 0x{format(a, '064x')} ^ 0x{format(b_shifted, '064x')} = "
                   f"{format(a^b, '064x')} = {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.set_mlz_flags(self.flag_group, result)


class BNRSHI(OTBNInsn):
    insn = insn_for_mnemonic('bn.rshi', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.imm = op_vals['imm']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        result = (((a << 256) | b) >> self.imm) & ((1 << 256) - 1)
        if DEBUG_ARITH:
            eprint(f"bn.rshi {format(a, '064x')}, {format(b, '064x')} = {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSHV(OTBNInsn):
    insn = insn_for_mnemonic('bn.shv', 6)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.type = op_vals['type']
        self.shift_type = op_vals['shift_type']
        self.shift_bits = op_vals['shift_bits']
        self.shift_arith = op_vals['shift_arith']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()

        size = 32 if self.type == 0 else 16

        result = 0

        for i in range((256 - size) // size, -1, -1):
            ai = extract_sub_word(a, size, i)
            if self.shift_arith:
                ai_shifted = bit_shift(ai, self.shift_type, self.shift_bits, size, arith=True)
            else:
                ai_shifted = bit_shift(ai, self.shift_type, self.shift_bits, size)

            resulti = ai_shifted
            result = (result << size) | (resulti & ((1 << size) - 1))

        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNSEL(OTBNInsn):
    insn = insn_for_mnemonic('bn.sel', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.flag_group = op_vals['flag_group']
        self.flag = op_vals['flag']

    def execute(self, state: OTBNState) -> None:
        flag_is_set = state.csrs.flags[self.flag_group].get_by_idx(self.flag)
        wrs = self.wrs1 if flag_is_set else self.wrs2
        value = state.wdrs.get_reg(wrs).read_unsigned()
        if DEBUG_ARITH:
            eprint(f"bn.sel {flag_is_set} -> {format(value, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(value)


class BNCMP(OTBNInsn):
    insn = insn_for_mnemonic('bn.cmp', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)

        full_result = a - b_shifted
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        if DEBUG_ARITH:
            eprint(f"bn.cmp {format(a, '064x')}, {format(b_shifted, '064x')} = "
                   f"{format(full_result, '064x')}")
            eprint(f"\tCarry: {carry_flag}")

        state.set_flags(self.flag_group, flags)


class BNCMPB(OTBNInsn):
    insn = insn_for_mnemonic('bn.cmpb', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.shift_type = op_vals['shift_type']
        self.shift_bytes = op_vals['shift_bits'] // 8
        self.flag_group = op_vals['flag_group']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        b_shifted = logical_byte_shift(b, self.shift_type, self.shift_bytes)
        borrow = int(state.csrs.flags[self.flag_group].C)

        full_result = a - b_shifted - borrow
        mask256 = (1 << 256) - 1
        masked_result = full_result & mask256
        carry_flag = bool((full_result >> 256) & 1)
        flags = FlagReg.mlz_for_result(carry_flag, masked_result)

        state.set_flags(self.flag_group, flags)


class BNLID(OTBNInsn):
    insn = insn_for_mnemonic('bn.lid', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grd_inc = op_vals['grd_inc']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']
        self.grs1_inc = op_vals['grs1_inc']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        # BN.LID executes over two cycles. On the first cycle, we read the base
        # address, compute the load address and check it for correctness,
        # increment any GPRs, then perform the load itself. On the second
        # cycle, update the WDR with the result.

        if self.grs1_inc and self.grd_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grs1_val = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (grs1_val + self.offset) & ((1 << 32) - 1)
        grd_val = state.gprs.get_reg(self.grd).read_unsigned()
        if DEBUG_MEM:
            print(f"bn.lid {grs1_val} {self.offset}", file=sys.stderr)
        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)
        bad_grd = state.gprs.call_stack_err and (self.grd == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grd_val > 31 and not bad_grd:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        wrd = grd_val & 0x1f
        value, valid = state.dmem.load_u256(addr)

        if self.grd_inc:
            new_grd_val = grd_val + 1
            state.gprs.get_reg(self.grd).write_unsigned(new_grd_val)

        if self.grs1_inc:
            new_grs1_val = (grs1_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs1).write_unsigned(new_grs1_val)

        # Stall for a single cycle for memory to respond
        yield None

        if not valid:
            state.stop_at_end_of_cycle(ErrBits.DMEM_INTG_VIOLATION)
            return None

        if DEBUG_MEM:
            print(f"\t {format(value, '064x')}", file=sys.stderr)

        state.wdrs.get_reg(wrd).write_unsigned(value)
        return None


class BNSID(OTBNInsn):
    insn = insn_for_mnemonic('bn.sid', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grs2 = op_vals['grs2']
        self.grs2_inc = op_vals['grs2_inc']
        self.offset = op_vals['offset']
        self.grs1 = op_vals['grs1']
        self.grs1_inc = op_vals['grs1_inc']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        if self.grs1_inc and self.grs2_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grs1_val = state.gprs.get_reg(self.grs1).read_unsigned()
        addr = (grs1_val + self.offset) & ((1 << 32) - 1)
        grs2_val = state.gprs.get_reg(self.grs2).read_unsigned()

        bad_grs1 = state.gprs.call_stack_err and (self.grs1 == 1)
        bad_grs2 = state.gprs.call_stack_err and (self.grs2 == 1)
        if DEBUG_MEM:
            print(f"bn.sid {grs1_val} {self.offset} <- {grs2_val}", file=sys.stderr)
        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grs2_val > 31 and not bad_grs2:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if not state.dmem.is_valid_256b_addr(addr) and not bad_grs1:
            state.stop_at_end_of_cycle(ErrBits.BAD_DATA_ADDR)
            saw_err = True

        if saw_err:
            return None

        if self.grs1_inc:
            new_grs1_val = (grs1_val + 32) & ((1 << 32) - 1)
            state.gprs.get_reg(self.grs1).write_unsigned(new_grs1_val)

        if self.grs2_inc:
            new_grs2_val = grs2_val + 1
            state.gprs.get_reg(self.grs2).write_unsigned(new_grs2_val)

        yield None

        wrs = grs2_val & 0x1f
        wrs_val = state.wdrs.get_reg(wrs).read_unsigned()
        if DEBUG_MEM:
            print(f"\t {format(wrs_val, '064x')}", file=sys.stderr)
        state.dmem.store_u256(addr, wrs_val)
        return None


class BNMOV(OTBNInsn):
    insn = insn_for_mnemonic('bn.mov', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs = op_vals['wrs']

    def execute(self, state: OTBNState) -> None:
        value = state.wdrs.get_reg(self.wrs).read_unsigned()
        state.wdrs.get_reg(self.wrd).write_unsigned(value)


class BNMOVR(OTBNInsn):
    insn = insn_for_mnemonic('bn.movr', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.grd = op_vals['grd']
        self.grd_inc = op_vals['grd_inc']
        self.grs = op_vals['grs']
        self.grs_inc = op_vals['grs_inc']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        if DEBUG_ARITH:
            eprint("MOVR")
        if self.grs_inc and self.grd_inc:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        grd_val = state.gprs.get_reg(self.grd).read_unsigned()
        grs_val = state.gprs.get_reg(self.grs).read_unsigned()

        bad_grs = state.gprs.call_stack_err and (self.grs == 1)
        bad_grd = state.gprs.call_stack_err and (self.grd == 1)

        saw_err = False

        if state.gprs.call_stack_err:
            state.stop_at_end_of_cycle(ErrBits.CALL_STACK)
            saw_err = True

        if grd_val > 31 and not bad_grd:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if grs_val > 31 and not bad_grs:
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            saw_err = True

        if saw_err:
            return None

        wrd = grd_val & 0x1f
        wrs = grs_val & 0x1f

        if self.grd_inc:
            new_grd_val = grd_val + 1
            state.gprs.get_reg(self.grd).write_unsigned(new_grd_val)

        if self.grs_inc:
            new_grs_val = grs_val + 1
            state.gprs.get_reg(self.grs).write_unsigned(new_grs_val)

        yield None

        value = state.wdrs.get_reg(wrs).read_unsigned()
        state.wdrs.get_reg(wrd).write_unsigned(value)
        return None


class BNWSRR(OTBNInsn):
    insn = insn_for_mnemonic('bn.wsrr', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wsr = op_vals['wsr']

    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        # The first, and possibly only, cycle of execution.
        if not state.wsrs.check_idx(self.wsr):
            # Invalid WSR index. Stop with an illegal instruction error.
            state.stop_at_end_of_cycle(ErrBits.ILLEGAL_INSN)
            return None

        if self.wsr == 0x1:
            # A read from RND. If a RND value is not available, request_value()
            # initiates or continues an EDN request and returns False. If a RND
            # value is available, it returns True.
            while not state.wsrs.RND.request_value():
                # There's a pending EDN request. Stall for a cycle.
                yield None

        # At this point, the WSR is ready. Does it have a valid value? (It
        # might not if this is a sideload key register and keymgr hasn't
        # provided us with a value). If not, fail with a KEY_INVALID error.
        if not state.wsrs.has_value_at_idx(self.wsr):
            state.stop_at_end_of_cycle(ErrBits.KEY_INVALID)
            return None

        # The WSR is ready and has a value. Read it.
        val = state.wsrs.read_at_idx(self.wsr)
        if DEBUG_KMAC:
            eprint(f"read WSR: {format(val, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(val)
        return None


class BNWSRW(OTBNInsn):
    insn = insn_for_mnemonic('bn.wsrw', 2)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wsr = op_vals['wsr']
        self.wrs = op_vals['wrs']

    def execute(self, state: OTBNState) -> None:
        val = state.wdrs.get_reg(self.wrs).read_unsigned()
        if DEBUG_KMAC or DEBUG_ARITH:
            eprint(f"write WSR: {format(val, '064x')}")
        state.wsrs.write_at_idx(self.wsr, val)


class BNTRN(OTBNInsn):
    insn = insn_for_mnemonic('bn.trn', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: OTBNState) -> None:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()

        # see instruction scheme for details
        mode_2 = True if self.type in [4, 5, 6, 7] else False
        size = None
        if (self.type % 4) == 0:
            size = 16
        elif (self.type % 4) == 1:
            size = 32
        elif (self.type % 4) == 2:
            size = 64
        else:
            size = 128
        result = 0

        if mode_2:
            a >>= size
            b >>= size

        for i in range(256 // size - 2, -1, -2):
            ai = extract_sub_word(a, size, i)
            bi = extract_sub_word(b, size, i)
            result = (result << size) | bi
            result = (result << size) | ai

        result = result & ((1 << 256) - 1)
        if (DEBUG_ARITH):
            eprint(f"trn: {format(a,'064x')}, {format(b,'064x')}, {format(result, '064x')}")
        state.wdrs.get_reg(self.wrd).write_unsigned(result)


class BNMULV(OTBNInsn):
    insn = insn_for_mnemonic('bn.mulv', 4)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.wrs2 = op_vals['wrs2']
        self.type = op_vals['type']

    def execute(self, state: OTBNState) -> None:
        wrs1 = state.wdrs.get_reg(self.wrs1).read_unsigned()
        wrs2 = state.wdrs.get_reg(self.wrs2).read_unsigned()

        # Extract fields in the encoding:
        #    data_type:    0 = .16H, 1 = .8S
        #    sel:       0 = .even, 1 = .odd
        #    acc_mode:  0 = disabled, 1 = .acc, 2 = .acc.z
        #    exec_mode: 0 = standard, 1 = .lo, 2 = .hi
        data_type = self.type & 0b01
        sel = (self.type & 0b10) >> 1
        acc_mode = (self.type & 0b1100) >> 2
        exec_mode = (self.type & 0b110000) >> 4

        if data_type:
            size = 32
        else:
            size = 16
        num_lanes = 256 // size

        wrs1_v = [extract_sub_word(wrs1, size, i) for i in range(num_lanes)]
        wrs2_v = [extract_sub_word(wrs2, size, i) for i in range(num_lanes)]
        wrd_v = wrs1_v.copy()

        if (data_type == 0) and (exec_mode != 0):
            lane_indices = range(num_lanes)
        else:
            if sel:
                lane_indices = range(1, num_lanes, 2)
            else:
                lane_indices = range(0, num_lanes, 2)

        acc_en = (acc_mode == 1) or (acc_mode == 2)
        accl = state.wsrs.ACC.read_unsigned()
        acch = state.wsrs.ACCH.read_unsigned()
        if acc_mode == 2:
            accl = 0
            acch = 0

        accl_v = [extract_sub_word(accl, 2 * size, i) for i in range(num_lanes // 2)]
        acch_v = [extract_sub_word(acch, 2 * size, i) for i in range(num_lanes // 2)]
        acc_v = accl_v + acch_v

        dmask = (1 << 2 * size) - 1
        mask = (1 << size) - 1

        if DEBUG_ARITH:
            eprint(f"lane_mode | exec_mode | acc_mode | sel | data_type = \
                   0 | {exec_mode} | {acc_mode} | {sel} | {data_type}")
            eprint(f"acc_v = {[hex(acci) for acci in acc_v]}")
            eprint(f'lane_indices = {lane_indices}')

        for i in lane_indices:
            prodi = wrs1_v[i] * wrs2_v[i]

            if DEBUG_ARITH:
                eprint(f'i = {i}')
                eprint(f"ai * bi = {hex(wrs1_v[i])} * {hex(wrs2_v[i])} = {hex(prodi)}")
                eprint(f"acci = {hex(acc_v[i])}")

            if acc_en:
                prodi += acc_v[i]
                acc_v[i] = prodi
                if DEBUG_ARITH:
                    eprint(f"acc_mode: prodi = acci = {hex(prodi)}")

            if exec_mode == 0:
                lo = prodi & mask
                hi = (prodi >> size) & mask
                wrd_v[i - 1 if sel else i     ] = lo
                wrd_v[i     if sel else i + 1 ] = hi
            elif exec_mode == 1:
                wrd_v[i] = prodi & mask
            elif exec_mode == 2:
                wrd_v[i] = (prodi >> size) & mask

            if DEBUG_ARITH:
                eprint(f"wrd_v[{i}] = {hex(wrd_v[i])}")

        result = sum((wrd_v[i] & mask) << (i * size) for i in range(num_lanes))
        state.wdrs.get_reg(self.wrd).write_unsigned(result)

        if acc_en:
            acc_o = sum((acc_v[i] & dmask) << (i * 2 * size) for i in range(num_lanes))
            accl = acc_o & ((1 << 256) - 1)
            acch = (acc_o >> 256) & ((1 << 256) - 1)
            state.wsrs.ACC.write_unsigned(accl)
            if _HAS_ACCH:
                state.wsrs.ACCH.write_unsigned(acch)

        if DEBUG_ARITH:
            eprint(f"result at the end = {hex(result)}")
            eprint(f"accl at the end = {hex(accl)}")
            eprint(f"acch at the end = {hex(acch)}")


class BNMULVL(OTBNInsn):
    insn = insn_for_mnemonic('bn.mulv.l', 5)

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals['wrd']
        self.wrs1 = op_vals['wrs1']
        self.type = op_vals['type']
        self.lane_reg = op_vals['lane_reg']
        self.lane_index = op_vals['lane_index']

    def execute(self, state: OTBNState) -> None:
        # Extract fields in the encoding:
        #    data_type:    0 = .16H, 1 = .8S
        #    sel:       0 = .even, 1 = .odd
        #    acc_mode:  0 = disabled, 1 = .acc, 2 = .acc.z
        #    exec_mode: 0 = standard, 1 = .lo, 2 = .hi
        data_type = self.type & 0b01
        sel = (self.type & 0b10) >> 1
        acc_mode = (self.type & 0b1100) >> 2
        exec_mode = (self.type & 0b110000) >> 4

        wrs1 = state.wdrs.get_reg(self.wrs1).read_unsigned()
        if self.lane_reg:
            wrs2 = state.wdrs.get_reg(17).read_unsigned()
        else:
            wrs2 = state.wdrs.get_reg(16).read_unsigned()

        if data_type:
            size = 32
        else:
            size = 16
        num_lanes = 256 // size

        wrs1_v = [extract_sub_word(wrs1, size, i) for i in range(num_lanes)]
        wrs2_v = [extract_sub_word(wrs2, size, self.lane_index) for i in range(num_lanes)]
        wrd_v = wrs1_v.copy()

        if (data_type == 0) and (exec_mode != 0):
            lane_indices = range(num_lanes)
        else:
            if sel:
                lane_indices = range(1, num_lanes, 2)
            else:
                lane_indices = range(0, num_lanes, 2)

        acc_en = (acc_mode == 1) or (acc_mode == 2)
        accl = state.wsrs.ACC.read_unsigned()
        acch = state.wsrs.ACCH.read_unsigned()
        if acc_mode == 2:
            accl = 0
            acch = 0

        accl_v = [extract_sub_word(accl, 2 * size, i) for i in range(num_lanes // 2)]
        acch_v = [extract_sub_word(acch, 2 * size, i) for i in range(num_lanes // 2)]
        acc_v = accl_v + acch_v

        dmask = (1 << 2 * size) - 1
        mask = (1 << size) - 1

        if DEBUG_ARITH:
            eprint(f"lane_mode | exec_mode | acc_mode | sel | data_type = \
                   1 | {exec_mode} | {acc_mode} | {sel} | {data_type}")
            eprint(f"acc_v = {[hex(acci) for acci in acc_v]}")
            eprint(f'lane_indices = {lane_indices}')

        for i in lane_indices:
            prodi = wrs1_v[i] * wrs2_v[i]

            if DEBUG_ARITH:
                eprint(f'i = {i}')
                eprint(f"ai * bi = {hex(wrs1_v[i])} * {hex(wrs2_v[i])} = {hex(prodi)}")
                eprint(f"acci = {hex(acc_v[i])}")

            if acc_en:
                prodi += acc_v[i]
                acc_v[i] = prodi
                if DEBUG_ARITH:
                    eprint(f"acc_mode: prodi = acci = {hex(prodi)}")

            if exec_mode == 0:
                lo = prodi & mask
                hi = (prodi >> size) & mask
                wrd_v[i - 1 if sel else i     ] = lo
                wrd_v[i     if sel else i + 1 ] = hi
            elif exec_mode == 1:
                wrd_v[i] = prodi & mask
            elif exec_mode == 2:
                wrd_v[i] = (prodi >> size) & mask

            if DEBUG_ARITH:
                eprint(f"wrd_v[{i}] = {hex(wrd_v[i])}")

        result = sum((wrd_v[i] & mask) << (i * size) for i in range(num_lanes))
        state.wdrs.get_reg(self.wrd).write_unsigned(result)

        if acc_en:
            acc_o = sum((acc_v[i] & dmask) << (i * 2 * size) for i in range(num_lanes))
            accl = acc_o & ((1 << 256) - 1)
            acch = (acc_o >> 256) & ((1 << 256) - 1)
            state.wsrs.ACC.write_unsigned(accl)
            if _HAS_ACCH:
                state.wsrs.ACCH.write_unsigned(acch)

        if DEBUG_ARITH:
            eprint(f"result at the end = {hex(result)}")
            eprint(f"accl at the end = {hex(accl)}")
            eprint(f"acch at the end = {hex(acch)}")


class BNMODP256(OTBNInsn):
    """bn.modp256: NIST P-256 fast Solinas modular multiplication.

    Schoolbook 16 cycles (matching RTL ROM) + 10-term Solinas reduction
    with p/2p complements + conditional p-subtract + DONE.
    Total: ~29 cycles depending on conditional subtract iterations.
    """
    insn = insn_for_mnemonic("bn.modp256", 3)
    P256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

    # Schoolbook ROM matching RTL otbn_modp256.sv:
    # (wsel_a, wsel_b, dshift, sel_hi)
    # sel_hi=0: product at dshift*64 in 512-bit space
    # sel_hi=1: product at 256 + dshift*64 (via mul_hi path)
    _SB = [
        (0, 0, 0, 0),  # cnt 0:  a0*b0, eff_shift=0
        (0, 1, 1, 0),  # cnt 1:  a0*b1, eff_shift=64
        (0, 2, 2, 0),  # cnt 2:  a0*b2, eff_shift=128
        (0, 3, 3, 0),  # cnt 3:  a0*b3, eff_shift=192
        (1, 0, 1, 0),  # cnt 4:  a1*b0, eff_shift=64
        (1, 1, 2, 0),  # cnt 5:  a1*b1, eff_shift=128
        (1, 2, 3, 0),  # cnt 6:  a1*b2, eff_shift=192
        (2, 0, 2, 0),  # cnt 7:  a2*b0, eff_shift=128
        (2, 1, 3, 0),  # cnt 8:  a2*b1, eff_shift=192
        (3, 0, 3, 0),  # cnt 9:  a3*b0, eff_shift=192
        (1, 3, 0, 1),  # cnt 10: a1*b3, eff_shift=256 (4*64)
        (2, 2, 0, 1),  # cnt 11: a2*b2, eff_shift=256 (4*64)
        (2, 3, 1, 1),  # cnt 12: a2*b3, eff_shift=320 (5*64)
        (3, 1, 0, 1),  # cnt 13: a3*b1, eff_shift=256 (4*64)
        (3, 2, 1, 1),  # cnt 14: a3*b2, eff_shift=320 (5*64)
        (3, 3, 2, 1),  # cnt 15: a3*b3, eff_shift=384 (6*64)
    ]

    def __init__(self, raw: int, op_vals: Dict[str, int]):
        super().__init__(raw, op_vals)
        self.wrd = op_vals["wrd"]
        self.wrs1 = op_vals["wrs1"]
        self.wrs2 = op_vals["wrs2"]

    # --------------------------------------------------------
    # Solinas term construction helpers
    # --------------------------------------------------------
    @staticmethod
    def _term_from_words(sel_list):
        """Build a 256-bit term from 8 32-bit lane selectors.

        sel_list: list of 8 tuples (src, word_idx) or None for zero.
          src='s' -> from S, src='r' -> from R.
        """
        val = 0
        for lane, spec in enumerate(sel_list):
            if spec is not None:
                val |= (spec[0] << ((7 - lane) * 32))
        return val

    def _build_terms(self, S, R):
        """Build the 10 Solinas reduction terms from S and R.

        Verified formula (see verify_modp256.py), 2000+ random tests passed.
        Index: s[0]=S[255:224](MSB), s[7]=S[31:0](LSB), same for r.
        """
        s = [(S >> (224 - i * 32)) & 0xFFFFFFFF for i in range(8)]
        r = [(R >> (224 - i * 32)) & 0xFFFFFFFF for i in range(8)]

        # Verified sub-terms (c-index: c[0..7]=s[0..7], c[8..15]=r[0..7])
        s1 = (s[0] << 224) | (s[1] << 192) | (s[2] << 160) | (s[3] << 128) | (s[4] << 96)
        s2 = (s[0] << 192) | (s[1] << 160) | (s[2] << 128) | (s[3] << 96)
        s3 = (s[0] << 224) | (s[1] << 192) | (s[5] << 64) | (s[6] << 32) | s[7]
        s4 = (s[7] << 224) | (s[2] << 192) | (s[0] << 160) | (s[1] << 128) | \
             (s[2] << 96)  | (s[4] << 64)  | (s[5] << 32)  | s[6]
        d1 = (s[5] << 224) | (s[7] << 192) | (s[2] << 64) | (s[3] << 32) | s[4]
        d2 = (s[4] << 224) | (s[6] << 192) | (s[0] << 96) | (s[1] << 64) | (s[2] << 32) | s[3]
        d3 = (s[3] << 224) | (s[5] << 160) | (s[6] << 128) | (s[7] << 96) | \
             (s[0] << 64)  | (s[1] << 32)  | s[2]
        d4 = (s[2] << 224) | (s[4] << 160) | (s[5] << 128) | (s[6] << 96) | (s[0] << 32) | s[1]

        p2 = 2 * self.P256
        terms = [
            (s1, True),              # +s1 (1st)
            (s1, True),              # +s1 (2nd)
            (s2, True),              # +s2 (1st)
            (s2, True),              # +s2 (2nd)
            (s3, True),              # +s3
            (s4, True),              # +s4
            (p2 - d1, True),         # +(2p-d1)
            (p2 - d2, True),         # +(2p-d2)
            (self.P256 - d3, True),  # +(p-d3)
            (self.P256 - d4, True),  # +(p-d4)
        ]
        return terms

    def _d_val(self, S, idx):
        """Return raw d1/d2/d3/d4 from S (matching RTL term_val for complement terms)."""
        s = [(S >> (224 - i * 32)) & 0xFFFFFFFF for i in range(8)]
        if idx == 6:   # d1
            return (s[5] << 224) | (s[7] << 192) | (s[2] << 64) | (s[3] << 32) | s[4]
        elif idx == 7: # d2
            return (s[4] << 224) | (s[6] << 192) | (s[0] << 96) | (s[1] << 64) | (s[2] << 32) | s[3]
        elif idx == 8: # d3
            return (s[3] << 224) | (s[5] << 160) | (s[6] << 128) | (s[7] << 96) | (s[0] << 64) | (s[1] << 32) | s[2]
        elif idx == 9: # d4
            return (s[2] << 224) | (s[4] << 160) | (s[5] << 128) | (s[6] << 96) | (s[0] << 32) | s[1]
        return 0

    # --------------------------------------------------------
    # Execute
    # --------------------------------------------------------
    def execute(self, state: OTBNState) -> Optional[Iterator[None]]:
        a = state.wdrs.get_reg(self.wrs1).read_unsigned()
        b = state.wdrs.get_reg(self.wrs2).read_unsigned()
        mask256 = (1 << 256) - 1
        mask512 = (1 << 512) - 1
        mask64  = (1 << 64) - 1

        eprint(f"[ISS_START] opA={a:064x} opB={b:064x}")

        # ================================================
        # Phase 1: Schoolbook multiplication (16 cycles)
        # ================================================
        acc_lo = 0
        acc_hi = 0
        for cnt in range(16):
            i, j, sh, hi = self._SB[cnt]
            ai = (a >> (i * 64)) & mask64
            bj = (b >> (j * 64)) & mask64
            prod = ai * bj

            effective_shift = sh * 64 + (256 if hi else 0)
            total = (acc_hi << 256) | acc_lo
            total = (total + (prod << effective_shift)) & mask512

            acc_lo = total & mask256
            acc_hi = (total >> 256) & mask256
            state.wsrs.ACC.write_unsigned(acc_lo)
            state.wsrs.ACCH.write_unsigned(acc_hi)
            yield None

        S = acc_hi
        R = acc_lo

        # ================================================
        # Phase 2: RED_S0
        # ================================================
        acc_lo = R
        acc_hi = 0
        state.wsrs.ACC.write_unsigned(acc_lo)
        state.wsrs.ACCH.write_unsigned(acc_hi)
        yield None

        # ================================================
        # Phase 3: 10-term Solinas reduction
        # ================================================
        terms = self._build_terms(S, R)
        for idx, (term_val, is_add) in enumerate(terms):
            total = (acc_hi << 256) | acc_lo
            total = (total + term_val) & mask512
            acc_lo = total & mask256
            acc_hi = (total >> 256) & mask256
            pass

            state.wsrs.ACC.write_unsigned(acc_lo)
            state.wsrs.ACCH.write_unsigned(acc_hi)
            yield None

        # ================================================
        # Phase 4: Conditional subtract p (full 512-bit check)
        # ================================================
        full_T = (acc_hi << 256) | acc_lo
        while full_T >= self.P256:
            full_T -= self.P256
            state.wsrs.ACC.write_unsigned(full_T & mask256)
            state.wsrs.ACCH.write_unsigned((full_T >> 256) & mask256)
            yield None

        result = full_T & mask256

        # DONE cycle (RTL ST_DONE)
        state.wsrs.ACC.write_unsigned(result)
        state.wsrs.ACCH.write_unsigned(0)
        yield None

        # ================================================
        # Phase 5: DONE — write result, clear ACCH, set flags
        # ================================================
        state.wdrs.get_reg(self.wrd).write_unsigned(result)
        state.wsrs.ACC.write_unsigned(result)
        state.wsrs.ACCH.write_unsigned(0)
        flags = FlagReg.mlz_for_result(False, result)
        state.set_flags(0, flags)
        return None


INSN_CLASSES = [
    ADD, ADDI, LUI, SUB, SLL, SLLI, SRL, SRLI, SRA, SRAI,
    AND, ANDI, OR, ORI, XOR, XORI,
    LW, SW,
    BEQ, BNE, JAL, JALR,
    CSRRS, CSRRW,
    ECALL,
    LOOP, LOOPI,

    BNADD, BNADDC, BNADDI, BNADDM, BNADDV,
    BNMULV, BNMULVL,
    BNMULQACC, BNMULQACCWO, BNMULQACCSO,
    BNSUB, BNSUBB, BNSUBI, BNSUBM, BNSUBV,
    BNAND, BNOR, BNNOT, BNXOR,
    BNSHV,
    BNRSHI,
    BNSEL,
    BNCMP, BNCMPB,
    BNLID, BNSID,
    BNMOV, BNMOVR, BNTRN,
    BNMODP256,
    BNWSRR, BNWSRW
]
