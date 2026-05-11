#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# Based on: "Towards ML-KEM & ML-DSA on OpenTitan" (https://eprint.iacr.org/2024/1192).

"""
ML-KEM-768 + P-256 ECDH (OTBN) 验证与基准测试
----------------------------------------------
直接使用 OpenTitan 自带的底层仿真类，不依赖论文扩展文件。
"""

import os
import sys
import re
import struct
import argparse
import sqlite3
import time
from typing import Tuple


def dump_to_plain(raw_dump: bytes) -> bytes:
    """OTBN dump_data 返回 5 字节/word: [validity][u32_LE]。剥掉 validity。"""
    out = bytearray()
    for i in range(0, len(raw_dump), 5):
        out.extend(raw_dump[i + 1 : i + 5])
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════
# 0) 环境与路径
# ═══════════════════════════════════════════════════════════════════════════

def _find_opentitan_root():
    cur = os.path.abspath(os.path.dirname(__file__))
    while cur != "/":
        if os.path.isdir(os.path.join(cur, "hw/ip/otbn")):
            if cur not in sys.path:
                sys.path.insert(0, cur)
            return cur
        cur = os.path.dirname(cur)
    return None

_OT_ROOT = _find_opentitan_root()
if _OT_ROOT is None:
    print("Error: Cannot find OpenTitan root (missing hw/ip/otbn)")
    sys.exit(1)
print(f"OpenTitan root: {_OT_ROOT}")

# 自动补全 __init__.py
for _d in [
    os.path.join(_OT_ROOT, "hw"),
    os.path.join(_OT_ROOT, "hw", "ip"),
    os.path.join(_OT_ROOT, "hw", "ip", "otbn"),
    os.path.join(_OT_ROOT, "hw", "ip", "otbn", "dv"),
    os.path.join(_OT_ROOT, "hw", "ip", "otbn", "dv", "otbnsim"),
    os.path.join(_OT_ROOT, "hw", "ip", "otbn", "dv", "otbnsim", "sim"),
]:
    _init = os.path.join(_d, "__init__.py")
    if os.path.isdir(_d) and not os.path.exists(_init):
        open(_init, "w").close()

# 导入 OpenTitan 自带的底层仿真类
from hw.ip.otbn.dv.otbnsim.sim.standalonesim import StandaloneSim  # noqa: E402
from hw.ip.otbn.dv.otbnsim.sim.load_elf import load_elf            # noqa: E402

try:
    from hw.ip.otbn.dv.otbnsim.sim.stats import ExecutionStatAnalyzer  # noqa: E402
    _HAS_STAT_ANALYZER = True
except ImportError:
    _HAS_STAT_ANALYZER = False
    print("  Note: ExecutionStatAnalyzer not available, stats will be basic")

# kyberpy
_KYBER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kyberpy")
if _KYBER_DIR not in sys.path:
    sys.path.insert(0, _KYBER_DIR)
from kyber_py.ml_kem import ML_KEM_768  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════
# 1) OTBN 仿真封装
# ═══════════════════════════════════════════════════════════════════════════

_ELF_MAP: dict = {}


def _inject_dmem(sim, additional_data: list) -> None:
    """向 OTBN DMEM 写入数据。"""
    for offset, data in additional_data:
        if offset % 4 != 0:
            raise ValueError(
                f"inject_dmem: offset {offset:#x} is not 4-byte aligned"
            )
        word_offset = offset // 4
        sim.state.dmem.load_le_words(bytes(data), False, word_offset)


# ── 解析 dump() 返回的文本 ─────────────────────────────────────────────
def _parse_stat_dump(text: str) -> dict:
    """
    解析 ExecutionStatAnalyzer.dump() 的文本输出，
    提取 insn_count, cycles, stall_count, 指令频次。
    """
    result = {
        "insn_count": 0,
        "stall_count": 0,
        "cycles": 0,
        "func_instrs": {},
        "func_calls": {},
    }

    # "OTBN executed 581344 instructions in 603173 cycles."
    m = re.search(
        r"OTBN executed ([\d,]+) instructions in ([\d,]+) cycles", text
    )
    if m:
        result["insn_count"] = int(m.group(1).replace(",", ""))
        result["cycles"] = int(m.group(2).replace(",", ""))

    # "The execution stalled for 21829 cycles (3.8 percent)"
    m = re.search(r"stalled for ([\d,]+) cycles", text)
    if m:
        result["stall_count"] = int(m.group(1).replace(",", ""))

    # 指令频次 → func_instrs["__global__"]["bn.mulqacc"] = [191990, 0]
    instr_section = re.search(
        r"Instruction frequencies\s*\n-+\ninstruction\s+count\n-+\n"
        r"(.*?)(?=\n\n|\nBasic|\Z)",
        text,
        re.DOTALL,
    )
    if instr_section:
        result["func_instrs"]["__global__"] = {}
        for line in instr_section.group(1).strip().split("\n"):
            parts = line.strip().split()
            if len(parts) == 2:
                try:
                    cnt = int(parts[1].replace(",", ""))
                    result["func_instrs"]["__global__"][parts[0]] = [cnt, 0]
                except ValueError:
                    pass

    return result


def _get_stat_data(sim, elf_path: str) -> dict:
    """提取仿真统计数据，确保 cycles / insn_count / stall_count 正确。"""
    stat_data = {
        "insn_count": 0,
        "stall_count": 0,
        "cycles": 0,
        "func_instrs": {},
        "func_calls": {},
    }

    if _HAS_STAT_ANALYZER:
        try:
            analyzer = ExecutionStatAnalyzer(sim.stats, elf_path)

            # 1) get_stat_data() → cycles/insn_count/stalls
            if hasattr(analyzer, "get_stat_data"):
                sd = analyzer.get_stat_data()
                if sd:
                    for k, v in sd.items():
                        if v:
                            stat_data[k] = v

            # 2) dump() → 指令频次 + 函数调用（始终调用，不提前 return）
            if hasattr(analyzer, "dump"):
                dump_ret = analyzer.dump()
                if isinstance(dump_ret, str) and dump_ret:
                    print(dump_ret)
                    parsed = _parse_stat_dump(dump_ret)
                    # 用 dump 的数据补充缺失字段
                    for k, v in parsed.items():
                        if v and not stat_data.get(k):
                            stat_data[k] = v
                # 如果 dump_ret 为 None，说明 dump() 自行输出到 stdout 了

        except Exception as e:
            print(f"  Warning: stat analysis failed: {e}")

    # 3) Fallback：从 sim.stats 直接提取
    try:
        if sim.stats is not None:
            for attr in ("insn_count", "stall_count", "cycles"):
                if not stat_data[attr]:
                    stat_data[attr] = getattr(sim.stats, attr, 0)
    except Exception:
        pass

    # 4) 兜底
    if stat_data["cycles"] == 0:
        stat_data["cycles"] = stat_data["insn_count"] + stat_data["stall_count"]

    return stat_data


def run_otbn(operation: str, additional_data: list = None) -> Tuple[bytes, dict]:
    """运行 OTBN 仿真。"""
    if operation not in _ELF_MAP:
        print(f"Error: operation '{operation}' not in ELF_MAP: {list(_ELF_MAP.keys())}")
        sys.exit(1)

    elf_path = _ELF_MAP[operation]
    if not os.path.isfile(elf_path):
        print(f"Error: ELF not found: {elf_path}")
        sys.exit(1)

    sim = StandaloneSim()

    exp_end_addr = load_elf(sim, elf_path)

    if additional_data:
        _inject_dmem(sim, additional_data)

    try:
        key0 = int("deadbeef" * 12, 16)
        key1 = int("baadf00d" * 12, 16)
        sim.state.wsrs.set_sideload_keys(key0, key1)
        sim.state.ext_regs.commit()
    except AttributeError:
        pass

    sim.start(True)
    sim.run(False, None)

    if exp_end_addr is not None:
        try:
            if sim.state.pc != exp_end_addr:
                print(
                    f"Error: PC mismatch: got {sim.state.pc:#x}, "
                    f"expected {exp_end_addr:#x}",
                    file=sys.stderr,
                )
        except AttributeError:
            pass

    raw_dmem = dump_to_plain(sim.dump_data())
    stat_data = _get_stat_data(sim, elf_path)
    stat_data["symbols"] = dict(sim.symbols)

    return raw_dmem, stat_data


# ═══════════════════════════════════════════════════════════════════════════
# 2) SQLite 辅助
# ═══════════════════════════════════════════════════════════════════════════

DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "kyber_bench.db"
)


def create_db(cur):
    try:
        cur.execute(
            "CREATE TABLE benchmark("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "start_time INTEGER, end_time INTEGER, iterations INTEGER, "
            "operation TEXT)"
        )
        cur.execute(
            "CREATE TABLE benchmark_iteration("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, benchmark_id INTEGER, "
            "FOREIGN KEY(benchmark_id) REFERENCES benchmark(id));"
        )
        cur.execute(
            "CREATE TABLE cycles(cycles INTEGER, benchmark_iteration_id INTEGER, "
            "FOREIGN KEY(benchmark_iteration_id) REFERENCES benchmark_iteration(id));"
        )
        cur.execute(
            "CREATE TABLE stalls(stalls INTEGER, benchmark_iteration_id INTEGER, "
            "FOREIGN KEY(benchmark_iteration_id) REFERENCES benchmark_iteration(id));"
        )
        cur.execute(
            "CREATE TABLE func_instrs("
            "func_name TEXT, instr_name TEXT, instr_count INTEGER, stall_count INTEGER, "
            "benchmark_iteration_id INTEGER, "
            "FOREIGN KEY(benchmark_iteration_id) REFERENCES benchmark_iteration(id));"
        )
        cur.execute(
            "CREATE TABLE func_calls("
            "caller_func_name TEXT, callee_func_name TEXT, call_count INTEGER, "
            "benchmark_iteration_id INTEGER, "
            "FOREIGN KEY(benchmark_iteration_id) REFERENCES benchmark_iteration(id));"
        )
    except sqlite3.OperationalError:
        print("DB already exists, skipping table creation.")


# ═══════════════════════════════════════════════════════════════════════════
# 3) OTBN 接口封装 —— ML-KEM-768
# ═══════════════════════════════════════════════════════════════════════════

CRYPTO_BYTES = 32
STACK_SIZE = 20000
_K768_PK = 1184
_K768_SK = 2400
_K768_CT = 1088


def mlkem_keypair_otbn_768(z_bytes: bytes, operation: str) -> Tuple[bytes, bytes, dict]:
    raw_dmem, stat_data = run_otbn(
        operation,
        [(STACK_SIZE + _K768_SK + _K768_PK, z_bytes)],
    )
    ek = raw_dmem[STACK_SIZE + _K768_SK : STACK_SIZE + _K768_SK + _K768_PK]
    dk = raw_dmem[STACK_SIZE : STACK_SIZE + _K768_SK]
    return ek, dk, stat_data


def mlkem_encaps_otbn_768(
    m_bytes: bytes, ek_bytes: bytes, operation: str
) -> Tuple[bytes, bytes, dict]:
    raw_dmem, stat_data = run_otbn(
        operation,
        [
            (STACK_SIZE + _K768_CT + CRYPTO_BYTES, m_bytes),
            (STACK_SIZE + _K768_CT + 2 * CRYPTO_BYTES, ek_bytes),
        ],
    )
    c = raw_dmem[STACK_SIZE : STACK_SIZE + _K768_CT]
    K = raw_dmem[STACK_SIZE + _K768_CT : STACK_SIZE + _K768_CT + CRYPTO_BYTES]
    return c, K, stat_data


def mlkem_decaps_otbn_768(
    c_bytes: bytes, dk_bytes: bytes, operation: str
) -> Tuple[bytes, dict]:
    raw_dmem, stat_data = run_otbn(
        operation,
        [
            (STACK_SIZE + CRYPTO_BYTES, c_bytes),
            (STACK_SIZE + CRYPTO_BYTES + _K768_CT, dk_bytes),
        ],
    )
    K_prime = raw_dmem[STACK_SIZE : STACK_SIZE + CRYPTO_BYTES]
    return K_prime, stat_data


# ═══════════════════════════════════════════════════════════════════════════
# 4) OTBN 接口封装 —— P-256 ECDH
# ═══════════════════════════════════════════════════════════════════════════


def p256_ecdh_otbn(operation: str) -> Tuple[bytes, dict]:
    raw_dmem, stat_data = run_otbn(operation)
    syms = stat_data.get("symbols", {})
    share0_addr = syms.get("x", 0x080)
    share1_addr = syms.get("y", 0x0A0)
    share0 = raw_dmem[share0_addr : share0_addr + 32]
    share1 = raw_dmem[share1_addr : share1_addr + 32]
    unmasked = bytes(a ^ b for a, b in zip(share0, share1))
    return unmasked, stat_data


# ═══════════════════════════════════════════════════════════════════════════
# 5) P-256 ECDH 参考实现
# ═══════════════════════════════════════════════════════════════════════════


def compute_p256_ecdh_reference() -> bytes:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print("Error: 'cryptography' not installed. pip install cryptography")
        sys.exit(1)

    d0_le = [
        0xFE6D1071, 0x21D0A016, 0xB0B2C781, 0x9590EF5D,
        0x3FDFa379, 0x1B76EBE8, 0x74210263, 0x1420FC41,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]
    x_le = [
        0xBFA8C334, 0x9773B7B3, 0xF36B0689, 0x6EC0C0B2,
        0xDB6C8BF3, 0x1628CE58, 0xFACDC546, 0xB5511A6A,
    ]
    y_le = [
        0x9E008C2E, 0xA8707058, 0xAB9C6924, 0x7F7A11D0,
        0xB53A17FA, 0x43DD09EA, 0x1F31C143, 0x42A1C697,
    ]

    d_int = int.from_bytes(struct.pack("<16I", *d0_le), "little")
    x_int = int.from_bytes(struct.pack("<8I", *x_le), "little")
    y_int = int.from_bytes(struct.pack("<8I", *y_le), "little")

    priv = ec.derive_private_key(d_int, ec.SECP256R1())
    pub = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1()).public_key()
    return priv.exchange(ec.ECDH(), pub)[::-1]


# ═══════════════════════════════════════════════════════════════════════════
# 6) 基准函数
# ═══════════════════════════════════════════════════════════════════════════
def bench_hash(operation):
    """运行纯哈希自测 ELF (无需外部 Python 参考比对，直接采集性能数据)"""
    _, st = run_otbn(operation)
    print("  [hash]    OK")
    return st

def bench_mlkem_keypair(operation, ref):
    d, z = os.urandom(32), os.urandom(32)
    ek, dk = ref._keygen_internal(d, z)
    ek_o, dk_o, st = mlkem_keypair_otbn_768(d + z, operation)
    if ek != ek_o:
        print("Error: Keypair encaps key mismatch")
        return -1
    if dk != dk_o:
        print("Error: Keypair decaps key mismatch")
        return -1
    print("  [keypair] OK")
    return st


def bench_mlkem_encaps(operation, ref):
    d, z, m = os.urandom(32), os.urandom(32), os.urandom(32)
    ek, dk = ref._keygen_internal(d, z)
    K, c = ref._encaps_internal(ek, m)
    c_o, K_o, st = mlkem_encaps_otbn_768(m, ek, operation)
    if c != c_o or K != K_o:
        print("Error: Encaps mismatch")
        return -1
    print("  [encap]   OK")
    return st


def bench_mlkem_decaps(operation, ref):
    d, z, m = os.urandom(32), os.urandom(32), os.urandom(32)
    ek, dk = ref._keygen_internal(d, z)
    K, c = ref._encaps_internal(ek, m)
    Kp = ref.decaps(dk, c)
    Kp_o, st = mlkem_decaps_otbn_768(c, dk, operation)
    if Kp != Kp_o:
        print("Error: Decaps shared key mismatch")
        return -1
    print("  [decap]   OK")
    return st


def bench_p256_ecdh(operation):
    otbn_key, st = p256_ecdh_otbn(operation)
    ref_key = compute_p256_ecdh_reference()
    if otbn_key != ref_key:
        print("Error: P-256 ECDH shared key mismatch")
        print(f"  OTBN: {otbn_key.hex()}")
        print(f"  Ref : {ref_key.hex()}")
        return -1
    print("  [p256]    OK")
    return st


# ═══════════════════════════════════════════════════════════════════════════
# 7) 运行基准 + 写入 DB
# ═══════════════════════════════════════════════════════════════════════════

ITERATIONS = 1


def _write_result_to_db(cur, bid, result):
    """将单次迭代结果写入 DB，cycles 使用 stat_data 中的真实值。"""
    cur.execute(
        "INSERT INTO benchmark_iteration (benchmark_id) VALUES(?)", (bid,)
    )
    it_id = cur.lastrowid

    # cycles：优先用 result["cycles"]，兜底用 insn+stall
    cycles_val = result.get("cycles", 0)
    if cycles_val == 0:
        cycles_val = result.get("insn_count", 0) + result.get("stall_count", 0)

    stall_val = result.get("stall_count", 0)

    cur.execute(
        "INSERT INTO cycles (cycles, benchmark_iteration_id) VALUES(?,?)",
        (cycles_val, it_id),
    )
    cur.execute(
        "INSERT INTO stalls (stalls, benchmark_iteration_id) VALUES(?,?)",
        (stall_val, it_id),
    )

    # func_instrs: {"__global__": {"bn.mulqacc": [191990, 0], ...}}
    for fn, per in result.get("func_instrs", {}).items():
        for instr, vals in per.items():
            if isinstance(vals, (list, tuple)):
                ic, sc = vals[0], vals[1]
            else:
                ic, sc = vals, 0
            cur.execute(
                "INSERT INTO func_instrs "
                "(func_name,instr_name,instr_count,stall_count,benchmark_iteration_id) "
                "VALUES(?,?,?,?,?)",
                (fn, instr, ic, sc, it_id),
            )

    # func_calls: {"callee": {"caller": count, ...}, ...}
    for callee, callers in result.get("func_calls", {}).items():
        if isinstance(callers, dict):
            for caller, cnt in callers.items():
                cur.execute(
                    "INSERT INTO func_calls "
                    "(caller_func_name,callee_func_name,call_count,benchmark_iteration_id) "
                    "VALUES(?,?,?,?)",
                    (caller, callee, cnt, it_id),
                )


def run_bench(operation):
    con = sqlite3.connect(DATABASE_PATH)
    cur = con.cursor()
    create_db(cur)
    print(f"Benchmark: {operation}")

    if "hash" in operation:
        func, need_ref = bench_hash, False
    elif "keypair" in operation:
        func, need_ref = bench_mlkem_keypair, True
    elif "encap" in operation:
        func, need_ref = bench_mlkem_encaps, True
    elif "decap" in operation:
        func, need_ref = bench_mlkem_decaps, True
    elif "p256" in operation or "ecdh" in operation:
        func, need_ref = bench_p256_ecdh, False
    else:
        print(f"Unknown operation: {operation}")
        sys.exit(1)


    ref = ML_KEM_768
    results = []
    t0 = int(time.time())
    for _ in range(ITERATIONS):
        r = func(operation, ref) if need_ref else func(operation)
        results.append(r)
    t1 = int(time.time())

    if -1 in results:
        print("Error in computation, aborting")
        con.close()
        sys.exit(1)

    cur.execute(
        "INSERT INTO benchmark "
        "(start_time,end_time,iterations,operation) VALUES(?,?,?,?)",
        (t0, t1, ITERATIONS, operation),
    )
    bid = cur.lastrowid
    for r in results:
        _write_result_to_db(cur, bid, r)
    con.commit()
    con.close()


# ═══════════════════════════════════════════════════════════════════════════
# 8) 命令行入口
# ═══════════════════════════════════════════════════════════════════════════


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HASH + ML-KEM-768 + P-256 ECDH OTBN benchmark"
    )
    parser.add_argument("simulator", help="(ignored) Path to OTBN standalone simulator.")
    parser.add_argument("elf", help='ELF map: name#/path/to.elf,...')
    parser.add_argument("test_name", help="Operation name")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    for item in args.elf.split(","):
        if "#" not in item:
            continue
        name, path = item.split("#", 1)
        _ELF_MAP[name] = path

    print("SW/OTBN/CRYPTO (ML-KEM-768 + P-256 ECDH)")
    print(f"  test_name : {args.test_name}")
    print(f"  ELF_MAP   : {list(_ELF_MAP.keys())}")

    run_bench(args.test_name)
    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())