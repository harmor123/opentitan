#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""
ML-KEM-768 + P-256 ECDH  基准测试自动分析（Log 驱动）
====================================================
用法:
    python3 test/analyze_bench.py                                # 分析最新 log
    python3 test/analyze_bench.py --log logs/bench_xxx.log       # 指定日志
    python3 test/analyze_bench.py --db kyber_bench.db            # 指定数据库
    python3 test/analyze_bench.py --compare db_old.db db_new.db  # 版本对比
    python3 test/analyze_bench.py --no-latex                     # 不输出 LaTeX
"""

import os
import sys
import glob
import re
import sqlite3
import argparse
from collections import defaultdict
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(SCRIPT_DIR, "kyber_bench.db")
DEFAULT_LOG_DIR = os.path.join(SCRIPT_DIR, "logs")

# ── ANSI 颜色 ──
C_OK   = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"
C_HEAD = "\033[96m"
C_BOLD = "\033[1m"
C_DIM  = "\033[2m"
C_END  = "\033[0m"

OP_DISPLAY = {
    "hash_test":        "SHA3/SHAKE Hash",       
    "mlkem768_keypair": "ML-KEM-768 Keypair",
    "mlkem768_encap":   "ML-KEM-768 Encap",
    "mlkem768_decap":   "ML-KEM-768 Decap",
    "p256_ecdh":        "P-256 ECDH",
}


BANNER = f"""
{C_HEAD}╔══════════════════════════════════════════════════════════════╗
║     ML-KEM-768 + P-256 ECDH  Benchmark Analysis Report      ║
╚══════════════════════════════════════════════════════════════╝{C_END}
"""

SEP_THIN  = "─" * 70
SEP_THICK = "═" * 70


# ══════════════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════════════
# ── 终端宽度感知（CJK 字符占 2 列） ──
def _dw(s: str) -> int:
    """计算字符串的终端显示宽度。"""
    return sum(2 if ord(c) > 0x2fff else 1 for c in s)


def _rpad(s: str, width: int) -> str:
    """右端填充空格，使显示宽度达到 width。"""
    return s + " " * max(0, width - _dw(s))

def _op(name: str) -> str:
    return OP_DISPLAY.get(name, name)


def _norm(name: str) -> str:
    """将各种形式的操作名统一为内部 key。"""
    n = name.lower().strip()
    if "hash" in n:               
        return "hash_test"
    if "keypair" in n:
        return "mlkem768_keypair"
    if "encap" in n:
        return "mlkem768_encap"
    if "decap" in n:
        return "mlkem768_decap"
    if "ecdh" in n or "p256" in n:
        return "p256_ecdh"
    return n


def _bar(ratio: float, width: int = 20) -> str:
    if ratio < 0:
        ratio = 0
    if ratio > 1:
        ratio = 1
    filled = int(ratio * width)
    return f"{C_OK}{'█' * filled}{C_END}{C_DIM}{'░' * (width - filled)}{C_END}"


def _delta_pct(new: float, old: float) -> str:
    if old == 0:
        return "  N/A "
    d = (new - old) / old * 100
    if d <= -0.5:
        return f"{C_OK}▼{abs(d):5.1f}%{C_END}"
    elif d >= 0.5:
        return f"{C_FAIL}▲{d:5.1f}%{C_END}"
    else:
        return "  ~0% "


def _latest_log(log_dir: str) -> str:
    logs = sorted(glob.glob(os.path.join(log_dir, "bench_*.log")))
    return logs[-1] if logs else ""


def _fmt(n: int) -> str:
    return f"{n:,}"


# ══════════════════════════════════════════════════════════════════════════
# 1) Log 解析器
# ══════════════════════════════════════════════════════════════════════════

def parse_log(log_path: str) -> list:
    """解析单个 log 文件，返回结构化数据列表（已去重）。"""
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    # 按 "\n>>> [N/M] Name" 分割，第一个元素是文件头（丢弃）
    blocks = re.split(r"\n>>>\s*\[\d+/\d+\]\s*", text)

    tests = []
    for i, block in enumerate(blocks[1:], 1):
        lines = block.strip().split("\n")
        if not lines:
            continue
        name = lines[0].strip()
        body = "\n".join(lines[1:])
        # 截断：遇到 "=====" 分隔线或 "All N tests" 即停止，防止尾部重复内容污染
        cut = re.split(r"\n={10,}|\nAll \d+ tests", body)
        if len(cut) > 1:
            body = cut[0]

        t = {
            "num": i, "total": len(blocks) - 1,
            "raw_name": name, "op_key": _norm(name),
            "instructions": 0, "cycles": 0, "stalls": 0, "stall_pct": 0.0,
            "ms": 0.0, "instr_freq": [], "func_calls": [], "pass": False,
            "source": "log",
        }

        # ── 指令数 & cycles ──
        m = re.search(
            r"OTBN executed ([\d,]+) instructions in ([\d,]+) cycles", body
        )
        if m:
            t["instructions"] = int(m.group(1).replace(",", ""))
            t["cycles"]       = int(m.group(2).replace(",", ""))

        # ── Stall ──
        m = re.search(r"stalled for ([\d,]+) cycles \(([0-9.]+) percent\)", body)
        if m:
            t["stalls"]    = int(m.group(1).replace(",", ""))
            t["stall_pct"] = float(m.group(2))

        # ── 时间 ──
        m = re.search(r"would take ([0-9.]+) ms", body)
        if m:
            t["ms"] = float(m.group(1))

        # ── 指令频次：宽松解析 ──
        parts = re.split(r"Instruction\s+frequencies", body)
        if len(parts) > 1:
            for line in parts[1].split("\n"):
                stripped = line.strip()
                if not stripped:
                    if t["instr_freq"]:  # 已有数据时遇到空行才结束
                        break
                    continue              # 开头的空行直接跳过
                # 跳过表头行（横线、列名）
                if stripped.startswith("-") or stripped.startswith("instruction"):
                    continue
                # 跳过非数据行（如 "Basic block" 等后续章节）
                if stripped.startswith("Basic") or stripped.startswith("Number"):
                    break
                # 匹配 "name  count"
                im = re.match(r"^(\S+)\s+([\d,]+)\s*$", stripped)
                if im:
                    try:
                        cnt = int(im.group(2).replace(",", ""))
                        t["instr_freq"].append((im.group(1), cnt))
                    except ValueError:
                        continue

        # ── 函数调用频次 ──
        #    匹配 "Function 0xADDR (name)" 定义行，再往后找 "* N times"
        for fm in re.finditer(
            r"^Function\s+0x[0-9a-f]+\s+\(([^)]+)\)", body, re.MULTILINE
        ):
            fname = fm.group(1).strip()
            # 跳过明显异常的名字
            if "\n" in fname or len(fname) > 60:
                continue
            after = body[fm.end():fm.end() + 500]
            total = sum(
                int(cm.group(1))
                for cm in re.finditer(r"\*\s*(\d+)\s+times", after)
            )
            if total > 0:
                t["func_calls"].append((fname, total))

        # ── 判定 pass/fail ──
        tail = body[-500:].lower() if len(body) > 500 else body.lower()
        t["pass"] = (
            "[hash]    ok" in tail or "[keypair] ok" in tail or "[encap]   ok" in tail   
            or "[decap]   ok" in tail or "[p256]    ok" in tail
        ) and "error" not in tail

        tests.append(t)

    # ── 去重（日志尾部可能有重复内容） ──
    seen_keys = set()
    deduped = []
    for t in tests:
        if t["op_key"] not in seen_keys:
            seen_keys.add(t["op_key"])
            deduped.append(t)
    return deduped


# ══════════════════════════════════════════════════════════════════════════
# 2) DB 读取
# ══════════════════════════════════════════════════════════════════════════

def db_read_latest(db_path: str) -> list:
    """从 DB 读取最近一次运行数据。"""
    if not os.path.isfile(db_path):
        return []
    con = sqlite3.connect(db_path)
    rows = con.execute("""
        SELECT b.operation, c.cycles, s.stalls,
               (SELECT SUM(fi.instr_count) FROM func_instrs fi
                WHERE fi.benchmark_iteration_id = bi.id) as total_instr
        FROM benchmark b
        JOIN benchmark_iteration bi ON b.id = bi.benchmark_id
        JOIN cycles c ON bi.id = c.benchmark_iteration_id
        JOIN stalls s ON bi.id = s.benchmark_iteration_id
        ORDER BY b.start_time DESC
    """).fetchall()
    con.close()

    seen = set()
    result = []
    for op, cyc, stal, tinstr in rows:
        if op in seen:
            continue
        seen.add(op)
        result.append({
            "raw_name": op,
            "op_key": _norm(op),
            "cycles": cyc or 0,
            "stalls": stal or 0,
            "instructions": tinstr or 0,
            "stall_pct": (stal / cyc * 100) if cyc and stal else 0,
            "ms": (cyc / 100000.0) if cyc else 0,
            "source": "db",
        })
    return result


def db_read_history(db_path: str) -> dict:
    """读取 DB 中所有运行记录，返回 {op_key: [(timestamp, cycles), ...]}。"""
    if not os.path.isfile(db_path):
        return {}
    con = sqlite3.connect(db_path)
    rows = con.execute("""
        SELECT b.start_time, b.operation, c.cycles
        FROM benchmark b
        JOIN benchmark_iteration bi ON b.id = bi.benchmark_id
        JOIN cycles c ON bi.id = c.benchmark_iteration_id
        ORDER BY b.start_time ASC
    """).fetchall()
    con.close()

    per_op = defaultdict(list)
    for ts, op, cyc in rows:
        key = _norm(op)
        if cyc and cyc > 0:
            per_op[key].append((ts, cyc))
    return dict(per_op)


# ══════════════════════════════════════════════════════════════════════════
# 3) 输出模块
# ══════════════════════════════════════════════════════════════════════════

def print_overview(tests: list):
    """[1] 性能总览"""
    print(f"\n{C_BOLD}[1] 性能总览{C_END}")
    print(SEP_THIN)
    print(f"  {'操作':<28} {'Instructions':>14} {'Cycles':>12} "
          f"{'Stalls':>10} {'Stall%':>8} {'@100MHz':>10}")
    print(f"  {'─' * 28} {'─' * 14} {'─' * 12} {'─' * 10} {'─' * 8} {'─' * 10}")

    total_cyc = 0
    for t in tests:
        name = _op(t["op_key"])
        pct  = t["stall_pct"]
        ms   = t["cycles"] / 100000.0 if t["cycles"] else t["ms"]
        status = f"{C_OK}✓{C_END}" if t.get("pass", True) else f"{C_FAIL}✗{C_END}"

        if pct < 5:
            pct_s = f"{C_OK}{pct:>6.1f}%{C_END}"
        elif pct < 10:
            pct_s = f"{C_WARN}{pct:>6.1f}%{C_END}"
        else:
            pct_s = f"{C_FAIL}{pct:>6.1f}%{C_END}"

        print(f"  {name:<28} {t['instructions']:>14,} {t['cycles']:>12,} "
              f"{t['stalls']:>10,} {pct_s} {ms:>8.2f}ms {status}")
        total_cyc += t["cycles"]

    print(f"  {'─' * 28} {'─' * 14} {'─' * 12} {'─' * 10} {'─' * 8} {'─' * 10}")
    print(f"  {'TOTAL':<28} {'':>14} {total_cyc:>12,} "
          f"{'':>10} {'':>8} {total_cyc / 100000.0:>8.2f}ms")

    kem = [t for t in tests if "mlkem" in t["op_key"]]
    if kem:
        ki = sum(t["instructions"] for t in kem)
        kc = sum(t["cycles"] for t in kem)
        print(f"  {'KEM total (kp+en+dc)':<28} {ki:>14,} {kc:>12,} "
              f"{'':>10} {'':>8} {kc / 100000.0:>8.2f}ms")


def print_top_instructions(tests: list):
    """[2] 各操作 Top-10 指令"""
    print(f"\n{C_BOLD}[2] 各操作 Top-10 指令{C_END}")
    print(SEP_THIN)

    for t in tests:
        name = _op(t["op_key"])
        freqs = t.get("instr_freq", [])
        if not freqs:
            print(f"\n  {C_DIM}▸ {name} — 无指令数据{C_END}")
            continue

        total = sum(c for _, c in freqs)
        print(f"\n  {C_HEAD}▸ {name}  ({_fmt(total)} total instructions){C_END}")
        max_val = freqs[0][1] if freqs else 1
        print(f"    {'指令':<22} {'次数':>12} {'占比':>8}  柱状")
        print(f"    {'─' * 22} {'─' * 12} {'─' * 8}  {'─' * 20}")
        for iname, cnt in freqs[:10]:
            pct = cnt * 100.0 / total if total else 0
            bar = _bar(cnt / max_val)
            print(f"    {iname:<22} {cnt:>12,} {pct:>6.1f}%  {bar}")


def print_hot_functions(tests: list):
    """[3] 各操作热点函数（调用次数）"""
    print(f"\n{C_BOLD}[3] 各操作热点函数{C_END}")
    print(SEP_THIN)

    for t in tests:
        name = _op(t["op_key"])
        fcalls = t.get("func_calls", [])
        if not fcalls:
            print(f"\n  {C_DIM}▸ {name} — 无函数调用数据{C_END}")
            continue

        print(f"\n  {C_HEAD}▸ {_rpad(name, 28)}{C_END}")
        sorted_fc = sorted(fcalls, key=lambda x: -x[1])
        max_val = sorted_fc[0][1] if sorted_fc else 1
        print(f"    {'函数名':<50} {'调用次数':>10}")
        print(f"    {'─' * 50} {'─' * 10}")
        for fname, cnt in sorted_fc[:15]:
            bar = _bar(cnt / max_val)
            print(f"    {fname:<50} {cnt:>8}×  {bar}")


def print_instruction_breakdown(tests: list):
    """[4] 各操作指令分布（按类别）"""
    print(f"\n{C_BOLD}[4] 各操作指令类别分布{C_END}")
    print(SEP_THIN)

    categories = {
        "乘累加 (mulqacc*)": ("bn.mulqacc", "bn.mulqacc.wo", "bn.mulqacc.so"),
        "加/减 (add/sub*)": ("bn.add", "bn.addc", "bn.addi", "bn.addm",
                             "bn.sub", "bn.subb", "bn.subi", "bn.subm"),
        "移位/选择 (shift)": ("bn.rshi", "bn.sel"),
        "逻辑 (logic)": ("bn.and", "bn.or", "bn.xor"),
        "访存 (mem)": ("bn.lid", "bn.sid", "bn.mov"),
        "控制流 (ctrl)": ("jal", "jalr", "beq", "bne", "loop", "loopi", "ecall"),
        "RISC-V 其他": ("addi", "lui", "andi", "xori", "csrrw", "csrrs"),
        "WSR": ("bn.wsrr", "bn.wsrw"),
    }

    for t in tests:
        freqs = t.get("instr_freq", [])
        if not freqs:
            continue

        name = _op(t["op_key"])
        instr_map = {n: c for n, c in freqs}
        total = sum(instr_map.values())

        cat_totals = {}
        for cat, members in categories.items():
            cat_totals[cat] = sum(instr_map.get(m, 0) for m in members)

        classified = set()
        for members in categories.values():
            classified.update(members)
        unclassified = sum(v for k, v in instr_map.items() if k not in classified)
        if unclassified > 0:
            cat_totals["其他"] = unclassified

        print(f"\n  {C_HEAD}▸ {name}{C_END}  ({_fmt(total)} instrs)")
        max_cat = max(cat_totals.values()) if cat_totals else 1
        for cat, cnt in sorted(cat_totals.items(), key=lambda x: -x[1]):
            pct = cnt * 100.0 / total if total else 0
            bar = _bar(cnt / max_cat)
            print(f"    {_rpad(cat, 22)}{cnt:>10,}  {pct:>5.1f}%  {bar}")


def print_stall_analysis(tests: list):
    """[5] Stall 分析"""
    print(f"\n{C_BOLD}[5] Stall 分析{C_END}")
    print(SEP_THIN)

    print(f"  {'操作':<28} {'Stall Cycles':>14} {'Stall%':>8}  {'评级'}")
    print(f"  {'─' * 28} {'─' * 14} {'─' * 8}  {'─' * 16}")

    for t in tests:
        name = _op(t["op_key"])
        pct = t["stall_pct"]
        if pct < 5:
            rating = f"{C_OK}优秀 (<5%){C_END}"
        elif pct < 10:
            rating = f"{C_WARN}一般 (5-10%){C_END}"
        else:
            rating = f"{C_FAIL}偏高 (>10%){C_END}"
        print(f"  {name:<28} {t['stalls']:>14,} {pct:>7.1f}%  {rating}")

    print(f"\n  {C_DIM}说明：Stall 表示流水线空闲周期。低 stall = 乘法器/功能单元利用率高。{C_END}")
    print(f"  {C_DIM}ML-KEM 的 stall 主要来自 Keccak 的顺序数据依赖。{C_END}")
    print(f"  {C_DIM}P-256 的 bn.mulqacc 流水线效率高，stall 通常 < 5%。{C_END}")


def print_db_history(db_path: str):
    """[6] DB 历史趋势（按操作分组）"""
    per_op = db_read_history(db_path)

    print(f"\n{C_BOLD}[6] 数据库历史{C_END}")
    print(SEP_THIN)

    if not per_op:
        print(f"  {C_DIM}DB 中无有效记录。运行 `./run_py_kyber768_test.sh` 后再查看。{C_END}")
        return

    for key in ["hash_test", "mlkem768_keypair", "mlkem768_encap", "mlkem768_decap", "p256_ecdh"]:  
        runs = per_op.get(key, [])

        name = _op(key)
        if not runs:
            print(f"  {C_DIM}▸ {name:<28}  无记录{C_END}")
            continue

        print(f"  {C_HEAD}▸ {_rpad(name, 28)}{C_END}({len(runs)} 次运行)")
        for idx, (ts, cyc) in enumerate(runs):
            t_str = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
            if idx == 0:
                print(f"    #{idx + 1:<2} {t_str}  {_fmt(cyc):>14}")
            else:
                prev = runs[idx - 1][1]
                delta = _delta_pct(cyc, prev)
                print(f"    #{idx + 1:<2} {t_str}  {_fmt(cyc):>14}  {delta}")



def print_latex_table(tests: list):
    """[7] LaTeX 表格"""
    print(f"\n{C_BOLD}[7] LaTeX 表格{C_END}")
    print(SEP_THIN)

    print(r"\begin{table}[h]")
    print(r"\centering")
    print(r"\caption{OTBN Benchmark Results (@100 MHz)}")
    print(r"\begin{tabular}{lrrr}")
    print(r"\toprule")
    print(r"Operation & Instructions & Cycles & Time ($\mu$s) \\")
    print(r"\midrule")

    for t in tests:
        name = _op(t["op_key"])
        cyc = t["cycles"]
        us  = cyc / 100.0 if cyc else 0
        print(f"{name} & {t['instructions']:,} & {cyc:,} & {us:,.0f} \\\\")

    kem = [t for t in tests if "mlkem" in t["op_key"]]
    if kem:
        total_instr = sum(t["instructions"] for t in kem)
        total_cyc   = sum(t["cycles"] for t in kem)
        print(r"\midrule")
        print(f"KEM Total & {total_instr:,} & {total_cyc:,} & {total_cyc / 100:,.0f} \\\\")

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")

def print_optimization_tips(tests: list):
    """[💡] 优化建议"""
    print(f"\n{C_BOLD}[💡] 优化建议{C_END}")
    print(SEP_THIN)

    for t in tests:
        freqs = t.get("instr_freq", [])
        if not freqs:
            continue
        instr_map = {n: c for n, c in freqs}
        total = sum(instr_map.values())
        name = _op(t["op_key"])

        mulqacc = sum(instr_map.get(k, 0) for k in
                      ("bn.mulqacc", "bn.mulqacc.wo", "bn.mulqacc.so"))
        rshi = instr_map.get("bn.rshi", 0)

        tips = []
        if total > 0:
            if mulqacc / total > 0.30:
                tips.append(f"乘法器负载重 ({mulqacc / total * 100:.0f}%)，优化空间有限")
            if rshi / total > 0.10:
                tips.append(f"bn.rshi 占 {rshi / total * 100:.0f}% — 考虑减少位操作")

        if "decap" in t["op_key"]:
            tips.append("Decap 含完整 re-encapsulation 路径，是最大的优化目标")
        if "keypair" in t["op_key"]:
            tips.append("Keypair 是 KEM 协议入口，优化直接影响握手延迟")

        if t["stall_pct"] > 8:
            tips.append(f"Stall {t['stall_pct']:.1f}% 偏高 — 可尝试指令交错隐藏延迟")

        if tips:
            print(f"\n  {C_HEAD}▸ {_rpad(name, 28)}{C_END}")
            for tip in tips:
                print(f"    • {tip}")

    if not any(t.get("instr_freq") for t in tests):
        print(f"  {C_DIM}暂无足够的指令级数据来生成建议。{C_END}")


# ══════════════════════════════════════════════════════════════════════════
# 4) 版本对比
# ══════════════════════════════════════════════════════════════════════════

def compare_versions(db_a: str, db_b: str):
    hist_a = db_read_history(db_a)
    hist_b = db_read_history(db_b)

    if not hist_a and not hist_b:
        print(f"{C_FAIL}两个数据库都无有效记录{C_END}")
        return

    all_ops = sorted(set(list(hist_a.keys()) + list(hist_b.keys())))

    print(f"\n{C_BOLD}版本对比{C_END}")
    print(f"  {C_DIM}A: {os.path.basename(db_a)}{C_END}")
    print(f"  {C_DIM}B: {os.path.basename(db_b)}{C_END}")
    print(SEP_THICK)

    print(f"\n  {'操作':<28} {'A Cycles':>14} {'B Cycles':>14} {'变化':>10}")
    print(f"  {'─' * 28} {'─' * 14} {'─' * 14} {'─' * 10}")

    for op in all_ops:
        runs_a = hist_a.get(op, [])
        runs_b = hist_b.get(op, [])
        va = runs_a[-1][1] if runs_a else 0
        vb = runs_b[-1][1] if runs_b else 0
        name = _op(op)
        if va and vb:
            d = _delta_pct(vb, va)
            print(f"  {name:<28} {va:>14,} {vb:>14,} {d:>10}")
        elif va:
            print(f"  {name:<28} {va:>14,} {'—':>14} {'仅 A':>10}")
        else:
            print(f"  {name:<28} {'—':>14} {vb:>14,} {'仅 B':>10}")

    print(f"\n{C_DIM}提示: 如需函数级对比，请分别分析两个版本的 log 文件。{C_END}")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Benchmark 分析工具（Log 驱动）")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite 数据库路径")
    parser.add_argument("--log", default="", help="指定 log 文件")
    parser.add_argument("--all-logs", action="store_true", help="分析所有 log")
    parser.add_argument("--compare", nargs=2, metavar=("DB_A", "DB_B"),
                        help="对比两个数据库")
    parser.add_argument("--no-latex", action="store_true", help="不输出 LaTeX")
    args = parser.parse_args()

    print(BANNER)
    print(f"  生成时间 : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  数据库   : {args.db}")

    # ── 版本对比模式 ──
    if args.compare:
        compare_versions(args.compare[0], args.compare[1])
        print(f"\n{SEP_THICK}")
        print(f"  {C_OK}对比完成{C_END}")
        return 0

    # ── 解析 log ──
    log_path = ""
    if args.log:
        log_path = args.log
    else:
        log_path = _latest_log(DEFAULT_LOG_DIR)

    log_tests = []
    if log_path and os.path.isfile(log_path):
        log_tests = parse_log(log_path)
        print(f"  日志文件 : {os.path.basename(log_path)}")
    else:
        print(f"  {C_WARN}未找到日志文件{C_END}")

    if not log_tests:
        print(f"\n  {C_FAIL}错误: 无法解析任何测试数据。请确保 log 文件存在且格式正确。{C_END}")
        return 1

    # ── DB 数据（辅助） ──
    db_tests = db_read_latest(args.db)

    # ── 输出报告 ──
    print_overview(log_tests)
    print_top_instructions(log_tests)
    print_hot_functions(log_tests)
    print_instruction_breakdown(log_tests)
    print_stall_analysis(log_tests)
    print_db_history(args.db)

    if not args.no_latex:
        print_latex_table(log_tests)

    print_optimization_tips(log_tests)

    # ── 退出 ──
    all_pass = all(t.get("pass", True) for t in log_tests)
    if all_pass:
        print(f"\n{SEP_THICK}")
        print(f"  {C_OK}所有测试通过 ✓{C_END}")
    else:
        print(f"\n{SEP_THICK}")
        print(f"  {C_FAIL}存在失败的测试 ✗{C_END}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
