#!/usr/bin/env python3
"""Hybrid KEM 性能测试。使用 StandaloneSim API 直接获取全量指标。"""

import argparse
import logging
import os
import re
import sys
import json
from datetime import datetime
from pathlib import Path

import yaml

OT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(OT_ROOT))

# 自动补全 __init__.py
for _d in [
    "hw", "hw/ip", "hw/ip/otbn", "hw/ip/otbn/dv",
    "hw/ip/otbn/dv/otbnsim", "hw/ip/otbn/dv/otbnsim/sim",
]:
    init = OT_ROOT / _d / "__init__.py"
    if not init.exists():
        init.touch()


from db_manager import DBManager
from analyzer import report_latest, report_history

C_OK = "\033[92m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"
# ver2 指令集 YAML
BNMULV_VER2_YAML = OT_ROOT / "hw/ip/otbn/data/bignum-insns-ver2.yml"

_RE_INST_CYC = re.compile(r"OTBN executed ([\d,]+) instructions in ([\d,]+) cycles")
_RE_STALL = re.compile(r"stalled for ([\d,]+) cycles \(([0-9.]+) percent\)")
_RE_INSTR_SEC = re.compile(
    r"Instruction frequencies\s*\n[- ]+\ninstruction\s+count\n[- ]+\n(.*?)(?=\n\n|\n\S|\Z)",
    re.DOTALL,
)
_RE_FUNC = re.compile(r"^Function\s+0x[0-9a-f]+\s+\(([^)]+)\)", re.MULTILINE)
_RE_FUNC_COUNT = re.compile(r"\*\s*(\d+)\s+times")

INSTR_CATEGORIES = {
    "BN MAC": ("bn.mulqacc", "bn.mulqacc.so", "bn.mulqacc.wo",
               "bn.mulqacc.z", "bn.mulqacc.so.z", "bn.mulqacc.wo.z",
               "bn.mulqacc.so.wo", "bn.mulqacc.so.wo.z"),
    "BN ALU": ("bn.add", "bn.addc", "bn.addi", "bn.addm",
               "bn.sub", "bn.subb", "bn.subi", "bn.subm",
               "bn.and", "bn.or", "bn.xor", "bn.not", "bn.cmp", "bn.cmpb"),
    "BN Shift": ("bn.rshi", "bn.sel", "bn.shv", "bn.pack", "bn.unpk",
                 "bn.trn", "bn.trn1", "bn.trn2"),
    "BN Vector": ("bn.addv", "bn.addvm", "bn.subv", "bn.subvm",
                  "bn.mulv", "bn.mulv.l", "bn.mulvl", "bn.mulvm", "bn.mulvml"),
    "BN Mem": ("bn.lid", "bn.sid", "bn.mov", "bn.movr", "bn.wsrr", "bn.wsrw"),
    "RISC-V ALU": ("add", "addi", "sub", "and", "andi", "or", "ori",
                   "xor", "xori", "sll", "slli", "srl", "srli", "sra", "srai", "lui"),
    "RISC-V Ctrl": ("beq", "bne", "jal", "jalr", "loop", "loopi", "ecall"),
    "RISC-V CSR": ("csrrs", "csrrw"),
    "RISC-V Mem": ("lw", "sw"),
    "RISC-V Other": ("li", "la", "mv", "ret", "nop", "unimp"),
}


def _resolve_db(config: dict, db_arg: str = "") -> str:
    if db_arg:
        p = Path(db_arg)
    else:
        cfg_db = config.get("database", "db/perf_results.db")
        p = Path(cfg_db)
        if not p.is_absolute():
            p = SCRIPT_DIR / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return str(p)


def load_config(path: str = "") -> dict:
    p = Path(path) if path else DEFAULT_CONFIG
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def bazel_build(target: str) -> Path | None:
    result = subprocess = __import__("subprocess")
    r = subprocess.run(
        ["./bazelisk.sh", "build", "--cache_test_results=no", target],
        cwd=str(OT_ROOT), capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        logger.error("bazel build 失败: %s", target)
        return None
    t = target.lstrip("/")
    pkg, _, name = t.partition(":")
    elf = OT_ROOT / "bazel-bin" / pkg / (name + ".elf")
    return elf if elf.exists() else None


def _get_elf_sizes(elf_path: str) -> dict:
    import subprocess, shutil
    sizes = {"imem": 0, "dmem": 0}
    tool = None
    for name in ["riscv32-unknown-elf-readelf", "readelf"]:
        if shutil.which(name):
            tool = name; break
    if not tool:
        return sizes
    try:
        out = subprocess.check_output([tool, "-S", elf_path], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 7 or not parts[1].rstrip("]").isdigit():
                continue
            name = parts[2]
            try:
                size = int(parts[6], 16)
            except ValueError:
                continue
            if name == ".text":
                sizes["imem"] = size
            elif name in (".data", ".bss"):
                sizes["dmem"] += size
    except Exception:
        pass
    return sizes


def run_iss(elf_path: str, test_name: str, bnmulv: str = "") -> dict | None:
    """直接调用 StandaloneSim API，获取 ExecutionStatAnalyzer 全量指标。"""
    import importlib, sys
    if bnmulv:
        os.environ["BNMULV_VER"] = bnmulv
    else:
        os.environ.pop("BNMULV_VER", None)
    # 清除缓存，否则切换版本时 decode 模块不变
    for mod in list(sys.modules):
        if "otbn" in mod or "otbnsim" in mod:
            sys.modules.pop(mod, None)
    from hw.ip.otbn.dv.otbnsim.sim.standalonesim import StandaloneSim
    from hw.ip.otbn.dv.otbnsim.sim.load_elf import load_elf
    from hw.ip.otbn.dv.otbnsim.sim.stats import ExecutionStatAnalyzer
    sim = StandaloneSim()

    try:
        exp_end = load_elf(sim, elf_path)
    except Exception as e:
        logger.error("[%s] ELF 加载失败: %s", test_name, e)
        return None

    sim.start(True)
    sim.run(False, None)


    raw = {"operation": test_name, "imem": 0, "dmem": 0,
           "instr_freqs": {}, "instr_categories": {}, "func_calls": {}}
    raw.update(_get_elf_sizes(elf_path))

    dump_text = ""
    try:
        analyzer = ExecutionStatAnalyzer(sim.stats, elf_path)
        dump_text = analyzer.dump() or ""
        if dump_text:
            _parse_dump(dump_text, raw)
    except Exception as e:
        logger.warning("[%s] stat analyzer 失败: %s", test_name, e)
        if sim.stats:
            raw["instructions"] = getattr(sim.stats, "insn_count", 0)
            raw["stalls"] = getattr(sim.stats, "stall_count", 0)
            raw["cycles"] = raw["instructions"] + raw["stalls"]

    raw["dump_text"] = dump_text
    logger.info("[%s] cycles=%s  ins=%s  stalls=%s  imem=%s  dmem=%s",
                test_name, raw.get("cycles", "?"), raw.get("instructions", "?"),
                raw.get("stalls", "?"), raw.get("imem", "?"), raw.get("dmem", "?"))
    return raw


def _parse_dump(text: str, entry: dict):
    m = _RE_INST_CYC.search(text)
    if m:
        entry["instructions"] = int(m.group(1).replace(",", ""))
        entry["cycles"] = int(m.group(2).replace(",", ""))
    m = _RE_STALL.search(text)
    if m:
        entry["stalls"] = int(m.group(1).replace(",", ""))
        entry["stall_pct"] = float(m.group(2))

    # 指令频次——从 "Instruction frequencies" 到下一个空行
    idx = text.find("Instruction frequencies")
    if idx >= 0:
        block = text[idx:]
        lines_iter = iter(block.split("\n"))
        freqs = {}
        in_table = False
        for line in lines_iter:
            s = line.strip()
            if "instruction" in s.lower() and "count" in s.lower():
                in_table = True
                # skip dashes line
                try: next(lines_iter)
                except StopIteration: break
                continue
            if in_table:
                if not s:  # blank line = end
                    break
                parts = s.split()
                if len(parts) >= 2:
                    try:
                        freqs[parts[0]] = int(parts[-1].replace(",", ""))
                    except ValueError:
                        pass
        if freqs:
            entry["instr_freqs"] = freqs
        # 归类
        cats = {}
        unmapped = set(freqs.keys())
        for cat, members in INSTR_CATEGORIES.items():
            total = sum(freqs.get(m, 0) for m in members)
            if total:
                cats[cat] = total
                unmapped -= set(members)
        if unmapped:
            cats["Other"] = sum(freqs[k] for k in unmapped)
        entry["instr_categories"] = cats

    # 函数调用热点
    func_start = text.find("Function call statistics")
    if func_start > 0:
        func_text = text[func_start:]
        funcs = {}
        for fm in re.finditer(
            r"^Function 0x[0-9a-f]+ \(([^)]+)\)", func_text, re.MULTILINE
        ):
            fname = fm.group(1).strip()
            if "\n" in fname or len(fname) > 80:
                continue
            after = func_text[fm.end():fm.end() + 800]
            total = sum(int(m.group(1)) for m in re.finditer(r"\*\s*(\d+)\s+times", after))
            if total > 0:
                funcs[fname] = total
        entry["func_calls"] = dict(sorted(funcs.items(), key=lambda x: -x[1])[:10])


def run_single_test(ver: dict, test_name: str, timeout: int = 120) -> dict | None:
    targets = ver.get("targets", {})
    target = targets.get(test_name, "")
    if not target:
        logger.warning("[%s] 未知测试: %s", ver["name"], test_name)
        return None
    elf = bazel_build(target)
    if elf is None:
        return None
    bnv = "2" if ver["name"] == "ver2" else ""
    return run_iss(str(elf), test_name, bnmulv=bnv)


def cmd_run(config, version_filter="", test_filter="", db_path=""):
    timeout = config.get("timeout", 120)
    db = DBManager(_resolve_db(config, db_path))
    log_dir = SCRIPT_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    v_allow = set(v.strip() for v in version_filter.split(",") if v.strip()) if version_filter else None
    t_allow = set(t.strip() for t in test_filter.split(",") if t.strip()) if test_filter else None

    for ver in config["versions"]:
        ver_name = ver["name"]
        if v_allow and ver_name not in v_allow:
            continue
        print(f"\n{C_BOLD}═══ {ver_name} ({ver['label']}) ═══{C_END}")
        run_id = db.insert_run(ver_name, "")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"bench_{ver_name}_{ts}.log"
        all_dumps: list[str] = []

        for test_name in ver.get("tests", []):
            if t_allow and test_name not in t_allow:
                continue
            metrics = run_single_test(ver, test_name, timeout)
            if metrics is None:
                logger.warning("[%s] %s: 无结果，跳过", ver_name, test_name)
                continue
            all_dumps.append(f">>> [{test_name}] {ver_name}\n{metrics.get('dump_text', '')}")
            db.insert_metric(
                run_id, test_name,
                cycles=metrics.get("cycles") or 0,
                instructions=metrics.get("instructions") or 0,
                stalls=metrics.get("stalls") or 0,
                stall_pct=metrics.get("stall_pct") or 0.0,
                imem=metrics.get("imem") or 0,
                dmem=metrics.get("dmem") or 0,
                instr_categories=metrics.get("instr_categories", {}),
                instr_freqs=metrics.get("instr_freqs", {}),
                func_calls=metrics.get("func_calls", {}),
            )
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(all_dumps))
        print(f"  {ver_name}: {C_OK}DONE{C_END}  (log: {log_file})")

    print(f"\n{C_BOLD}═══ 报告 ═══{C_END}")
    print(report_latest(db))


def cmd_report(config, output="", db_path=""):
    import re as _re
    db = DBManager(_resolve_db(config, db_path))
    report = report_latest(db)
    print(report)
    out_dir = SCRIPT_DIR / "report"
    out_dir.mkdir(parents=True, exist_ok=True)
    if output:
        out_path = out_dir / Path(output).name
    else:
        out_path = out_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(_re.sub(r"\033\[[0-9;]*m", "", report))
    logger.info("报告已保存: %s", out_path)


def cmd_history(config, version, db_path=""):
    db = DBManager(_resolve_db(config, db_path))
    print(report_history(db, version))


def cmd_delete(config, run_id=0, version="", before="", db_path=""):
    db = DBManager(_resolve_db(config, db_path))
    if run_id:
        print(f"删除记录 ID={run_id}: {db.delete_run(run_id)} 条")
    elif version:
        print(f"删除 {version}: {db.delete_runs_by_version(version, before or None)} 条")
    else:
        print("请指定 --id 或 --version")


def main():
    parser = argparse.ArgumentParser(description="Hybrid KEM 性能测试框架")
    sub = parser.add_subparsers(dest="command")
    p_run = sub.add_parser("run"); p_run.add_argument("--config", default="")
    p_run.add_argument("--db", default=""); p_run.add_argument("--versions", "-V", default="")
    p_run.add_argument("--tests", "-t", default="")
    p_report = sub.add_parser("report"); p_report.add_argument("--config", default="")
    p_report.add_argument("--db", default=""); p_report.add_argument("--output", "-o", default="")
    p_hist = sub.add_parser("history"); p_hist.add_argument("--version", "-v", required=True)
    p_hist.add_argument("--db", default="")
    p_del = sub.add_parser("delete"); p_del.add_argument("--id", type=int, default=0)
    p_del.add_argument("--version", "-v", default=""); p_del.add_argument("--before", default="")
    p_del.add_argument("--db", default="")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help(); return
    config = load_config(getattr(args, "config", "") or "")
    if args.command == "run":
        cmd_run(config, getattr(args, "versions", ""), getattr(args, "tests", ""), getattr(args, "db", ""))
    elif args.command == "report":
        cmd_report(config, getattr(args, "output", ""), getattr(args, "db", ""))
    elif args.command == "history":
        cmd_history(config, args.version, getattr(args, "db", ""))
    elif args.command == "delete":
        cmd_delete(config, args.id, args.version, getattr(args, "before", ""), getattr(args, "db", ""))


if __name__ == "__main__":
    main()
