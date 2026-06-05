#!/usr/bin/env python3
"""Hybrid KEM 性能测试主入口：多版本 ISS 基准测试 & 分析。

用法:
  python main.py run                         一键运行所有版本
  python main.py run --tests sha3            只跑指定模块
  python main.py report                      最新横向对比报告
  python main.py history --version ver0
  python main.py delete --id 5
  python main.py plot
"""

import argparse
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

from collector import parse_iss_output, add_sizes_to_entry
from db_manager import DBManager
from analyzer import report_latest, report_history

C_OK = "\033[92m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"
OT_ROOT = SCRIPT_DIR.parent
OTBN_SIM = OT_ROOT / "hw" / "ip" / "otbn" / "dv" / "otbnsim" / "standalone.py"


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
    result = subprocess.run(
        ["./bazelisk.sh", "build", "--cache_test_results=no", target],
        cwd=str(OT_ROOT), capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        logger.error("bazel build 失败: %s", target)
        if result.stderr:
            logger.error(result.stderr[-500:])
        return None
    t = target.lstrip("/")
    pkg, _, name = t.partition(":")
    elf = OT_ROOT / "bazel-bin" / pkg / (name + ".elf")
    if elf.exists():
        return elf
    logger.error("ELF 不存在: %s", elf)
    return None


def run_iss_sim(elf: Path, test_name: str, timeout: int = 120,
                bnmulv_ver: str = "") -> dict | None:
    """运行 standalone.py --verbose 一次，返回 metrics。"""
    if not OTBN_SIM.exists():
        logger.warning("standalone.py 不存在: %s", OTBN_SIM)
        return None
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(OT_ROOT))
    cmd = ["python3", str(OTBN_SIM), "--verbose"]
    if bnmulv_ver:
        cmd += ["--bnmulv_version_id", bnmulv_ver]
    cmd.append(str(elf))
    try:
        result = subprocess.run(
            cmd,
            cwd=str(OT_ROOT), capture_output=True, text=True, timeout=timeout,
            env=env,
        )
        output = result.stdout + "\n" + result.stderr
        metrics = parse_iss_output(output, test_name)
        add_sizes_to_entry(metrics, str(elf))
        passed = result.returncode == 0
        if passed:
            logger.info("[%s] cycles=%s  ins=%s  imem=%s  dmem=%s",
                        test_name, metrics.get("cycles", "?"),
                        metrics.get("instructions", "?"),
                        metrics.get("imem", "?"), metrics.get("dmem", "?"))
        else:
            logger.warning("[%s] 非零退出", test_name)
        metrics["passed"] = passed
        metrics["raw_output"] = output
        return metrics
    except subprocess.TimeoutExpired:
        logger.error("[%s] 超时", test_name)
    except Exception as e:
        logger.error("[%s] 异常: %s", test_name, e)
    return None


def run_single_test(ver: dict, test_name: str, timeout: int) -> dict | None:
    targets = ver.get("targets", {})
    target = targets.get(test_name, "")
    if not target:
        logger.warning("[%s] 未知测试: %s", ver["name"], test_name)
        return None
    elf = bazel_build(target)
    if elf is None:
        return None
    # ver2 需要 BNMULV_VER2
    bnv = "2" if ver["name"] == "ver2" else ""
    return run_iss_sim(elf, test_name, timeout, bnmulv_ver=bnv)


def cmd_run(config: dict, version_filter: str = "", test_filter: str = "",
           db_path: str = ""):
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
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"bench_{ver_name}_{ts}.log"
        run_id = db.insert_run(ver_name, str(log_file))
        all_logs: list[str] = []

        for test_name in ver.get("tests", []):
            if t_allow and test_name not in t_allow:
                continue
            metrics = run_single_test(ver, test_name, timeout)
            if metrics is None:
                logger.warning("[%s] %s: 无结果，跳过", ver_name, test_name)
                continue
            all_logs.append(f"\n>>> [{test_name}] {ver_name}\n{metrics.get('raw_output', '')}")

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
            )

        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(all_logs))
        print(f"  {ver_name}: {C_OK}DONE{C_END}  (log: {log_file})")

    print(f"\n{C_BOLD}═══ 报告 ═══{C_END}")
    print(report_latest(db))


def cmd_report(config: dict, output: str = "", db_path: str = ""):
    import re
    import re
    db = DBManager(_resolve_db(config, db_path))
    report = report_latest(db)
    print(report)
    out_dir = SCRIPT_DIR / "report"
    out_dir.mkdir(parents=True, exist_ok=True)
    if output:
        out_path = out_dir / Path(output).name
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"report_{ts}.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(re.sub(r"\033\[[0-9;]*m", "", report))
    logger.info("报告已保存: %s", out_path)


def cmd_history(config: dict, version: str, db_path: str = ""):
    db = DBManager(_resolve_db(config, db_path))
    print(report_history(db, version))


def cmd_delete(config: dict, run_id: int = 0, version: str = "", before: str = "",
               db_path: str = ""):
    db = DBManager(_resolve_db(config, db_path))
    if run_id:
        count = db.delete_run(run_id)
        print(f"删除记录 ID={run_id}: {count} 条")
    elif version:
        count = db.delete_runs_by_version(version, before or None)
        print(f"删除 {version}: {count} 条")
    else:
        print("请指定 --id 或 --version")



def main():
    parser = argparse.ArgumentParser(description="Hybrid KEM ISS 性能测试框架")
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="运行性能测试")
    p_run.add_argument("--config", default="")
    p_run.add_argument("--db", default="", help="数据库路径 (默认: db/perf_results.db)")
    p_run.add_argument("--versions", "-V", default="", help="版本过滤 (ver0,ver2)")
    p_run.add_argument("--tests", "-t", default="", help="测试过滤 (sha3,mlkem_keypair)")

    p_report = sub.add_parser("report", help="最新横向对比报告")
    p_report.add_argument("--config", default="")
    p_report.add_argument("--db", default="")
    p_report.add_argument("--output", "-o", default="", help="保存到文件")

    p_hist = sub.add_parser("history", help="单版本历史趋势")
    p_hist.add_argument("--version", "-v", required=True)
    p_hist.add_argument("--db", default="")

    p_del = sub.add_parser("delete", help="删除记录")
    p_del.add_argument("--id", type=int, default=0)
    p_del.add_argument("--version", "-v", default="")
    p_del.add_argument("--before", default="")
    p_del.add_argument("--db", default="")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    config = load_config(getattr(args, "config", "") or "")

    if args.command == "run":
        cmd_run(config, getattr(args, "versions", ""), getattr(args, "tests", ""),
                getattr(args, "db", ""))
    elif args.command == "report":
        cmd_report(config, getattr(args, "output", ""), getattr(args, "db", ""))
    elif args.command == "history":
        cmd_history(config, args.version, getattr(args, "db", ""))
    elif args.command == "delete":
        cmd_delete(config, args.id, args.version, getattr(args, "before", ""),
                   getattr(args, "db", ""))


if __name__ == "__main__":
    main()
