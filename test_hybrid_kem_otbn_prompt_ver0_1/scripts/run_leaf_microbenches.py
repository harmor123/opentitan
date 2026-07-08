#!/usr/bin/env python3
"""Run standalone OTBN leaf microbenchmarks with the OTBN ISS."""

import argparse
import csv
import re
import shutil
import subprocess
import sys
from pathlib import Path


STANDALONE_TARGET = "//hw/ip/otbn/dv/otbnsim:standalone"
STATS_RE = re.compile(r"OTBN executed (\d+) instructions in (\d+) cycles\.")

BENCHMARKS = [
    {
        "label": "P256_FIELD_MUL_REDUCE",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_p256_field_mul",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_p256_3",
        "repeat": 32,
    },
    {
        "label": "P256_FIELD_SQR",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_p256_field_sqr",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_p256_3",
        "repeat": 32,
    },
    {
        "label": "P256_FIELD_ADD",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_p256_field_add",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_p256_1",
        "repeat": 32,
    },
    {
        "label": "P256_FIELD_SUB",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_p256_field_sub",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_p256_1",
        "repeat": 32,
    },
    {
        "label": "P256_FIELD_INV",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_p256_field_inv",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_p256_1",
        "repeat": 1,
    },
    {
        "label": "MLKEM_NTT",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_mlkem_ntt",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_mlkem",
        "repeat": 1,
    },
    {
        "label": "MLKEM_INTT",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_mlkem_intt",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_mlkem",
        "repeat": 1,
    },
    {
        "label": "MLKEM_BASEMUL",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_mlkem_basemul",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_mlkem",
        "repeat": 1,
    },
    {
        "label": "KECCAK_F1600",
        "target": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_keccak_f1600",
        "empty": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/microbench:bench_empty_keccak",
        "repeat": 1,
    },
]


def repo_root_from_script():
    return Path(__file__).resolve().parents[2]


def run_cmd(cmd, cwd, check=True):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        raise RuntimeError(f"command failed: {' '.join(str(c) for c in cmd)}")
    return proc


def find_standalone_bin(repo_root):
    out = run_cmd(["bazel", "cquery", "--output=files", STANDALONE_TARGET], repo_root).stdout
    matches = [
        line.strip()
        for line in out.splitlines()
        if line.strip().endswith("/standalone") or line.strip().endswith("standalone")
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one standalone simulator, found {len(matches)}: {matches}")
    standalone = repo_root / matches[0]
    if not standalone.exists():
        raise FileNotFoundError(f"standalone simulator was not found: {standalone}")
    return standalone


def find_elf(repo_root, target):
    out = run_cmd(
        ["bazel", "cquery", "--output=files", "--output_groups=elf", target],
        repo_root,
    ).stdout
    matches = [line.strip() for line in out.splitlines() if line.strip().endswith(".elf")]
    if len(matches) != 1:
        raise RuntimeError(f"expected one ELF for {target}, found {len(matches)}: {matches}")
    elf = repo_root / matches[0]
    if not elf.exists():
        raise FileNotFoundError(f"ELF reported by Bazel was not found: {elf}")
    return elf


def run_iss_stats(repo_root, standalone, elf):
    out = run_cmd(
        [str(standalone), "--bnmulv_version_id=0", "--dump-stats", "-", str(elf)],
        repo_root,
    ).stdout
    match = STATS_RE.search(out)
    if not match:
        raise RuntimeError(f"could not parse simulator stats for {elf}")
    return int(match.group(1)), int(match.group(2))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(description="Run standalone OTBN leaf microbenchmarks.")
    parser.add_argument("--input", default="", help="reserved for future imported result logs")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("test_hybrid_kem_otbn_prompt_ver0_1/results/microbench_leaf_profile"),
        help="output directory",
    )
    parser.add_argument("--no-build", action="store_true", help="reuse existing Bazel outputs")
    return parser.parse_args()


def main():
    args = parse_args()
    repo_root = repo_root_from_script()
    out_dir = repo_root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if shutil.which("bazel") is None:
        raise RuntimeError("bazel was not found in PATH")

    bench_targets = sorted({b["target"] for b in BENCHMARKS} | {b["empty"] for b in BENCHMARKS})
    if not args.no_build:
        proc = run_cmd(["bazel", "build", STANDALONE_TARGET], repo_root, check=False)
        if proc.returncode == 0:
            proc = run_cmd(["bazel", "build", "--output_groups=elf"] + bench_targets, repo_root, check=False)
        if proc.returncode != 0:
            (out_dir / "microbench_build_error.log").write_text(proc.stdout)
            print(proc.stdout, file=sys.stderr)
            raise RuntimeError("microbenchmark build failed; see microbench_build_error.log")

    standalone = find_standalone_bin(repo_root)
    elf_cache = {}
    stat_cache = {}
    rows = []
    missing_rows = []

    for bench in BENCHMARKS:
        label = bench["label"]
        target = bench["target"]
        empty_target = bench["empty"]
        repeat = bench["repeat"]
        try:
            for needed in (target, empty_target):
                if needed not in elf_cache:
                    elf_cache[needed] = find_elf(repo_root, needed)
                if needed not in stat_cache:
                    stat_cache[needed] = run_iss_stats(repo_root, standalone, elf_cache[needed])
            total_instr, total_cycles = stat_cache[target]
            empty_instr, empty_cycles = stat_cache[empty_target]
            net_cycles = total_cycles - empty_cycles
            net_instr = total_instr - empty_instr
            rows.append(
                {
                    "label": label,
                    "benchmark_target": target,
                    "repeat_count": repeat,
                    "total_cycles": total_cycles,
                    "empty_loop_cycles": empty_cycles,
                    "cycles_per_call": f"{net_cycles / repeat:.3f}",
                    "total_instr": total_instr,
                    "instr_per_call": f"{net_instr / repeat:.3f}",
                    "status": "measured",
                }
            )
            print(f"HKE_PROFILE_MICROBENCH,{label},cycles_per_call={net_cycles / repeat:.3f}")
        except Exception as exc:
            rows.append(
                {
                    "label": label,
                    "benchmark_target": target,
                    "repeat_count": repeat,
                    "total_cycles": "",
                    "empty_loop_cycles": "",
                    "cycles_per_call": "",
                    "total_instr": "",
                    "instr_per_call": "",
                    "status": "not_available",
                }
            )
            missing_rows.append(
                {
                    "label": label,
                    "status": "not_available",
                    "reason": str(exc),
                    "next_action": "fix or add standalone OTBN microbenchmark target",
                }
            )

    write_csv(
        out_dir / "microbench_leaf_summary.csv",
        rows,
        [
            "label",
            "benchmark_target",
            "repeat_count",
            "total_cycles",
            "empty_loop_cycles",
            "cycles_per_call",
            "total_instr",
            "instr_per_call",
            "status",
        ],
    )
    write_csv(
        out_dir / "microbench_missing.csv",
        missing_rows,
        ["label", "status", "reason", "next_action"],
    )
    print(f"results: {out_dir}")


if __name__ == "__main__":
    main()
