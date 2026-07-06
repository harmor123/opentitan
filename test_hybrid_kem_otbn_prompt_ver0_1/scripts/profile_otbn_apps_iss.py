#!/usr/bin/env python3
"""Profile baseline OTBN apps and leaf kernels with the OTBN ISS.

Outputs are intentionally separated:
  * otbn_app_profile_*.csv: whole-application ISS counts.
  * otbn_leaf_profile_*.csv: internal leaf-kernel counts from ISS trace PCs.

Leaf profiling is post-processing only. It does not insert instructions into
OTBN assembly and does not modify cryptographic behavior.
"""

import argparse
import csv
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path


APP_TARGETS = {
    "p256_keygen": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:p256_keygen_test",
    "p256_ecdh": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:p256_ecdh_test",
    "mlkem768_keypair": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:mlkem768_keypair_test",
    "mlkem768_encap": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:mlkem768_encap_test",
    "mlkem768_decap": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:mlkem768_decap_test",
    "hkdf_sha3": "//test_hybrid_kem_otbn_prompt_ver0_1/otbn/test:hkdf_test",
}

LEAF_LABELS = {
    "MLKEM_NTT": ["ntt"],
    "MLKEM_INTT": ["intt"],
    "MLKEM_BASEMUL": ["basemul", "basemul_acc"],
    "MLKEM_COEFF_REDUCE": ["poly_reduce"],
    "MLKEM_POLY_ADD_SUB": ["poly_add", "poly_sub"],
    "MLKEM_REJ_SAMPLING": ["_rej_sample_loop"],
    "MLKEM_CBD_SAMPLING": ["cbd2", "cbd3"],
    "MLKEM_MATRIX_EXPAND": ["poly_gen_matrix"],
    "MLKEM_PACK": ["pack_pk", "pack_sk", "pack_ciphertext"],
    "MLKEM_UNPACK": ["unpack_pk", "unpack_sk", "unpack_ciphertext"],
    "MLKEM_COMPRESS": ["poly_compress", "polyvec_compress"],
    "MLKEM_DECOMPRESS": ["poly_decompress", "polyvec_decompress"],
    "KECCAK_F1600": ["keccakf"],
    "KECCAK_ABSORB": ["sha3_update"],
    "KECCAK_SQUEEZE": ["shake_out"],
    "HKDF_EXTRACT": ["hkdf_extract"],
    "HKDF_EXPAND": ["hkdf_expand"],
    "P256_FIELD_MUL_REDUCE": ["mul_modp"],
    "P256_FIELD_SQR": [],
    "P256_FIELD_ADD_SUB": [],
    "P256_FIELD_INV": [],
    "P256_POINT_DOUBLE": ["proj_double"],
    "P256_POINT_ADD_MIXED": ["proj_add"],
    "P256_SCALAR_MULT": ["scalar_mult_int"],
}

STANDALONE_TARGET = "//hw/ip/otbn/dv/otbnsim:standalone"
STATS_RE = re.compile(r"OTBN executed (\d+) instructions in (\d+) cycles\.")
TRACE_RE = re.compile(r"^([0-9a-fA-F]{8}) \| (.*?) \|")
NM_RE = re.compile(r"^([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+)$")


def run_cmd(cmd, cwd):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return proc.stdout


def repo_root_from_script():
    return Path(__file__).resolve().parents[2]


def build_targets(repo_root, apps):
    if shutil.which("bazel") is None:
        raise RuntimeError("bazel was not found in PATH")

    labels = [APP_TARGETS[app] for app in apps]
    run_cmd(["bazel", "build", STANDALONE_TARGET], repo_root)
    run_cmd(["bazel", "build", "--output_groups=elf"] + labels, repo_root)


def find_app_elf(repo_root, app):
    out = run_cmd(
        [
            "bazel",
            "cquery",
            "--output=files",
            "--output_groups=elf",
            APP_TARGETS[app],
        ],
        repo_root,
    )
    matches = [
        line.strip() for line in out.splitlines() if line.strip().endswith(".elf")
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one ELF for {app}, found {len(matches)}: {matches}"
        )
    elf = repo_root / matches[0]
    if not elf.exists():
        raise FileNotFoundError(f"ELF reported by Bazel was not found: {elf}")
    return elf


def find_standalone_bin(repo_root):
    out = run_cmd(["bazel", "cquery", "--output=files", STANDALONE_TARGET], repo_root)
    matches = [
        line.strip()
        for line in out.splitlines()
        if line.strip().endswith("/standalone") or line.strip().endswith("standalone")
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one standalone simulator, found {len(matches)}: {matches}"
        )
    standalone = repo_root / matches[0]
    if not standalone.exists():
        raise FileNotFoundError(
            "standalone simulator was not found after Bazel query: "
            f"{standalone}\n"
            f"Try: bazel build {STANDALONE_TARGET}"
        )
    return standalone


def find_nm_tool(repo_root):
    for tool in ("riscv32-unknown-elf-nm", "llvm-nm", "nm"):
        path = shutil.which(tool)
        if path is not None:
            return path

    try:
        exec_root = Path(run_cmd(["bazel", "info", "execution_root"], repo_root).strip())
    except RuntimeError:
        exec_root = repo_root

    candidates = list(
        exec_root.glob("external/*lowrisc*toolchain*/bin/riscv32-unknown-elf-nm")
    )
    candidates += list(
        repo_root.glob("external/*lowrisc*toolchain*/bin/riscv32-unknown-elf-nm")
    )
    if candidates:
        return str(candidates[0])
    raise RuntimeError("could not find an nm tool for OTBN ELF symbol parsing")


def parse_symbols(repo_root, nm_tool, elf):
    out = run_cmd([nm_tool, "-an", str(elf)], repo_root)
    symbols = []
    for line in out.splitlines():
        match = NM_RE.match(line.strip())
        if not match:
            continue
        addr = int(match.group(1), 16)
        sym_type = match.group(2)
        name = match.group(3).split()[0]
        if sym_type.lower() == "t":
            symbols.append((addr, name))

    symbols.sort()
    ranges = {}
    for idx, (addr, name) in enumerate(symbols):
        end = symbols[idx + 1][0] if idx + 1 < len(symbols) else None
        if end is None or end > addr:
            ranges.setdefault(name, []).append((addr, end))
    return ranges


def profile_once(repo_root, standalone, elf):
    out = run_cmd(
        [
            str(standalone),
            "--bnmulv_version_id=0",
            "--dump-stats",
            "-",
            str(elf),
        ],
        repo_root,
    )
    match = STATS_RE.search(out)
    if not match:
        raise RuntimeError(f"could not parse simulator stats for {elf}")
    return int(match.group(1)), int(match.group(2))


def run_verbose_trace(repo_root, standalone, elf):
    return run_cmd(
        [
            str(standalone),
            "--bnmulv_version_id=0",
            "--verbose",
            "--dump-stats",
            "-",
            str(elf),
        ],
        repo_root,
    )


def summarize(values):
    if len(values) == 1:
        return values[0], values[0], values[0], 0.0
    return (
        statistics.mean(values),
        min(values),
        max(values),
        statistics.pstdev(values),
    )


def range_contains(ranges, pc):
    for start, end in ranges:
        if pc >= start and (end is None or pc < end):
            return True
    return False


def aggregate_leaf_trace(app, trace_text, symbol_ranges):
    label_ranges = {}
    label_symbols = {}
    for label, symbols in LEAF_LABELS.items():
        ranges = []
        found = []
        for symbol in symbols:
            if symbol in symbol_ranges:
                found.append(symbol)
                ranges.extend(symbol_ranges[symbol])
        if ranges:
            label_ranges[label] = ranges
            label_symbols[label] = "|".join(found)

    stats = {
        label: {"calls": 0, "cycles": 0, "instr": 0, "prev_in": False}
        for label in label_ranges
    }
    raw_rows = []

    for line in trace_text.splitlines():
        match = TRACE_RE.match(line)
        if not match:
            continue
        pc = int(match.group(1), 16)
        disasm = match.group(2).strip()
        is_stall = disasm == "(stall)"

        for label, ranges in label_ranges.items():
            in_range = range_contains(ranges, pc)
            if in_range:
                entry = stats[label]
                if not entry["prev_in"]:
                    entry["calls"] += 1
                entry["cycles"] += 1
                if not is_stall:
                    entry["instr"] += 1
                raw_rows.append(
                    {
                        "app": app,
                        "label": label,
                        "source_symbol": label_symbols[label],
                        "pc": f"0x{pc:08x}",
                        "disasm": disasm,
                        "is_stall": int(is_stall),
                    }
                )
            stats[label]["prev_in"] = in_range

    summary_rows = []
    for label, symbols in LEAF_LABELS.items():
        if label in stats:
            entry = stats[label]
            calls = entry["calls"]
            summary_rows.append(
                {
                    "label": label,
                    "source_symbol": label_symbols[label],
                    "calls": calls,
                    "total_cycles": entry["cycles"],
                    "avg_cycles": "" if calls == 0 else entry["cycles"] // calls,
                    "total_instr": entry["instr"],
                    "avg_instr": "" if calls == 0 else entry["instr"] // calls,
                    "status": "measured",
                }
            )
        elif symbols:
            summary_rows.append(
                {
                    "label": label,
                    "source_symbol": "|".join(symbols),
                    "calls": "",
                    "total_cycles": "",
                    "avg_cycles": "",
                    "total_instr": "",
                    "avg_instr": "",
                    "status": "not_measured",
                }
            )
        else:
            summary_rows.append(
                {
                    "label": label,
                    "source_symbol": "",
                    "calls": "",
                    "total_cycles": "",
                    "avg_cycles": "",
                    "total_instr": "",
                    "avg_instr": "",
                    "status": "not_measured",
                }
            )
    return raw_rows, summary_rows


def merge_leaf_summaries(per_app_summaries):
    merged = {}
    for rows in per_app_summaries:
        for row in rows:
            label = row["label"]
            current = merged.setdefault(label, dict(row))
            if row["status"] != "measured":
                continue
            if current["status"] != "measured":
                merged[label] = dict(row)
                continue
            current["source_symbol"] = "|".join(
                sorted(set(current["source_symbol"].split("|")) |
                       set(row["source_symbol"].split("|")))
            )
            current["calls"] = int(current["calls"]) + int(row["calls"])
            current["total_cycles"] = int(current["total_cycles"]) + int(row["total_cycles"])
            current["total_instr"] = int(current["total_instr"]) + int(row["total_instr"])
            current["avg_cycles"] = (
                "" if current["calls"] == 0 else current["total_cycles"] // current["calls"]
            )
            current["avg_instr"] = (
                "" if current["calls"] == 0 else current["total_instr"] // current["calls"]
            )
    return [merged[label] for label in LEAF_LABELS]


def write_csv(path, rows, fieldnames):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=1,
        help="number of ISS repetitions per app for app-level counts",
    )
    parser.add_argument(
        "--apps",
        nargs="+",
        choices=sorted(APP_TARGETS),
        default=list(APP_TARGETS),
        help="subset of apps to profile",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("test_hybrid_kem_otbn_prompt_ver0_1/results/iss_profile"),
        help="directory for app and leaf CSV files",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="reuse existing bazel-bin ELF and simulator outputs",
    )
    parser.add_argument(
        "--skip-leaf-profile",
        action="store_true",
        help="only produce app-level ISS counts",
    )
    args = parser.parse_args()

    if args.iterations <= 0:
        raise ValueError("--iterations must be positive")

    repo_root = repo_root_from_script()
    out_dir = repo_root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_build:
        build_targets(repo_root, args.apps)

    standalone = find_standalone_bin(repo_root)
    app_elves = {app: find_app_elf(repo_root, app) for app in args.apps}

    app_raw_rows = []
    app_summary_rows = []
    for app in args.apps:
        app_instr = []
        app_cycles = []
        for run_idx in range(args.iterations):
            instr, cycles = profile_once(repo_root, standalone, app_elves[app])
            app_instr.append(instr)
            app_cycles.append(cycles)
            app_raw_rows.append(
                {
                    "app": app,
                    "run": run_idx + 1,
                    "instructions": instr,
                    "cycles": cycles,
                }
            )
        instr_mean, instr_min, instr_max, instr_std = summarize(app_instr)
        cyc_mean, cyc_min, cyc_max, cyc_std = summarize(app_cycles)
        app_summary_rows.append(
            {
                "app": app,
                "runs": args.iterations,
                "instructions_mean": f"{instr_mean:.3f}",
                "instructions_min": instr_min,
                "instructions_max": instr_max,
                "instructions_stddev": f"{instr_std:.6f}",
                "cycles_mean": f"{cyc_mean:.3f}",
                "cycles_min": cyc_min,
                "cycles_max": cyc_max,
                "cycles_stddev": f"{cyc_std:.6f}",
            }
        )
        print(f"HKE_PROFILE_APP,{app},runs={args.iterations}")

    write_csv(
        out_dir / "otbn_app_profile_raw.csv",
        app_raw_rows,
        ["app", "run", "instructions", "cycles"],
    )
    write_csv(
        out_dir / "otbn_app_profile_summary.csv",
        app_summary_rows,
        [
            "app",
            "runs",
            "instructions_mean",
            "instructions_min",
            "instructions_max",
            "instructions_stddev",
            "cycles_mean",
            "cycles_min",
            "cycles_max",
            "cycles_stddev",
        ],
    )

    if not args.skip_leaf_profile:
        nm_tool = find_nm_tool(repo_root)
        leaf_raw_rows = []
        per_app_summaries = []
        for app in args.apps:
            symbol_ranges = parse_symbols(repo_root, nm_tool, app_elves[app])
            trace_text = run_verbose_trace(repo_root, standalone, app_elves[app])
            raw_rows, summary_rows = aggregate_leaf_trace(app, trace_text, symbol_ranges)
            leaf_raw_rows.extend(raw_rows)
            per_app_summaries.append(summary_rows)
            print(f"HKE_PROFILE_LEAF,{app},trace_processed=1")

        leaf_summary_rows = merge_leaf_summaries(per_app_summaries)
        limitation_rows = []
        for row in leaf_summary_rows:
            if row["status"] == "measured":
                limitation_rows.append(
                    {
                        "label": row["label"],
                        "status": "measured",
                        "reason": "symbol range found in at least one profiled ELF",
                    }
                )
            elif row["source_symbol"]:
                limitation_rows.append(
                    {
                        "label": row["label"],
                        "status": "not_measured",
                        "reason": "candidate source symbol not present in profiled ELFs",
                    }
                )
            else:
                limitation_rows.append(
                    {
                        "label": row["label"],
                        "status": "not_measured",
                        "reason": "no separate stable source symbol configured",
                    }
                )
        write_csv(
            out_dir / "otbn_leaf_profile_raw.csv",
            leaf_raw_rows,
            ["app", "label", "source_symbol", "pc", "disasm", "is_stall"],
        )
        write_csv(
            out_dir / "otbn_leaf_profile_summary.csv",
            leaf_summary_rows,
            [
                "label",
                "source_symbol",
                "calls",
                "total_cycles",
                "avg_cycles",
                "total_instr",
                "avg_instr",
                "status",
            ],
        )
        write_csv(
            out_dir / "otbn_leaf_profile_limitations.csv",
            limitation_rows,
            ["label", "status", "reason"],
        )

    print(f"results: {out_dir}")


if __name__ == "__main__":
    main()
