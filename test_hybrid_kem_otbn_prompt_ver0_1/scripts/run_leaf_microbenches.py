#!/usr/bin/env python3
"""Emit the current standalone leaf-microbenchmark audit.

This patch does not add standalone OTBN microbenchmark programs. The script is
kept deliberately honest: it creates the required output files and marks each
candidate as missing, so paper tables cannot accidentally treat unavailable
microbenchmark data as measured results.
"""

import argparse
import csv
from pathlib import Path


BENCHMARKS = [
    ("P256_FIELD_MUL_REDUCE", "bench_p256_field_mul"),
    ("P256_FIELD_SQR", "bench_p256_field_sqr"),
    ("P256_FIELD_ADD", "bench_p256_field_add"),
    ("P256_FIELD_SUB", "bench_p256_field_sub"),
    ("P256_FIELD_INV", "bench_p256_field_inv"),
    ("P256_POINT_DOUBLE", "bench_p256_point_double"),
    ("P256_POINT_ADD_MIXED", "bench_p256_point_add_mixed"),
    ("P256_POINT_SELECT_CMOV", "bench_p256_point_select_cmov"),
    ("MLKEM_NTT", "bench_mlkem_ntt"),
    ("MLKEM_INTT", "bench_mlkem_intt"),
    ("MLKEM_BASEMUL", "bench_mlkem_basemul"),
    ("MLKEM_COEFF_REDUCE", "bench_mlkem_reduce"),
    ("MLKEM_POLY_ADD", "bench_mlkem_poly_add"),
    ("MLKEM_POLY_SUB", "bench_mlkem_poly_sub"),
    ("KECCAK_F1600", "bench_keccak_f1600"),
    ("KECCAK_ABSORB", "bench_sha3_absorb"),
    ("KECCAK_SQUEEZE", "bench_sha3_squeeze"),
    ("HKDF_EXTRACT_EXPAND", "bench_hkdf_extract_expand"),
]


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(description="Create the leaf microbenchmark status CSVs.")
    parser.add_argument(
        "--input",
        default="",
        help="reserved for a future microbenchmark result log; currently unused",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("test_hybrid_kem_otbn_prompt_ver0_1/results/microbench_leaf_profile"),
        help="output directory",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    summary_rows = [
        {
            "label": label,
            "benchmark_name": bench,
            "repeat_count": "",
            "total_cycles": "",
            "cycles_per_call": "",
            "total_instr": "",
            "instr_per_call": "",
            "status": "not_implemented",
            "notes": "standalone microbenchmark is not implemented in this patch",
        }
        for label, bench in BENCHMARKS
    ]
    missing_rows = [
        {
            "label": label,
            "status": "missing",
            "reason": "standalone OTBN microbenchmark not implemented",
            "next_action": f"create {bench} with fixed public test inputs",
        }
        for label, bench in BENCHMARKS
    ]
    write_csv(
        args.output_dir / "microbench_leaf_summary.csv",
        summary_rows,
        [
            "label",
            "benchmark_name",
            "repeat_count",
            "total_cycles",
            "cycles_per_call",
            "total_instr",
            "instr_per_call",
            "status",
            "notes",
        ],
    )
    write_csv(
        args.output_dir / "microbench_missing.csv",
        missing_rows,
        ["label", "status", "reason", "next_action"],
    )
    print(f"results: {args.output_dir}")


if __name__ == "__main__":
    main()
