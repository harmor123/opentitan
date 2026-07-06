#!/usr/bin/env python3
"""Validate that the HKE profiling pipeline generated its expected files."""

import argparse
import csv
from pathlib import Path


EXPECTED = [
    "phase_app_profile/phase_profile_summary.csv",
    "phase_app_profile/app_profile_summary.csv",
    "iss_leaf_profile/leaf_profile_by_app_exclusive.csv",
    "iss_leaf_profile/leaf_profile_by_app_inclusive.csv",
    "iss_leaf_profile/leaf_profile_coverage_by_app.csv",
    "iss_leaf_profile/leaf_profile_missing_labels.csv",
    "iss_leaf_profile/leaf_profile_top_hotspots.csv",
    "iss_leaf_profile/leaf_profile_symbol_map.csv",
    "iss_leaf_profile/leaf_profile_warnings.txt",
    "microbench_leaf_profile/microbench_leaf_summary.csv",
    "microbench_leaf_profile/microbench_missing.csv",
]


def count_rows(path):
    if path.suffix == ".txt":
        return len([line for line in path.read_text(errors="replace").splitlines() if line.strip()])
    with path.open(newline="") as f:
        return max(0, sum(1 for _ in csv.reader(f)) - 1)


def parse_args():
    parser = argparse.ArgumentParser(description="Check expected HKE profiling output files.")
    parser.add_argument(
        "--input",
        default="",
        help="reserved for future validation manifests; currently unused",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("test_hybrid_kem_otbn_prompt_ver0_1/results"),
        help="profiling results root",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    missing = []
    for rel in EXPECTED:
        path = args.root / rel
        if not path.exists():
            missing.append(rel)
            print(f"MISSING,{rel}")
        else:
            print(f"OK,{rel},rows={count_rows(path)}")
    if missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
