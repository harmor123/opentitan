#!/usr/bin/env python3
"""Extract HKE phase/app profiling CSVs from chip-sim logs."""

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


PROFILE_RE = re.compile(r"(HKE_PROFILE_[A-Z_]+|HKEM_PROF[A-Z_]*),([^,\r\n]+),([^,\r\n]+),([0-9]+)")
SUMMARY_RE = re.compile(
    r"(HKE_PROFILE_PHASE|HKE_PROFILE_APP),([^,\r\n]+),label=([^,\r\n]+),calls=([0-9]+),total_cycles=([0-9]+),avg_cycles=([0-9]+)"
)

PHASE_NAMES = {
    "phase1_keygen": "bob_setup",
    "phase2_alice_encap": "alice_encapsulation",
    "phase2_bob_decap": "bob_decapsulation",
}

APP_GROUPS = {
    "phase1_keygen": [
        ("p256_keygen", "bob_setup_p256_keygen", "p256_keygen"),
        ("mlkem_keypair", "bob_setup_mlkem_keypair", "mlkem_keypair"),
    ],
    "phase2_alice_encap": [
        ("p256_keygen", "alice_p256_keygen", "p256_keygen"),
        ("p256_ecdh", "alice_p256_ecdh", "p256_ecdh"),
        ("mlkem_encap", "alice_mlkem_encap", "mlkem_encap"),
        ("hkdf", "alice_hkdf_sha3", "hkdf_sha3"),
    ],
    "phase2_bob_decap": [
        ("mlkem_decap", "bob_mlkem_decap", "mlkem_decap"),
        ("p256", "bob_p256_ecdh", "p256_ecdh"),
        ("hkdf", "bob_hkdf_sha3", "hkdf_sha3"),
    ],
}


def phase_key(name):
    return PHASE_NAMES.get(name, name)


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_logs(paths):
    entries = defaultdict(dict)
    tests = defaultdict(dict)
    scopes = defaultdict(dict)
    summaries = []
    for path in paths:
        text = Path(path).read_text(errors="replace")
        for match in PROFILE_RE.finditer(text):
            kind, phase, step, cycles = match.groups()
            cycles = int(cycles)
            if kind in {"HKE_PROFILE_PHASE", "HKEM_PROF"} and step == "protocol_total":
                scopes[phase]["protocol_total"] = cycles
            elif kind in {"HKE_PROFILE_APP", "HKEM_PROF"}:
                entries[phase][step] = cycles
            elif kind in {"HKE_PROFILE_APP_TEST", "HKEM_PROF_TEST"}:
                tests[phase][step] = cycles
            elif kind in {"HKE_PROFILE_PHASE_SCOPE", "HKEM_PROF_SCOPE"}:
                scopes[phase][step] = cycles
        for match in SUMMARY_RE.finditer(text):
            kind, phase, label, calls, total_cycles, avg_cycles = match.groups()
            summaries.append(
                {
                    "kind": kind,
                    "phase": phase,
                    "label": label,
                    "calls": int(calls),
                    "total_cycles": int(total_cycles),
                    "avg_cycles": int(avg_cycles),
                }
            )
    return entries, tests, scopes, summaries


def get_steps(data, prefix, contains=None):
    total = 0
    for step, cycles in data.items():
        if not step.startswith(prefix):
            continue
        if contains is not None and contains not in step:
            continue
        total += cycles
    return total


def app_row(phase, step_prefix, operation, app, entries, tests):
    phase_entries = entries[phase]
    phase_tests = tests[phase]
    load = get_steps(phase_entries, step_prefix, "load")
    write = get_steps(phase_entries, step_prefix, "write")
    execute = get_steps(phase_entries, step_prefix, "execute_wait")
    read = get_steps(phase_entries, step_prefix, "read")
    wipe = sum(
        cycles
        for step, cycles in phase_entries.items()
        if step.startswith("wipe_after_" + step_prefix.rstrip("_"))
    )
    check = sum(
        cycles
        for step, cycles in phase_tests.items()
        if step.startswith("check_") and step_prefix.rstrip("_") in step
    )
    total = load + write + execute + read + wipe
    return {
        "phase": phase_key(phase),
        "app": app,
        "operation": operation,
        "load_cycles": load,
        "write_input_cycles": write,
        "execute_wait_cycles": execute,
        "read_output_cycles": read,
        "wipe_cycles": wipe,
        "check_cycles": check,
        "total_cycles": total,
        "status": "measured" if total else "missing",
    }


def build_app_rows(entries, tests):
    rows = []
    for phase, groups in APP_GROUPS.items():
        for prefix, operation, app in groups:
            rows.append(app_row(phase, prefix, operation, app, entries, tests))
    return rows


def build_phase_rows(app_rows, tests, scopes):
    by_phase = defaultdict(list)
    for row in app_rows:
        by_phase[row["phase"]].append(row)

    rows = []
    for raw_phase, nice_phase in PHASE_NAMES.items():
        phase_apps = by_phase[nice_phase]
        p256 = sum(row["total_cycles"] for row in phase_apps if row["app"].startswith("p256"))
        mlkem = sum(row["total_cycles"] for row in phase_apps if row["app"].startswith("mlkem"))
        kdf = sum(row["total_cycles"] for row in phase_apps if row["app"] in {"hkdf_sha3", "kmac", "hmac"})
        test_cycles = scopes[raw_phase].get("test_total", sum(tests[raw_phase].values()))
        total = scopes[raw_phase].get("protocol_total", p256 + mlkem + kdf)
        scope_total = scopes[raw_phase].get("scope_total", "")
        accounted = scopes[raw_phase].get("accounted_total", total + test_cycles)
        unaccounted = scopes[raw_phase].get("unaccounted_total", "")
        if unaccounted == "" and scope_total != "":
            unaccounted = int(scope_total) - int(accounted)
        unaccounted_pct = "" if scope_total in {"", 0} else f"{100.0 * int(unaccounted) / int(scope_total):.3f}"
        rows.append(
            {
                "phase": nice_phase,
                "total_cycles": total,
                "p256_branch_cycles": p256,
                "mlkem_branch_cycles": mlkem,
                "kdf_branch_cycles": kdf,
                "test_check_cycles": test_cycles,
                "scope_total_cycles": scope_total,
                "accounted_total_cycles": accounted,
                "unaccounted_cycles": unaccounted,
                "unaccounted_pct": unaccounted_pct,
                "status": "measured" if total else "missing",
            }
        )
    return rows


def parse_args():
    parser = argparse.ArgumentParser(description="Extract phase/app profiling CSVs from chip-sim logs.")
    parser.add_argument("--input", nargs="+", required=True, help="chip-sim log files")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("test_hybrid_kem_otbn_prompt_ver0_1/results/phase_app_profile"),
        help="output directory",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    entries, tests, scopes, _ = parse_logs(args.input)
    app_rows = build_app_rows(entries, tests)
    phase_rows = build_phase_rows(app_rows, tests, scopes)
    write_csv(
        args.output_dir / "app_profile_summary.csv",
        app_rows,
        [
            "phase",
            "app",
            "operation",
            "load_cycles",
            "write_input_cycles",
            "execute_wait_cycles",
            "read_output_cycles",
            "wipe_cycles",
            "check_cycles",
            "total_cycles",
            "status",
        ],
    )
    write_csv(
        args.output_dir / "phase_profile_summary.csv",
        phase_rows,
        [
            "phase",
            "total_cycles",
            "p256_branch_cycles",
            "mlkem_branch_cycles",
            "kdf_branch_cycles",
            "test_check_cycles",
            "scope_total_cycles",
            "accounted_total_cycles",
            "unaccounted_cycles",
            "unaccounted_pct",
            "status",
        ],
    )
    print(f"results: {args.output_dir}")


if __name__ == "__main__":
    main()
