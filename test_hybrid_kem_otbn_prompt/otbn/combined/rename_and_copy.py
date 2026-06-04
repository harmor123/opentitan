#!/usr/bin/env python3
"""Copy ML-KEM phase files to combined/, rename conflicting labels."""

import os, shutil, sys

BASE = "C:/Users/harmor/Desktop/test/opentitan/test_hybrid_kem_otbn_prompt/otbn"
DST = os.path.join(BASE, "combined")
MLKEM = os.path.join(BASE, "mlkem768")

# ── Label rename maps (from original → prefixed) ──
# keypair phase: coins, ek, dk
KP_RENAME = {
    "coins": "kp_coins",
    "ek":    "kp_ek",
    "dk":    "kp_dk",
    "stack": "kp_stack", "stack_end": "kp_stack_end",
}
# encap phase: coins, ek, ct, ss
ENC_RENAME = {
    "coins": "enc_coins",
    "ek":    "enc_ek",
    "ct":    "enc_ct",
    "ss":    "enc_ss",
    "stack": "enc_stack", "stack_end": "enc_stack_end",
}
# decap phase: ct, dk, ss
DEC_RENAME = {
    "ct":    "dec_ct",
    "dk":    "dec_dk",
    "ss":    "dec_ss",
    "stack": "dec_stack", "stack_end": "dec_stack_end",
}

def rename_labels(text, renames):
    for old, new in renames.items():
        # Match label definitions: .globl label or label:
        text = text.replace(f".globl {old}", f".globl {new}")
        text = text.replace(f"{old}:", f"{new}:")
        # Match references in la/li instructions (bare label name, word boundary)
        import re
        text = re.sub(rf'\b{old}\b', new, text)
    return text

def copy_and_rename(src_name, renames):
    """Copy mlkem768/src_name.s → combined/renamed_version.s"""
    src = os.path.join(MLKEM, src_name)
    dst_name = src_name  # keep same name for library files
    dst = os.path.join(DST, dst_name)
    with open(src) as f:
        text = f.read()
    text = rename_labels(text, renames)
    with open(dst, 'w') as f:
        f.write(text)
    print(f"  {src_name} → combined/ (renamed: {list(renames.keys())})")

# ── Phase-specific files: copy + rename labels ──
print("=== Phase-specific files ===")
copy_and_rename("mlkem_keypair.s", KP_RENAME)
copy_and_rename("mlkem_encap.s", ENC_RENAME)
copy_and_rename("mlkem_decap.s", DEC_RENAME)

# ── Copy shared library files (no rename) ──
SHARED = ["basemul.s", "cbd.s", "ntt.s", "intt.s", "poly.s",
          "poly_gen_matrix.s", "pack_keys.s", "pack_ciphertext.s",
          "kmac_sha3_template.s"]
print("=== Shared library files (no rename) ===")
for f in SHARED:
    shutil.copy2(os.path.join(MLKEM, f), os.path.join(DST, f))
    print(f"  {f} → combined/")

# ── Test data: keypair version has all shared constants ──
# Keep keypair test data (renamed), skip encap/decap test data
print("=== Test data ===")
# keypair test → renamed labels
src = os.path.join(BASE, "test/mlkem_base_keypair_test.s")
dst = os.path.join(DST, "kp_test_data.s")
with open(src) as f:
    text = f.read()
# Remove .text.start section → only keep .data
lines = text.split('\n')
data_start = None
for i, line in enumerate(lines):
    if line.strip().startswith('.data'):
        data_start = i
        break
if data_start:
    text = '\n'.join(lines[data_start:])
text = rename_labels(text, KP_RENAME)
with open(dst, 'w') as f:
    f.write(text)
print(f"  mlkem_base_keypair_test.s → kp_test_data.s")

# ── Encap/decap test data: only keep phase-specific labels ──
for phase, renames, prefix in [
    ("encap", ENC_RENAME, "enc"),
    ("decap", DEC_RENAME, "dec"),
]:
    src = os.path.join(BASE, f"test/mlkem_base_{phase}_test.s")
    dst = os.path.join(DST, f"{prefix}_test_data.s")
    with open(src) as f:
        text = f.read()
    data_start = None
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if line.strip().startswith('.data'):
            data_start = i
            break
    if data_start:
        text = '\n'.join(lines[data_start:])
    # Only keep phase-specific labels, remove shared constants (already in kp_test_data)
    text = rename_labels(text, renames)
    with open(dst, 'w') as f:
        f.write(text)
    print(f"  mlkem_base_{phase}_test.s → {prefix}_test_data.s")

print("\nDone! Now update BUILD to use local copies.")
