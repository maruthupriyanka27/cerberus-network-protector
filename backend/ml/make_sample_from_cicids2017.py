"""
Convert your CICIDS2017 "MachineLearningCVE" CSVs into a small, balanced
sample CSV with the SAME column schema the Signal Room frontend already
expects (previously filled by cicddos2019_sample.csv). This lets you swap
datasets without touching simulator.html / dashboard.js logic — only the
filename and a couple of display labels change.

Target schema (must match exactly, this is what simulator.html reads):
    Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Bytes/s,
    Flow Packets/s,Avg Packet Size,SYN Flag Count,Label,Category,IsAttack

Usage:
    pip install pandas
    python make_sample_from_cicids2017.py \
        --data-dir "K:\\MP3\\MachineLearningCSV\\MachineLearningCVE" \
        --out "cicids2017_sample.csv" \
        --benign-n 1500 --attack-n 1500
"""

import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd

# Maps this script's output columns -> the raw CICIDS2017 column name
# (after stripping whitespace from headers).
COLUMN_MAP = {
    "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Total Fwd Packets",
    "Total Backward Packets": "Total Backward Packets",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Avg Packet Size": "Average Packet Size",  # raw CICIDS2017 spells this out
    "SYN Flag Count": "SYN Flag Count",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True,
                     help="Folder containing the CICIDS2017 MachineLearningCVE CSVs")
    ap.add_argument("--out", default="cicids2017_sample.csv")
    ap.add_argument("--benign-n", type=int, default=1500,
                     help="How many benign rows to sample (default 1500, matches the old sample's size)")
    ap.add_argument("--attack-n", type=int, default=1500,
                     help="How many attack rows to sample in TOTAL across all attack types (default 1500)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    csv_paths = sorted(glob.glob(os.path.join(args.data_dir, "*.csv")))
    if not csv_paths:
        sys.exit(f"No CSV files found in {args.data_dir!r}")

    print(f"Loading {len(csv_paths)} file(s)...")
    frames = []
    for p in csv_paths:
        df = pd.read_csv(p, low_memory=False, encoding="latin1")
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    print(f"Combined: {len(full):,} rows")

    missing = [raw for raw in COLUMN_MAP.values() if raw not in full.columns]
    if missing:
        sys.exit(f"These expected columns are missing from your CSVs: {missing}\n"
                  f"Available columns: {list(full.columns)}")

    full["Label"] = full["Label"].astype(str).str.strip()
    full = full.replace([np.inf, -np.inf], np.nan).dropna(subset=list(COLUMN_MAP.values()) + ["Label"])
    print(f"After dropping Infinity/NaN rows: {len(full):,} rows")

    full["IsAttack"] = (full["Label"].str.upper() != "BENIGN").astype(int)
    full["Category"] = full["Label"]  # CICIDS2017 has no separate category column; Label doubles as it

    benign_pool = full[full["IsAttack"] == 0]
    attack_pool = full[full["IsAttack"] == 1]
    print(f"Pool sizes — benign: {len(benign_pool):,}  attack: {len(attack_pool):,}")
    print("Attack types available:", sorted(attack_pool["Label"].unique()))

    rng = np.random.RandomState(args.seed)

    def sample(pool, n):
        n = min(n, len(pool))
        return pool.sample(n=n, random_state=rng)

    benign_sample = sample(benign_pool, args.benign_n)

    # Spread the attack sample evenly across whichever attack categories
    # are present in your files, instead of just grabbing whichever type
    # happens to have the most rows.
    attack_types = sorted(attack_pool["Label"].unique())
    per_type = max(1, args.attack_n // len(attack_types))
    attack_parts = [sample(attack_pool[attack_pool["Label"] == t], per_type) for t in attack_types]
    attack_sample = pd.concat(attack_parts, ignore_index=True)

    out = pd.concat([benign_sample, attack_sample], ignore_index=True)
    out = out.sample(frac=1, random_state=rng).reset_index(drop=True)  # shuffle

    result = pd.DataFrame({
        out_col: out[raw_col] for out_col, raw_col in COLUMN_MAP.items()
    })
    result["Label"] = out["Label"]
    result["Category"] = out["Category"]
    result["IsAttack"] = out["IsAttack"]

    result.to_csv(args.out, index=False)
    print(f"\nWrote {len(result):,} rows to {args.out}")
    print(f"  benign: {(result['IsAttack']==0).sum():,}")
    print(f"  attack: {(result['IsAttack']==1).sum():,}  ({result[result['IsAttack']==1]['Label'].value_counts().to_dict()})")
    print("\nCopy this file into public/console/ in your Signal Room project, "
          "replacing/alongside cicddos2019_sample.csv.")


if __name__ == "__main__":
    main()
