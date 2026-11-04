"""
BASELINE: train on the CICIDS2017 "MachineLearningCVE" CSVs as close to
UNMODIFIED as a model can actually run on.

Purpose: this is the comparison point for your mentor's question. Run this
script AND train.py (the "cleaned" version), then show both sets of
numbers side by side. That comparison — not an assertion — is "the basis."

What counts as "unmodified" here, and the ONE thing that can't be skipped:
  - No class balancing (model sees the real, imbalanced benign/attack ratio)
  - No feature selection (every numeric column is kept, including ones
    like Destination Port that might leak the label)
  - No scaling (features used on their raw, wildly different scales)
  - The ONLY unavoidable step: rows with Infinity/NaN are dropped, because
    scikit-learn's underlying math (NumPy/LAPACK) cannot process a non-finite
    value — it will raise "Input contains infinity or a value too large"
    and refuse to train at all. This is not a judgment call, it's a hard
    requirement of the library. Rows are not CHANGED, just excluded.

USAGE:
    pip install pandas scikit-learn
    python train_unmodified.py --data-dir "C:/path/to/MachineLearningCVE"
"""

import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    csv_paths = sorted(glob.glob(os.path.join(args.data_dir, "*.csv")))
    if not csv_paths:
        sys.exit(f"No CSV files found in {args.data_dir!r}")

    print(f"Loading {len(csv_paths)} file(s) — no preprocessing applied:")
    frames = []
    for path in csv_paths:
        df = pd.read_csv(path, low_memory=False, encoding="latin1")
        print(f"  {os.path.basename(path)}: {len(df):,} rows")
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]  # only to find "Label" reliably
    print(f"Total: {len(df):,} rows, {len(df.columns)} columns (all kept)")

    # The one unavoidable step — see module docstring.
    n_before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"Rows usable by the model (non-finite values excluded): "
          f"{n_before:,} -> {len(df):,}")

    df["is_attack"] = (df["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)
    print(f"\nRaw class balance — benign: {(df['is_attack']==0).sum():,}  "
          f"attack: {(df['is_attack']==1).sum():,}  "
          f"(attack = {df['is_attack'].mean()*100:.1f}% of data, UNBALANCED, used as-is)")

    # Every numeric column kept, no feature selection, no scaling.
    feature_cols = [c for c in df.select_dtypes(include=[np.number]).columns
                     if c != "is_attack"]
    X = df[feature_cols].values
    y = df["is_attack"].values

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )

    # Plain LogisticRegression — no class_weight, no scaling pipeline.
    model = LogisticRegression(max_iter=1000, random_state=args.seed)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    print("\n" + "=" * 60)
    print("UNMODIFIED BASELINE — VALIDATION RESULTS")
    print("=" * 60)
    print(f"Accuracy:              {accuracy_score(y_val, y_pred):.4f}")
    print(f"Precision (attack=1):  {precision_score(y_val, y_pred, zero_division=0):.4f}")
    print(f"Recall (attack=1):     {recall_score(y_val, y_pred, zero_division=0):.4f}  "
          "<- watch this number specifically")
    print(f"F1 (attack=1):         {f1_score(y_val, y_pred, zero_division=0):.4f}")
    print("\nConfusion matrix [benign, attack]:")
    print(confusion_matrix(y_val, y_pred))
    print()
    print(classification_report(y_val, y_pred, target_names=["benign", "attack"], zero_division=0))
    print("\nIf recall on 'attack' is near 0 here, that's the likely result of "
          "skipping class balancing — with CICIDS2017 typically ~80% benign, "
          "an unbalanced model can get high 'accuracy' while barely ever "
          "flagging an attack. That specific failure, shown numerically, IS "
          "your basis for the preprocessing choices in the other script.")


if __name__ == "__main__":
    main()
