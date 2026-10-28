"""
Train a DDoS/attack-vs-benign classifier on the CICIDS2017 "MachineLearningCVE"
CSV files, for the Signal Room project's dashboard ML panel.

WHAT THIS DOES (and why, so you can explain it to your mentor):
1. Loads every CSV in the dataset folder (one per day: Monday..Friday).
2. Cleans known CICIDS2017 artifacts: Infinity/NaN values from zero-duration
   flows (Flow Bytes/s = bytes / 0), duplicate rows, and leading/trailing
   whitespace in column names (the raw files have it, e.g. " Flow Duration").
3. Collapses the multi-class Label column into binary BENIGN=0 / ATTACK=1
   (you can switch to multi-class later if you want per-attack-type output).
4. Splits into train/validation with STRATIFICATION (keeps the same
   benign/attack ratio in both splits) and SHUFFLING.
5. Trains a small, explainable model (logistic regression) — not because
   it's the most powerful option, but because it's fast, interpretable
   (you can show feature coefficients in your report), and appropriate for
   a project whose point is the SCORING LOGIC, not a leaderboard-chasing model.
6. Reports accuracy, precision, recall, F1, and a confusion matrix —
   specifically calling out recall on the ATTACK class, because missing an
   attack (false negative) is worse for a DDoS defense than a false alarm.
7. Saves the trained model + the feature list + the scaler to disk, so the
   backend (or a small inference script) can load and reuse it without
   retraining every time.

USAGE:
    pip install pandas scikit-learn joblib
    python train.py --data-dir "C:/path/to/MachineLearningCVE"

The --data-dir should point at the FOLDER containing the CSV files directly
(not a zip, not a parent folder with subfolders).
"""

import argparse
import glob
import os
import sys

import joblib
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
from sklearn.preprocessing import StandardScaler


def load_dataset(data_dir: str) -> pd.DataFrame:
    csv_paths = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_paths:
        sys.exit(f"No CSV files found in {data_dir!r} — check the path.")

    print(f"Found {len(csv_paths)} CSV file(s):")
    frames = []
    for path in csv_paths:
        print(f"  loading {os.path.basename(path)} ...", end=" ")
        # low_memory=False avoids pandas guessing dtypes chunk-by-chunk,
        # which otherwise throws mixed-type warnings on these files.
        df = pd.read_csv(path, low_memory=False, encoding="latin1")
        print(f"{len(df):,} rows")
        frames.append(df)

    full = pd.concat(frames, ignore_index=True)
    # The raw CICIDS2017 CSVs have leading spaces in most column names
    # (e.g. " Flow Duration") — strip them so --data-dir works regardless
    # of which exact release you downloaded.
    full.columns = [c.strip() for c in full.columns]
    print(f"\nTotal rows loaded: {len(full):,}")
    return full


def clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)

    # Known CICIDS2017 artifact: Flow Bytes/s and Flow Packets/s become
    # Infinity when Flow Duration is 0 (division by zero). Replace with NaN
    # so they can be dropped cleanly rather than silently poisoning the model.
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    df = df.drop_duplicates()

    after = len(df)
    print(f"Cleaned: {before:,} -> {after:,} rows ({before - after:,} removed: "
          f"Infinity/NaN from zero-duration flows, and duplicates)")
    return df


def binarize_label(df: pd.DataFrame) -> pd.DataFrame:
    df["Label"] = df["Label"].astype(str).str.strip()
    df["is_attack"] = (df["Label"].str.upper() != "BENIGN").astype(int)
    counts = df["is_attack"].value_counts()
    print(f"\nLabel distribution — benign: {counts.get(0, 0):,}  "
          f"attack: {counts.get(1, 0):,}")
    print("Attack types present:",
          sorted(df.loc[df["is_attack"] == 1, "Label"].unique()))
    return df


def select_features(df: pd.DataFrame) -> list[str]:
    # Drop columns that either leak the label trivially or aren't real
    # traffic-shape signals (an ID/port is not a behavioral feature).
    drop_cols = {"Label", "is_attack", "Destination Port", "Flow ID",
                 "Source IP", "Destination IP", "Timestamp", "Source Port"}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    features = [c for c in numeric_cols if c not in drop_cols]
    print(f"\nUsing {len(features)} numeric features (dropped ID/port/label columns).")
    return features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True,
                         help="Folder containing the CICIDS2017 MachineLearningCVE CSVs")
    parser.add_argument("--out-dir", default="model_out",
                         help="Where to save the trained model (default: ./model_out)")
    parser.add_argument("--test-size", type=float, default=0.2,
                         help="Validation split fraction (default: 0.2)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = load_dataset(args.data_dir)
    df = clean(df)
    df = binarize_label(df)
    features = select_features(df)

    X = df[features].values
    y = df["is_attack"].values

    # Stratified split: keeps the same benign/attack ratio in train and
    # validation, so validation performance isn't a fluke of an unlucky split.
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    print(f"\nTrain: {len(X_train):,} rows   Validation: {len(X_val):,} rows")

    # Logistic regression needs scaled features to converge reliably when
    # columns are on very different scales (e.g. Flow Duration in
    # microseconds vs. a 0/1 flag column).
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # class_weight="balanced" is the real answer to "on what basis" for your
    # mentor: it reweights the loss so the model isn't just predicting the
    # majority class, and we picked it (over no weighting) because recall on
    # the attack class is what matters for a DDoS defense — a missed attack
    # costs more than a false alarm.
    model = LogisticRegression(max_iter=1000, class_weight="balanced",
                                random_state=args.seed)
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_val_scaled)

    print("\n" + "=" * 60)
    print("VALIDATION RESULTS")
    print("=" * 60)
    print(f"Accuracy:              {accuracy_score(y_val, y_pred):.4f}")
    print(f"Precision (attack=1):  {precision_score(y_val, y_pred):.4f}")
    print(f"Recall (attack=1):     {recall_score(y_val, y_pred):.4f}  "
          "<- the number to highlight: missed attacks are costlier than false alarms")
    print(f"F1 (attack=1):         {f1_score(y_val, y_pred):.4f}")
    print("\nConfusion matrix (rows=actual, cols=predicted; [benign, attack]):")
    print(confusion_matrix(y_val, y_pred))
    print("\nFull report:")
    print(classification_report(y_val, y_pred, target_names=["benign", "attack"]))

    # Top features by absolute coefficient magnitude — this is what the
    # dashboard's "SHAP-style" panel should actually show once you wire a
    # real model in, instead of the placeholder values currently there.
    coefs = pd.Series(model.coef_[0], index=features).sort_values(
        key=abs, ascending=False)
    print("\nTop 10 most influential features (by |coefficient|):")
    print(coefs.head(10).to_string())

    os.makedirs(args.out_dir, exist_ok=True)
    joblib.dump(model, os.path.join(args.out_dir, "model.joblib"))
    joblib.dump(scaler, os.path.join(args.out_dir, "scaler.joblib"))
    joblib.dump(features, os.path.join(args.out_dir, "features.joblib"))
    print(f"\nSaved model, scaler, and feature list to {args.out_dir}/")


if __name__ == "__main__":
    main()
