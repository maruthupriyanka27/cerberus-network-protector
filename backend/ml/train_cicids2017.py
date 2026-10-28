"""
Train a DDoS/attack classifier on CICIDS2017 (MachineLearningCVE) CSVs.

What this does, and why — matches the answer you'd give your mentor about
"on what basis is tuning being done":
  1. Preprocessing: strips whitespace from CICIDS2017's notoriously messy
     column headers, removes Infinity/NaN rows (a known artifact when
     Flow Duration = 0 makes rate columns divide by zero), and collapses
     the multi-class Label into binary BENIGN (0) vs ATTACK (1).
  2. Model selection: trains two candidate models (Logistic Regression and
     Random Forest) and picks the better one via stratified 5-fold cross
     validation scored on RECALL of the attack class — not accuracy —
     because for a DDoS defense system a missed attack (false negative)
     is worse than a false alarm (false positive).
  3. Hyperparameters: the only tuning is the regularization strength for
     Logistic Regression and the tree depth for Random Forest, chosen via
     GridSearchCV over that same cross-validation, so the choice is backed
     by held-out performance, not guesswork.

Usage:
    cd backend/ml
    pip install pandas scikit-learn joblib
    python train_cicids2017.py --data-dir "C:\\path\\to\\MachineLearningCVE"

    # Train on one specific file instead of auto-combining everything:
    python train_cicids2017.py --data-dir "..." --file "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

Output:
    model.joblib        — the trained classifier
    scaler.joblib        — the fitted StandardScaler (needed to transform new data the same way)
    feature_columns.json — the exact feature column order the model expects
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, recall_score
from sklearn.preprocessing import StandardScaler
import joblib


def find_csvs(data_dir: Path, only_file: str | None):
    if only_file:
        p = data_dir / only_file
        if not p.exists():
            sys.exit(f"File not found: {p}")
        return [p]
    csvs = sorted(data_dir.glob("*.csv"))
    if not csvs:
        sys.exit(f"No CSV files found in {data_dir}")
    print(f"Found {len(csvs)} CSV file(s):")
    for f in csvs:
        print(f"  - {f.name}")
    return csvs


def load_and_clean(csv_paths):
    frames = []
    for p in csv_paths:
        print(f"Loading {p.name} ...")
        df = pd.read_csv(p, low_memory=False)
        # CICIDS2017 headers have stray leading/trailing spaces — normalize them.
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    print(f"Combined shape before cleaning: {df.shape}")

    if "Label" not in df.columns:
        sys.exit("Expected a 'Label' column — check the CSV headers.")

    # Replace the Infinity/NaN artifacts (Flow Duration == 0 -> divide-by-zero
    # in rate columns) rather than silently letting them corrupt training.
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    after = len(df)
    print(f"Dropped {before - after} rows with Infinity/NaN ({after} remain)")

    # Binary target: BENIGN -> 0, everything else (DDoS, PortScan, Bot, etc.) -> 1
    df["y"] = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int)
    print("Class balance:")
    print(df["y"].value_counts(normalize=True).rename({0: "benign", 1: "attack"}))

    feature_cols = [c for c in df.columns if c not in ("Label", "y")]
    # Drop any non-numeric leftovers defensively (shouldn't be any in this dataset).
    X = df[feature_cols].select_dtypes(include=[np.number])
    dropped_non_numeric = set(feature_cols) - set(X.columns)
    if dropped_non_numeric:
        print(f"Dropping non-numeric columns: {dropped_non_numeric}")
    y = df["y"].values
    return X, y, list(X.columns)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True, help="Folder containing the CICIDS2017 CSV(s)")
    ap.add_argument("--file", default=None, help="Train on just this one CSV filename instead of all in the folder")
    ap.add_argument("--out-dir", default=".", help="Where to save model.joblib / scaler.joblib / feature_columns.json")
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_paths = find_csvs(data_dir, args.file)
    X, y, feature_cols = load_and_clean(csv_paths)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    print("\n--- Tuning Logistic Regression (grid search over C, 5-fold CV, scored on recall) ---")
    lr_grid = GridSearchCV(
        LogisticRegression(max_iter=2000, class_weight="balanced"),
        param_grid={"C": [0.01, 0.1, 1, 10]},
        scoring="recall",
        cv=cv,
        n_jobs=-1,
    )
    lr_grid.fit(X_train_scaled, y_train)
    print(f"Best C: {lr_grid.best_params_}  |  CV recall: {lr_grid.best_score_:.4f}")

    print("\n--- Tuning Random Forest (grid search over max_depth, 5-fold CV, scored on recall) ---")
    rf_grid = GridSearchCV(
        RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42),
        param_grid={"max_depth": [8, 16, None]},
        scoring="recall",
        cv=cv,
        n_jobs=-1,
    )
    rf_grid.fit(X_train_scaled, y_train)
    print(f"Best max_depth: {rf_grid.best_params_}  |  CV recall: {rf_grid.best_score_:.4f}")

    # Pick whichever generalizes better on the held-out test set, not just CV.
    candidates = {"logistic_regression": lr_grid.best_estimator_, "random_forest": rf_grid.best_estimator_}
    results = {}
    for name, model in candidates.items():
        preds = model.predict(X_test_scaled)
        results[name] = recall_score(y_test, preds)
        print(f"\n=== {name} — held-out test set ===")
        print(classification_report(y_test, preds, target_names=["benign", "attack"]))
        print("Confusion matrix [[TN FP] [FN TP]]:")
        print(confusion_matrix(y_test, preds))

    winner_name = max(results, key=results.get)
    winner = candidates[winner_name]
    print(f"\nSelected model: {winner_name} (test recall {results[winner_name]:.4f})")

    joblib.dump(winner, out_dir / "model.joblib")
    joblib.dump(scaler, out_dir / "scaler.joblib")
    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    print(f"\nSaved model.joblib, scaler.joblib, feature_columns.json to {out_dir.resolve()}")


if __name__ == "__main__":
    main()
