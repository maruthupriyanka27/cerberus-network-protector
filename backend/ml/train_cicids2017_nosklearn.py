"""
Train a DDoS/attack classifier on CICIDS2017 — WITHOUT scikit-learn or scipy.

Use this version if train_cicids2017.py fails with an error like:
  "ImportError: DLL load failed ... Application Control policy has blocked this file"
That error means Windows or your antivirus is blocking a compiled file inside
scipy (which scikit-learn always loads, even just to import it). This script
only uses pandas and numpy, and implements logistic regression by hand with
gradient descent — same underlying method, no blocked dependency.

WHAT THIS DOES (same reasoning as before, for your mentor's "on what basis"
question):
  1. Loads every CSV in the dataset folder, strips messy whitespace from
     column headers (a known CICIDS2017 quirk).
  2. Cleans Infinity/NaN rows (from Flow Duration=0 divide-by-zero).
  3. Collapses the multi-class Label into binary BENIGN=0 / ATTACK=1.
  4. Standardizes features (zero mean, unit variance) by hand.
  5. Splits into train/validation with the same attack:benign ratio in both
     (stratified split), done manually with numpy.
  6. Trains logistic regression via batch gradient descent, with a
     class-weighted loss (attacks weighted more heavily than benign) so the
     model can't just predict "benign" every time and still look accurate —
     this is the direct, numbers-backed basis for the preprocessing choices.
  7. Reports accuracy, precision, recall, F1, and a confusion matrix, by
     hand (no sklearn.metrics either).
  8. Saves the trained weights + feature list + feature means/stds to a
     small JSON file, so they can be reloaded later without retraining.

USAGE:
    pip install pandas numpy
    python train_cicids2017_nosklearn.py --data-dir "K:\\MP3\\MachineLearningCSV\\MachineLearningCVE"
"""

import argparse
import glob
import json
import os
import sys

import numpy as np
import pandas as pd


def load_dataset(data_dir: str) -> pd.DataFrame:
    csv_paths = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_paths:
        sys.exit(f"No CSV files found in {data_dir!r} — check the path.")

    print(f"Found {len(csv_paths)} CSV file(s):")
    frames = []
    for path in csv_paths:
        print(f"  loading {os.path.basename(path)} ...", end=" ")
        df = pd.read_csv(path, low_memory=False, encoding="latin1")
        print(f"{len(df):,} rows")
        frames.append(df)

    full = pd.concat(frames, ignore_index=True)
    full.columns = [c.strip() for c in full.columns]
    print(f"\nTotal rows loaded: {len(full):,}")
    return full


def clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()
    after = len(df)
    print(f"Cleaned: {before:,} -> {after:,} rows "
          f"({before - after:,} removed: Infinity/NaN, duplicates)")
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


def select_features(df: pd.DataFrame):
    drop_cols = {"Label", "is_attack", "Destination Port", "Flow ID",
                 "Source IP", "Destination IP", "Timestamp", "Source Port"}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    features = [c for c in numeric_cols if c not in drop_cols]
    print(f"\nUsing {len(features)} numeric features.")
    return features


def stratified_split(X, y, test_size, seed):
    rng = np.random.RandomState(seed)
    idx0 = np.where(y == 0)[0]
    idx1 = np.where(y == 1)[0]
    rng.shuffle(idx0)
    rng.shuffle(idx1)

    n0_test = int(len(idx0) * test_size)
    n1_test = int(len(idx1) * test_size)

    test_idx = np.concatenate([idx0[:n0_test], idx1[:n1_test]])
    train_idx = np.concatenate([idx0[n0_test:], idx1[n1_test:]])
    rng.shuffle(test_idx)
    rng.shuffle(train_idx)
    return X[train_idx], X[test_idx], y[train_idx], y[test_idx]


def sigmoid(z):
    z = np.clip(z, -500, 500)  # avoid overflow in exp
    return 1.0 / (1.0 + np.exp(-z))


def train_logistic_regression(X, y, epochs=300, lr=0.5, l2=0.001, seed=42):
    rng = np.random.RandomState(seed)
    n, d = X.shape
    weights = rng.normal(0, 0.01, size=d)
    bias = 0.0

    # Class weighting: attacks get weighted by (benign_count / attack_count)
    # so the loss penalizes missing an attack more than a false alarm —
    # the same "class_weight=balanced" idea sklearn uses, done by hand.
    n_pos = max(1, y.sum())
    n_neg = max(1, len(y) - n_pos)
    pos_weight = n_neg / n_pos
    sample_weights = np.where(y == 1, pos_weight, 1.0)

    print(f"\nTraining logistic regression: {epochs} epochs, lr={lr}, "
          f"attack class weighted {pos_weight:.2f}x")

    for epoch in range(epochs):
        z = X @ weights + bias
        preds = sigmoid(z)
        error = (preds - y) * sample_weights

        grad_w = (X.T @ error) / n + l2 * weights
        grad_b = error.mean()

        weights -= lr * grad_w
        bias -= lr * grad_b

        if epoch % 50 == 0 or epoch == epochs - 1:
            eps = 1e-9
            loss = -np.mean(sample_weights * (
                y * np.log(preds + eps) + (1 - y) * np.log(1 - preds + eps)
            ))
            print(f"  epoch {epoch:4d}  loss={loss:.4f}")

    return weights, bias


def evaluate(X, y, weights, bias):
    preds_proba = sigmoid(X @ weights + bias)
    preds = (preds_proba >= 0.5).astype(int)

    tp = int(np.sum((preds == 1) & (y == 1)))
    tn = int(np.sum((preds == 0) & (y == 0)))
    fp = int(np.sum((preds == 1) & (y == 0)))
    fn = int(np.sum((preds == 0) & (y == 1)))

    accuracy = (tp + tn) / len(y)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--out-dir", default="model_out")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--epochs", type=int, default=300)
    parser.add_argument("--lr", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = load_dataset(args.data_dir)
    df = clean(df)
    df = binarize_label(df)
    features = select_features(df)

    X = df[features].values.astype(np.float64)
    y = df["is_attack"].values.astype(np.float64)

    X_train, X_val, y_train, y_val = stratified_split(X, y, args.test_size, args.seed)
    print(f"\nTrain: {len(X_train):,} rows   Validation: {len(X_val):,} rows")

    # Standardize by hand: (x - mean) / std, computed on train only, applied to both.
    means = X_train.mean(axis=0)
    stds = X_train.std(axis=0)
    stds[stds == 0] = 1.0  # avoid divide-by-zero on constant columns
    X_train_scaled = (X_train - means) / stds
    X_val_scaled = (X_val - means) / stds

    weights, bias = train_logistic_regression(
        X_train_scaled, y_train, epochs=args.epochs, lr=args.lr, seed=args.seed
    )

    results = evaluate(X_val_scaled, y_val, weights, bias)

    print("\n" + "=" * 60)
    print("VALIDATION RESULTS")
    print("=" * 60)
    print(f"Accuracy:              {results['accuracy']:.4f}")
    print(f"Precision (attack=1):  {results['precision']:.4f}")
    print(f"Recall (attack=1):     {results['recall']:.4f}  "
          "<- the number to highlight: missed attacks cost more than false alarms")
    print(f"F1 (attack=1):         {results['f1']:.4f}")
    print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
    print(np.array(results["confusion_matrix"]))

    coefs = pd.Series(weights, index=features).sort_values(key=abs, ascending=False)
    print("\nTop 10 most influential features (by |weight|):")
    print(coefs.head(10).to_string())

    os.makedirs(args.out_dir, exist_ok=True)
    model_data = {
        "weights": weights.tolist(),
        "bias": float(bias),
        "feature_means": means.tolist(),
        "feature_stds": stds.tolist(),
        "features": features,
        "validation_results": {k: v for k, v in results.items() if k != "confusion_matrix"},
        "confusion_matrix": results["confusion_matrix"],
    }
    out_path = os.path.join(args.out_dir, "model.json")
    with open(out_path, "w") as f:
        json.dump(model_data, f, indent=2)
    print(f"\nSaved model to {out_path}")


if __name__ == "__main__":
    main()
