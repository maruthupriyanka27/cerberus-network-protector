"""
Train the Signal Room attack classifier and EXPORT it as model.json so the
Node proxy can run it live (no Python needed at runtime).

Two data sources:

  python train_export.py --data-dir "K:\\MP3\\MachineLearningCSV\\MachineLearningCVE"
      Trains on the real CICIDS2017 CSVs. USE THIS for your final demo/report.

  python train_export.py --live-data data/benign.jsonl data/attack.jsonl
      Trains on windows recorded from YOUR OWN proxy (ML_RECORD mode, see
      lib/ml-scorer.js). These have exactly the semantics the proxy computes
      at runtime, so they avoid the CICIDS-flow vs HTTP-window mismatch.

  python train_export.py --synthetic
      Trains on a generated stand-in so the pipeline can be tested without
      any data. Stamped "synthetic-demo"; the dashboard shows that stamp.
      It is NOT a CICIDS2017 result.

Sources can be combined, e.g. --data-dir ... --live-data ...

What gets exported (model.json):
  * the Random Forest as plain arrays (feature / threshold / children / P(attack)
    per node) -> backend/lib/ml-scorer.js walks the same trees at request time
  * held-out test metrics (accuracy, precision, recall, F1, FPR, ROC-AUC,
    confusion matrix) and a Logistic Regression baseline for comparison
  * permutation importance (global "which features matter" - computed, not typed in)
  * provenance: dataset, row counts, training time

Features are the 7 that the proxy can compute for a live client from what it
actually observes (see lib/ml-scorer.js for the exact mapping):
  Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Bytes/s,
  Flow Packets/s, Avg Packet Size, SYN Flag Count
"""

import argparse
import glob
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Avg Packet Size", "SYN Flag Count"]
RAW_NAME = {"Avg Packet Size": "Average Packet Size"}  # CICIDS2017 spells this one out
N_TREES, MAX_DEPTH = 30, 7


# --------------------------------------------------------------------------
# Data sources
# --------------------------------------------------------------------------
def load_cicids(data_dir, max_rows, seed):
    paths = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not paths:
        sys.exit(f"No CSV files found in {data_dir!r}")
    frames = []
    for p in paths:
        print(f"  loading {os.path.basename(p)}")
        df = pd.read_csv(p, low_memory=False, encoding="latin1")
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    need = [RAW_NAME.get(f, f) for f in FEATURES] + ["Label"]
    missing = [c for c in need if c not in full.columns]
    if missing:
        sys.exit(f"Missing columns in your CSVs: {missing}")
    full = full[need].replace([np.inf, -np.inf], np.nan).dropna()
    full = full.rename(columns={v: k for k, v in RAW_NAME.items()})
    full["Label"] = full["Label"].astype(str).str.strip()
    full["y"] = (full["Label"].str.upper() != "BENIGN").astype(int)
    print(f"  {len(full):,} clean rows  (benign {int((full.y==0).sum()):,} / attack {int((full.y==1).sum()):,})")
    if len(full) > max_rows:
        full, _ = train_test_split(full, train_size=max_rows, stratify=full["y"], random_state=seed)
        print(f"  stratified down to {len(full):,} rows for training speed (--max-rows)")
    return full, "CICIDS2017 (MachineLearningCVE)"


def load_live(paths):
    rows = []
    for p in paths:
        n0 = len(rows)
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                rows.append(r["x"] + ["BENIGN" if r["label"] == "benign" else "Attack (recorded live)", r["group"]])
        print(f"  {p}: {len(rows) - n0:,} recorded windows")
    df = pd.DataFrame(rows, columns=FEATURES + ["Label", "group"])
    df["y"] = (df["Label"] != "BENIGN").astype(int)
    print(f"  {len(df):,} live windows from {df['group'].nunique()} distinct clients "
          f"(benign {int((df.y==0).sum()):,} / attack {int((df.y==1).sum()):,})")
    return df, "windows recorded live from this proxy"


def make_synthetic(n, seed):
    """Per-client 10-second windows as the proxy's own extractor would see them.
    Constructed by hand - plausible, overlapping, but NOT real traffic."""
    rng = np.random.default_rng(seed)
    rows = []

    def window(kind):
        if kind == "human":      # browsing: a page plus its assets, bursty then quiet
            n_req = 1 + rng.poisson(7)
            dur = rng.uniform(0.6, 9.5)
            resp = rng.lognormal(np.log(14000), 0.9)
            syn = 1 + min(5, rng.poisson(1.3))
        elif kind == "heavy_human":  # power user: many tabs/assets, overlaps with mild attacks
            n_req = rng.integers(14, 50)
            dur = rng.uniform(3, 10)
            resp = rng.lognormal(np.log(9000), 0.8)
            syn = 2 + min(8, rng.poisson(2.5))
        elif kind == "mild_flood":   # modest flood that looks a lot like a busy human
            n_req = rng.integers(18, 70)
            dur = rng.uniform(2, 10)
            resp = rng.lognormal(np.log(6000), 0.8)
            syn = 1 + rng.integers(0, 10)
        elif kind == "poller":   # API client / crawler: steady, small, few connections
            n_req = rng.integers(3, 22)
            dur = rng.uniform(4, 10)
            resp = rng.lognormal(np.log(3500), 0.7)
            syn = 1 + rng.integers(0, 2)
        elif kind == "http_flood":   # keep-alive GET flood
            n_req = int(rng.lognormal(np.log(160), 0.7)) + 20
            dur = rng.uniform(2, 10)
            resp = rng.lognormal(np.log(4500), 0.5)
            syn = 1 + rng.integers(0, 7)
        elif kind == "conn_flood":   # new connection per request
            n_req = int(rng.lognormal(np.log(70), 0.6)) + 12
            dur = rng.uniform(1.5, 9)
            resp = rng.lognormal(np.log(1800), 0.6)
            syn = int(n_req * rng.uniform(0.5, 1.0)) + 4
        else:                        # low-and-slow: few requests, tiny, many conns
            n_req = rng.integers(8, 30)
            dur = rng.uniform(7, 10)
            resp = rng.lognormal(np.log(700), 0.5)
            syn = rng.integers(6, 40)
        req_b = rng.lognormal(np.log(520), 0.25)
        fwd, bwd = n_req, max(1, int(n_req * rng.uniform(0.88, 1.0)))
        total_bytes = fwd * req_b + bwd * resp
        pkts = fwd + bwd
        return [dur * 1e6, fwd, bwd, total_bytes / dur, pkts / dur, total_bytes / pkts, syn]

    kinds = (["human"] * 44 + ["heavy_human"] * 8 + ["poller"] * 10 + ["mild_flood"] * 10
             + ["http_flood"] * 14 + ["conn_flood"] * 8 + ["slow"] * 6)
    for k in rng.choice(kinds, size=n):
        rows.append(window(k) + [k])
    df = pd.DataFrame(rows, columns=FEATURES + ["Label"])
    df["y"] = df["Label"].isin(["http_flood", "conn_flood", "slow", "mild_flood"]).astype(int)
    df["Label"] = df["Label"].map({"human": "BENIGN", "heavy_human": "BENIGN", "poller": "BENIGN",
                                   "mild_flood": "Mild flood (synthetic)", "http_flood": "HTTP flood (synthetic)",
                                   "conn_flood": "Connection flood (synthetic)", "slow": "Low-and-slow (synthetic)"})
    return df, "synthetic-demo (generated stand-in, NOT CICIDS2017)"


# --------------------------------------------------------------------------
# Export + metrics
# --------------------------------------------------------------------------
def export_forest(rf):
    trees = []
    for est in rf.estimators_:
        t = est.tree_
        counts = t.value[:, 0, :]
        p_attack = counts[:, 1] / counts.sum(axis=1)   # exactly what predict_proba averages
        trees.append({
            "f": [int(x) for x in t.feature],              # -2 on leaves
            "t": [round(float(x), 6) for x in t.threshold],
            "l": [int(x) for x in t.children_left],
            "r": [int(x) for x in t.children_right],
            "v": [round(float(x), 5) for x in p_attack],
        })
    return trees


def evaluate(y_true, prob):
    pred = (prob >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, pred), 4),
        "f1": round(f1_score(y_true, pred), 4),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "roc_auc": round(roc_auc_score(y_true, prob), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir")
    ap.add_argument("--live-data", nargs="+", help="one or more .jsonl files recorded with ML_RECORD")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--synthetic-rows", type=int, default=20000)
    ap.add_argument("--max-rows", type=int, default=600000)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.json"))
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    if not (a.data_dir or a.live_data or a.synthetic):
        sys.exit("Pass at least one of: --data-dir <CICIDS2017 folder> | --live-data <files.jsonl> | --synthetic")

    print("Loading data...")
    parts, names = [], []
    if a.data_dir:
        d, n = load_cicids(a.data_dir, a.max_rows, a.seed); parts.append(d); names.append(n)
    if a.live_data:
        d, n = load_live(a.live_data); parts.append(d); names.append(n)
    if a.synthetic:
        d, n = make_synthetic(a.synthetic_rows, a.seed); parts.append(d); names.append(n)
    df = pd.concat(parts, ignore_index=True)
    dataset_name = " + ".join(names)
    has_synthetic = bool(a.synthetic)

    # Rows from the same live client are near-duplicates of each other, so the
    # train/test split keeps every client entirely on one side (otherwise the
    # test score would be inflated by memorised clients).
    if "group" not in df.columns:
        df["group"] = None
    df["group"] = [g if isinstance(g, str) else f"row{i}" for i, g in enumerate(df["group"])]
    X, y = df[FEATURES].astype(float), df["y"].values
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=a.seed)
    tr_idx, te_idx = next(gss.split(X, y, groups=df["group"]))
    Xtr, Xte, ytr, yte = X.iloc[tr_idx], X.iloc[te_idx], y[tr_idx], y[te_idx]
    lab_te = df["Label"].values[te_idx]
    if len(set(yte)) < 2 or len(set(ytr)) < 2:
        sys.exit("The split left only one class on one side — record more clients/sessions of both kinds.")

    print("Training Random Forest + Logistic Regression baseline...")
    rf = RandomForestClassifier(n_estimators=N_TREES, max_depth=MAX_DEPTH, min_samples_leaf=5,
                                class_weight="balanced", random_state=a.seed, n_jobs=-1).fit(Xtr, ytr)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")).fit(Xtr, ytr)

    rf_prob, lr_prob = rf.predict_proba(Xte)[:, 1], lr.predict_proba(Xte)[:, 1]
    rf_m, lr_m = evaluate(yte, rf_prob), evaluate(yte, lr_prob)

    per_type = {}
    for lab in sorted(set(lab_te)):
        if lab.upper() == "BENIGN":
            continue
        mask = lab_te == lab
        per_type[lab] = {"n": int(mask.sum()), "recall": round(float((rf_prob[mask] >= 0.5).mean()), 4)}

    print("Computing permutation importance...")
    sub = np.random.default_rng(a.seed).choice(len(Xte), size=min(5000, len(Xte)), replace=False)
    pi = permutation_importance(rf, Xte.iloc[sub], yte[sub], scoring="f1", n_repeats=5, random_state=a.seed, n_jobs=-1)
    importance = sorted(({"feature": f, "importance": round(float(m), 4)} for f, m in zip(FEATURES, pi.importances_mean)),
                        key=lambda d: -d["importance"])

    model = {
        "format": 1,
        "features": FEATURES,
        "n_trees": N_TREES, "max_depth": MAX_DEPTH,
        "trees": export_forest(rf),
        "bias": round(float(np.mean([t["v"][0] for t in export_forest(rf)])), 5),
        "provenance": {
            "dataset": dataset_name,
            "is_real_dataset": not has_synthetic,
            "sources": names,
            "clients": int(df["group"].nunique()) if a.live_data else None,
            "rows_total": int(len(df)), "rows_train": int(len(Xtr)), "rows_test": int(len(Xte)),
            "attack_share": round(float(y.mean()), 4),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "metrics": {"random_forest": rf_m, "logistic_regression_baseline": lr_m, "per_attack_type_recall": per_type},
        "importance": importance,
        "threshold": 0.5,
    }
    with open(a.out, "w") as f:
        json.dump(model, f, separators=(",", ":"))

    # Parity fixture: 60 held-out rows + sklearn's own probabilities, so
    # verify-parity.js can prove the Node walker reproduces sklearn exactly.
    pick = np.random.default_rng(a.seed).choice(len(Xte), size=60, replace=False)
    with open(os.path.join(os.path.dirname(a.out), "parity_check.json"), "w") as f:
        json.dump({"x": Xte.iloc[pick].values.tolist(), "prob": [float(p) for p in rf_prob[pick]]}, f)

    print(f"\nDataset: {dataset_name}")
    print(f"Test rows: {len(Xte):,}")
    for name, m in (("Random Forest", rf_m), ("Logistic Reg.", lr_m)):
        print(f"  {name:14s} acc {m['accuracy']:.4f}  prec {m['precision']:.4f}  recall {m['recall']:.4f}  "
              f"F1 {m['f1']:.4f}  FPR {m['false_positive_rate']:.4f}  AUC {m['roc_auc']:.4f}")
    print("Permutation importance:", ", ".join(f"{d['feature']} {d['importance']:.3f}" for d in importance))
    print(f"\nWrote {a.out} ({os.path.getsize(a.out)/1024:.0f} KB)")
    if has_synthetic:
        print("\nREMINDER: this model is trained on SYNTHETIC data. Re-run with --data-dir on your real CICIDS2017 CSVs before presenting.")


if __name__ == "__main__":
    main()
