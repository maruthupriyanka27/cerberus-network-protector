"""
Evaluation chapter generator — trains and compares several models on CICIDS2017
and writes every table, figure and a draft of the written results.

    python ml/evaluate.py --data-dir "K:\\MP3\\MachineLearningCSV\\MachineLearningCVE"
    python ml/evaluate.py --data-dir "..." --live-data ml/data/benign.jsonl ml/data/nat_8082.jsonl ml/data/attack.jsonl

Output goes to ml/evaluation/ :
    report.md            tables + draft text for the chapter (numbers filled in)
    results.json         every number, for your own charts/tables
    fig_*.png            confusion matrices, ROC curves, per-attack recall,
                         threshold trade-off, feature importance

Two evaluation protocols (state both in the report — the gap between them is a finding):

  A. Random split (75 / 25, stratified). The usual way CICIDS2017 is scored.
     OPTIMISTIC: flows from the same attack session sit on both sides of the
     split, so the model is partly tested on near-copies of what it trained on.

  B. Day split: train on Monday-Thursday, test on Friday.
     Friday holds DDoS, PortScan and Bot traffic — attack types that do NOT
     appear in Mon-Thu — so this measures how well a model catches attacks it
     has never seen. Expect lower recall than A; that is the honest number.

Models compared (same 7 features the live proxy can compute):
    Logistic Regression   simple linear baseline
    Decision Tree         single tree, depth 7 (what a forest is built from)
    Random Forest         30 trees, depth 7 — the configuration deployed in the proxy
    Gradient Boosting     stronger reference; NOT deployed (the proxy walks plain trees)

Optional --live-data adds a third section: the CICIDS2017-trained models are
scored on windows recorded from the running proxy. That quantifies the domain
shift (flow features vs HTTP-request features) and is why the proxy serves a
model trained on live recordings.
"""

import argparse
import glob
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Avg Packet Size", "SYN Flag Count"]
RAW_NAME = {"Avg Packet Size": "Average Packet Size"}   # CICIDS2017 spells this one out
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- data ----
def load_cicids(data_dir):
    paths = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not paths:
        sys.exit(f"No CSV files found in {data_dir!r}")
    need = {RAW_NAME.get(f, f) for f in FEATURES} | {"Label"}
    frames = []
    for p in paths:
        print(f"  loading {os.path.basename(p)}", flush=True)
        # read only the 8 columns we need (the files have ~79) — faster, far less RAM
        df = pd.read_csv(p, low_memory=False, encoding="latin1", usecols=lambda c: c.strip() in need)
        df.columns = [c.strip() for c in df.columns]
        base = os.path.basename(p).lower()
        df["day"] = next((d for d in DAYS if base.startswith(d.lower())), "unknown")
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    missing = [c for c in need if c not in full.columns]
    if missing:
        sys.exit(f"Missing columns in your CSVs: {missing}")
    full[list(need - {"Label"})] = full[list(need - {"Label"})].replace([np.inf, -np.inf], np.nan)
    full = full.dropna()
    full = full.rename(columns={v: k for k, v in RAW_NAME.items()})
    full["Label"] = full["Label"].astype(str).str.strip().str.replace("\x96", "-", regex=False)
    full["y"] = (full["Label"].str.upper() != "BENIGN").astype(int)
    print(f"  {len(full):,} clean rows (benign {int((full.y == 0).sum()):,} / attack {int((full.y == 1).sum()):,})")
    return full


def load_live(paths):
    rows = []
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    rows.append(r["x"] + ["BENIGN" if r["label"] == "benign" else "Attack (recorded live)", r["group"]])
    df = pd.DataFrame(rows, columns=FEATURES + ["Label", "group"])
    df["y"] = (df["Label"] != "BENIGN").astype(int)
    return df


# -------------------------------------------------------------- models ----
def make_models(seed):
    hgb_kw = {"class_weight": "balanced"}
    try:
        gb = HistGradientBoostingClassifier(max_iter=100, random_state=seed, **hgb_kw)
    except TypeError:                       # older scikit-learn without class_weight
        gb = HistGradientBoostingClassifier(max_iter=100, random_state=seed)
    return {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Decision Tree": DecisionTreeClassifier(max_depth=7, min_samples_leaf=5, class_weight="balanced", random_state=seed),
        "Random Forest": RandomForestClassifier(n_estimators=30, max_depth=7, min_samples_leaf=5,
                                                class_weight="balanced", random_state=seed, n_jobs=-1),
        "Gradient Boosting": gb,
    }


def fit_all(Xtr, ytr, seed):
    models = make_models(seed)
    for name, m in models.items():
        t = time.time()
        m.fit(Xtr, ytr)
        print(f"    trained {name:20s} {time.time() - t:5.1f}s", flush=True)
    return models


# ------------------------------------------------------------- metrics ----
def metrics(y, prob, thr=0.5):
    pred = (prob >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "miss_rate": float(fn / max(1, fn + tp)),
        "roc_auc": float(roc_auc_score(y, prob)) if len(set(y)) > 1 else float("nan"),
        "pr_auc": float(average_precision_score(y, prob)) if len(set(y)) > 1 else float("nan"),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n_benign": int(tn + fp), "n_attack": int(fn + tp),
    }


def recall_at_fpr(y, prob, max_fpr):
    """Best recall achievable while keeping false alarms at or below max_fpr."""
    fpr, tpr, thr = roc_curve(y, prob)
    i = int(np.where(fpr <= max_fpr)[0][-1])
    return {"max_fpr": max_fpr, "threshold": float(min(thr[i], 1.0)), "recall": float(tpr[i]), "actual_fpr": float(fpr[i])}


def per_attack(labels, prob, thr=0.5):
    out = {}
    for lab in sorted(set(labels)):
        if str(lab).upper() == "BENIGN":
            continue
        mask = labels == lab
        out[lab] = {"n": int(mask.sum()), "recall": float((prob[mask] >= thr).mean())}
    return out


def evaluate_protocol(models, Xte, yte, labels_te):
    probs = {n: m.predict_proba(Xte)[:, 1] for n, m in models.items()}
    return {
        "probs": probs,
        "metrics": {n: metrics(yte, p) for n, p in probs.items()},
        "per_attack": {n: per_attack(labels_te, p) for n, p in probs.items()},
        "operating_points": {n: [recall_at_fpr(yte, p, f) for f in (0.01, 0.001)] for n, p in probs.items()},
    }


# ------------------------------------------------------------- figures ----
def make_figures(out_dir, results, yte_by_proto, imp):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib not installed — skipping figures (pip install matplotlib)")
        return []
    made = []
    PNAME = {"A": "random split", "B": "day split (train Mon-Thu, test Fri)"}
    colors = {"Logistic Regression": "#9B92B8", "Decision Tree": "#E8A400", "Random Forest": "#6C47FF", "Gradient Boosting": "#00B37E"}

    for proto, res in results.items():
        y = yte_by_proto[proto]
        # confusion matrices, all models
        names = list(res["metrics"])
        fig, axs = plt.subplots(1, len(names), figsize=(3.6 * len(names), 3.6))
        for ax, n in zip(np.atleast_1d(axs), names):
            c = res["metrics"][n]["confusion"]
            cm = np.array([[c["tn"], c["fp"]], [c["fn"], c["tp"]]])
            norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
            ax.imshow(norm, cmap="Purples", vmin=0, vmax=1)
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, f"{cm[i, j]:,}\n{norm[i, j]*100:.1f}%", ha="center", va="center",
                            color="white" if norm[i, j] > 0.5 else "#221C35", fontsize=9)
            ax.set_xticks([0, 1]); ax.set_xticklabels(["Benign", "Attack"]); ax.set_yticks([0, 1]); ax.set_yticklabels(["Benign", "Attack"])
            ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(n, fontsize=10)
        fig.suptitle(f"Confusion matrices — {PNAME[proto]}", y=1.02); fig.tight_layout()
        f = f"fig_confusion_{proto[0].lower()}.png"; fig.savefig(os.path.join(out_dir, f), dpi=160, bbox_inches="tight"); plt.close(fig); made.append(f)

        # ROC curves
        fig, ax = plt.subplots(figsize=(5.2, 4.6))
        for n, p in res["probs"].items():
            fpr, tpr, _ = roc_curve(y, p)
            ax.plot(fpr, tpr, label=f"{n} (AUC {res['metrics'][n]['roc_auc']:.3f})", color=colors[n], lw=2)
        ax.plot([0, 1], [0, 1], "--", color="#bbb", lw=1)
        ax.set_xlabel("False positive rate (legitimate flows wrongly flagged)"); ax.set_ylabel("True positive rate (attacks caught)")
        ax.set_title(f"ROC — {PNAME[proto]}"); ax.legend(loc="lower right", fontsize=8); ax.grid(alpha=.25)
        f = f"fig_roc_{proto[0].lower()}.png"; fig.savefig(os.path.join(out_dir, f), dpi=160, bbox_inches="tight"); plt.close(fig); made.append(f)

        # per-attack recall, Random Forest vs baseline
        pa_rf, pa_lr = res["per_attack"]["Random Forest"], res["per_attack"]["Logistic Regression"]
        labs = sorted(pa_rf, key=lambda k: -pa_rf[k]["n"])
        if labs:
            fig, ax = plt.subplots(figsize=(7, 0.45 * len(labs) + 1.4))
            yy = np.arange(len(labs))
            ax.barh(yy + .2, [pa_lr[l]["recall"] * 100 for l in labs], .38, color=colors["Logistic Regression"], label="Logistic Regression")
            ax.barh(yy - .2, [pa_rf[l]["recall"] * 100 for l in labs], .38, color=colors["Random Forest"], label="Random Forest")
            ax.set_yticks(yy); ax.set_yticklabels([f"{l}  (n={pa_rf[l]['n']:,})" for l in labs], fontsize=8)
            ax.invert_yaxis(); ax.set_xlim(0, 100); ax.set_xlabel("Recall (%)"); ax.set_title(f"Recall by attack type — {PNAME[proto]}")
            ax.legend(fontsize=8); ax.grid(axis="x", alpha=.25)
            f = f"fig_per_attack_{proto[0].lower()}.png"; fig.savefig(os.path.join(out_dir, f), dpi=160, bbox_inches="tight"); plt.close(fig); made.append(f)

        # threshold trade-off for the deployed model
        p = res["probs"]["Random Forest"]
        ths = np.linspace(0.05, 0.95, 37)
        rec = [metrics(y, p, t)["recall"] * 100 for t in ths]; fpr_ = [metrics(y, p, t)["false_positive_rate"] * 100 for t in ths]
        fig, ax = plt.subplots(figsize=(5.4, 4))
        ax.plot(ths, rec, color="#00B37E", lw=2, label="Attacks caught (recall)"); ax.plot(ths, fpr_, color="#E63971", lw=2, label="Legitimate flows flagged (FPR)")
        ax.axvline(0.5, color="#999", ls="--", lw=1); ax.text(0.51, 50, "deployed\nthreshold 0.5", fontsize=8, color="#666")
        ax.set_xlabel("Decision threshold"); ax.set_ylabel("%"); ax.set_title(f"Random Forest: recall vs false alarms\n{PNAME[proto]}", fontsize=10)
        ax.legend(fontsize=8); ax.grid(alpha=.25)
        f = f"fig_threshold_{proto[0].lower()}.png"; fig.savefig(os.path.join(out_dir, f), dpi=160, bbox_inches="tight"); plt.close(fig); made.append(f)

    if imp:
        fig, ax = plt.subplots(figsize=(5.6, 3.4))
        names = [d["feature"] for d in imp][::-1]; vals = [d["importance"] for d in imp][::-1]
        ax.barh(names, vals, color="#6C47FF"); ax.set_xlabel("Impurity-based importance"); ax.set_title("Random Forest feature importance (random-split model)")
        f = "fig_feature_importance.png"; fig.savefig(os.path.join(out_dir, f), dpi=160, bbox_inches="tight"); plt.close(fig); made.append(f)
    return made


# -------------------------------------------------------------- report ----
pct = lambda x: f"{x * 100:.2f}%"


def table(res):
    rows = ["| Model | Accuracy | Precision | Recall | F1 | False-positive rate | ROC-AUC |", "|---|---|---|---|---|---|---|"]
    for n, m in res["metrics"].items():
        mark = " **(deployed type)**" if n == "Random Forest" else ""
        rows.append(f"| {n}{mark} | {pct(m['accuracy'])} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | {pct(m['false_positive_rate'])} | {m['roc_auc']:.4f} |")
    return "\n".join(rows)


def conf_table(res, model="Random Forest"):
    c = res["metrics"][model]["confusion"]
    return (f"| | Predicted benign | Predicted attack |\n|---|---|---|\n"
            f"| **Actual benign** | {c['tn']:,} (true negatives) | {c['fp']:,} (false positives) |\n"
            f"| **Actual attack** | {c['fn']:,} (false negatives) | {c['tp']:,} (true positives) |")


def per_attack_table(res):
    models = list(res["per_attack"])
    labs = sorted(res["per_attack"]["Random Forest"], key=lambda k: -res["per_attack"]["Random Forest"][k]["n"])
    rows = ["| Attack type | Test flows | " + " | ".join(models) + " |", "|---|---|" + "---|" * len(models)]
    for l in labs:
        rows.append(f"| {l} | {res['per_attack'][models[0]][l]['n']:,} | " + " | ".join(pct(res["per_attack"][m][l]["recall"]) for m in models) + " |")
    return "\n".join(rows)


def build_report(a, results, meta, live, figs):
    A, B = results.get("A"), results.get("B")
    L = []
    L.append("# Evaluation — draft results chapter\n")
    L.append(f"_Generated {time.strftime('%Y-%m-%d %H:%M')} by `ml/evaluate.py`. Numbers below are computed, not typed in. "
             "The wording is a draft: read it, and edit it to match your own discussion._\n")
    L.append("## 1. Data and features\n")
    L.append(f"The CICIDS2017 CSVs (`MachineLearningCVE`) contain {meta['rows']:,} usable flows after removing rows with missing or infinite values: "
             f"{meta['benign']:,} benign ({meta['benign']/meta['rows']*100:.1f}%) and {meta['attack']:,} attack ({meta['attack']/meta['rows']*100:.1f}%). "
             "Every non-BENIGN label is treated as one class, “attack”, so the task is binary.\n")
    L.append("Seven features are used, chosen because the proxy can compute an equivalent for a live client: " + ", ".join(f"*{f}*" for f in FEATURES) + ".\n")
    L.append("Because the data is imbalanced, accuracy alone is misleading (predicting “benign” for everything would already score "
             f"{meta['benign']/meta['rows']*100:.1f}%). Precision, recall, F1, the false-positive rate and the confusion matrix are therefore reported, and models are trained with balanced class weights.\n")
    L.append("## 2. Method\n")
    L.append("Four models are compared on identical features: **Logistic Regression** (linear baseline), a single **Decision Tree** (depth 7), a **Random Forest** (30 trees, depth 7, the configuration exported to the proxy) and **Gradient Boosting** (a stronger reference that is not deployed, since the proxy evaluates plain trees).\n")
    L.append(f"* **Protocol A — random split.** {meta['rows_A']:,} flows sampled (stratified), 75% train / 25% test.\n"
             "* **Protocol B — day split.** Train on Monday–Thursday, test on Friday. Friday contains DDoS, PortScan and Bot traffic, which do not occur in Monday–Thursday, so this tests detection of attack types never seen in training.\n")
    for proto, name, res in (("A", "Protocol A — random split", A), ("B", "Protocol B — day split (train Mon–Thu, test Fri)", B)):
        if not res:
            continue
        m = res["metrics"]["Random Forest"]
        L.append(f"## 3{'a' if proto == 'A' else 'b'}. Results: {name}\n")
        L.append(f"Test set: {m['n_benign']:,} benign and {m['n_attack']:,} attack flows.\n")
        L.append(table(res) + "\n")
        L.append("Confusion matrix of the Random Forest at the deployed threshold (0.5):\n")
        L.append(conf_table(res) + "\n")
        L.append(f"Of every 1,000 legitimate flows the Random Forest wrongly flags about **{m['false_positive_rate'] * 1000:.1f}**, and it misses about **{m['miss_rate'] * 100:.1f}%** of attack flows.\n")
        op = res["operating_points"]["Random Forest"]
        L.append(f"Moving the threshold trades one error for the other: to hold false alarms at or below 1% the threshold becomes {op[0]['threshold']:.2f} and recall is {pct(op[0]['recall'])}; "
                 f"at or below 0.1% it becomes {op[1]['threshold']:.2f} and recall is {pct(op[1]['recall'])}.\n")
        L.append("Recall by attack type (threshold 0.5):\n")
        L.append(per_attack_table(res) + "\n")
        for f in figs:
            if f.startswith(("fig_confusion_" + proto.lower(), "fig_roc_" + proto.lower(), "fig_per_attack_" + proto.lower(), "fig_threshold_" + proto.lower())):
                L.append(f"![{f}]({f})\n")
    if A and B:
        ra, rb = A["metrics"]["Random Forest"], B["metrics"]["Random Forest"]
        L.append("## 4. Random split versus day split\n")
        drop = (ra["recall"] - rb["recall"]) * 100
        lead = (f"The Random Forest reaches recall {pct(ra['recall'])} and false-positive rate {pct(ra['false_positive_rate'])} under the random split, "
                f"and recall {pct(rb['recall'])} and false-positive rate {pct(rb['false_positive_rate'])} when tested on a day it has not seen. ")
        if drop > 1.0:
            body = (f"Recall falls by {drop:.1f} percentage points. The random split therefore overstates how well the model generalises, because flows from the same attack session appear in both training and test data. "
                    "The day-split figures are the more realistic estimate of behaviour against new attack campaigns, and the per-attack table above shows which attack types drive the difference.\n")
        else:
            body = (f"Recall changes by {-drop:+.1f} percentage points, so in this run the day split did not reduce detection of the unseen Friday attacks. "
                    "Compare the false-positive rates and the per-attack table before drawing a conclusion: a model can keep high recall on new attacks simply by flagging more legitimate traffic. "
                    "The day split remains the stricter test, because no Friday flow was available in training.\n")
        L.append(lead + body)
    if live:
        L.append("## 5. Domain shift: CICIDS2017 model on live proxy traffic\n")
        L.append(f"Windows recorded from the running proxy ({live['n_benign']:,} benign, {live['n_attack']:,} attack, {live['clients']} clients) were scored by the models trained on CICIDS2017 (Protocol A models), and compared with the same model type trained on the live recordings (clients kept entirely on one side of the split).\n")
        rows = ["| Model | Trained on | Recall | False-positive rate | Accuracy |", "|---|---|---|---|---|"]
        for n, m in live["cicids_models"].items():
            rows.append(f"| {n} | CICIDS2017 | {pct(m['recall'])} | {pct(m['false_positive_rate'])} | {pct(m['accuracy'])} |")
        for n, m in live["live_models"].items():
            rows.append(f"| {n} | live recordings | {pct(m['recall'])} | {pct(m['false_positive_rate'])} | {pct(m['accuracy'])} |")
        L.append("\n".join(rows) + "\n")
        L.append("The same feature names mean different things in the two settings: in CICIDS2017 a “packet” is a network packet and “SYN Flag Count” counts TCP flags in a flow; in the proxy one HTTP request or response is counted as one packet and a new TCP connection stands in for a SYN. "
                 "A model trained on one therefore sees a shifted distribution on the other. Models trained on recordings from the proxy itself avoid this mismatch but rest on far less, and far less varied, data.\n")
    L.append("## 6. Threats to validity (state these in the report)\n")
    L.append("* **Optimistic random split** — see section 4.\n"
             "* **Binary labels** — all attack types are merged; the model does not say which attack it saw.\n"
             "* **Approximate live features** — the proxy cannot see network packets, so its features approximate CICIDS2017 flow statistics (see section 5).\n"
             "* **Lab traffic** — CICIDS2017 is a 2017 testbed; real traffic and current attacks differ.\n"
             "* **Small live dataset** — recordings from the proxy come from scripted and a few human sessions; metrics on them have wide uncertainty.\n"
             "* **Rule layer not included** — these figures are for the ML model alone. In the proxy the model only adds up to 30 points to a rule-based score, so end-to-end behaviour differs from the numbers above.\n")
    if figs:
        L.append("## Other figures\n")
        for f in figs:
            if "importance" in f:
                L.append(f"![{f}]({f})\n")
    return "\n".join(L)


# ---------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True, help="folder with the CICIDS2017 MachineLearningCVE CSVs")
    ap.add_argument("--live-data", nargs="+", help="optional .jsonl files recorded from the proxy (ML_RECORD)")
    ap.add_argument("--max-rows", type=int, default=600000, help="rows sampled for Protocol A")
    ap.add_argument("--max-train", type=int, default=400000, help="max training rows for Protocol B")
    ap.add_argument("--out", default=os.path.join(HERE, "evaluation"))
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    print("Loading CICIDS2017...", flush=True)
    df = load_cicids(a.data_dir)
    meta = {"rows": int(len(df)), "benign": int((df.y == 0).sum()), "attack": int((df.y == 1).sum())}
    results, ytes, imp, models_A = {}, {}, None, None

    # ---- Protocol A: random stratified split ----
    print("\nProtocol A — random split", flush=True)
    dfa = df if len(df) <= a.max_rows else train_test_split(df, train_size=a.max_rows, stratify=df["y"], random_state=a.seed)[0]
    meta["rows_A"] = int(len(dfa))
    tr, te = train_test_split(dfa, test_size=0.25, stratify=dfa["y"], random_state=a.seed)
    models_A = fit_all(tr[FEATURES], tr["y"].values, a.seed)
    results["A"] = evaluate_protocol(models_A, te[FEATURES], te["y"].values, te["Label"].values)
    ytes["A"] = te["y"].values
    rf = models_A["Random Forest"]
    imp = sorted(({"feature": f, "importance": float(v)} for f, v in zip(FEATURES, rf.feature_importances_)), key=lambda d: -d["importance"])

    # ---- Protocol B: train Mon-Thu, test Fri ----
    print("\nProtocol B — day split", flush=True)
    trB, teB = df[df.day.isin(["Monday", "Tuesday", "Wednesday", "Thursday"])], df[df.day == "Friday"]
    if len(teB) == 0 or len(trB) == 0 or teB.y.nunique() < 2:
        print("  Could not find Monday–Thursday and Friday files by name — skipping Protocol B.")
    else:
        if len(trB) > a.max_train:
            trB = train_test_split(trB, train_size=a.max_train, stratify=trB["y"], random_state=a.seed)[0]
        models_B = fit_all(trB[FEATURES], trB["y"].values, a.seed)
        results["B"] = evaluate_protocol(models_B, teB[FEATURES], teB["y"].values, teB["Label"].values)
        ytes["B"] = teB["y"].values

    # ---- Optional: live proxy traffic ----
    live = None
    if a.live_data:
        print("\nLive proxy windows", flush=True)
        ld = load_live(a.live_data)
        if ld.y.nunique() == 2:
            on_live = {n: metrics(ld["y"].values, m.predict_proba(ld[FEATURES])[:, 1]) for n, m in models_A.items()}
            gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=a.seed)
            tri, tei = next(gss.split(ld[FEATURES], ld["y"], groups=ld["group"]))
            lm = fit_all(ld.iloc[tri][FEATURES], ld.iloc[tri]["y"].values, a.seed)
            trained_live = {n: metrics(ld.iloc[tei]["y"].values, m.predict_proba(ld.iloc[tei][FEATURES])[:, 1]) for n, m in lm.items()}
            live = {"n_benign": int((ld.y == 0).sum()), "n_attack": int((ld.y == 1).sum()), "clients": int(ld["group"].nunique()),
                    "cicids_models": on_live, "live_models": trained_live}
        else:
            print("  live data has only one class — skipping.")

    figs = make_figures(a.out, results, ytes, imp)
    report = build_report(a, results, meta, live, figs)
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    dump = {"meta": meta, "feature_importance": imp, "live": live,
            "protocols": {p: {k: v for k, v in r.items() if k != "probs"} for p, r in results.items()}}
    with open(os.path.join(a.out, "results.json"), "w") as f:
        json.dump(dump, f, indent=2)

    print("\n=== Summary (threshold 0.5) ===")
    for p, r in results.items():
        print(f"Protocol {p}:")
        for n, m in r["metrics"].items():
            print(f"  {n:20s} acc {m['accuracy']:.4f}  prec {m['precision']:.4f}  recall {m['recall']:.4f}  F1 {m['f1']:.4f}  FPR {m['false_positive_rate']:.4f}  AUC {m['roc_auc']:.4f}")
    print(f"\nWrote {a.out}{os.sep}report.md, results.json and {len(figs)} figures.")


if __name__ == "__main__":
    main()
