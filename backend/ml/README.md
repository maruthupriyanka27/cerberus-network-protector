# ML component — how the live model works and how to retrain it

The proxy scores every request with a Random Forest (`model.json`) and shows the
result on the dashboard (ML probability per visitor, per-request feature
contributions, model metrics). Nothing on that panel is typed in: it all comes
from `model.json`, which `train_export.py` writes.

## What gets scored

Each client (fingerprint) gets a sliding 10-second window. From it the proxy
computes the same 7 features used for training — the CICIDS2017 column names are
kept so the two worlds line up:

| Feature | Live meaning |
|---|---|
| Flow Duration | span of the window, microseconds |
| Total Fwd Packets | requests in the window |
| Total Backward Packets | responses finished in the window |
| Flow Bytes/s | (request + response bytes) / duration |
| Flow Packets/s | (fwd + bwd) / duration |
| Avg Packet Size | bytes / (fwd + bwd) |
| SYN Flag Count | new TCP connections from that IP in the window (counted by `tcp-monitor.js`) |

**Honest caveat (say this in the report):** one HTTP request/response is counted
as one "packet" each way. That is the limit of an application-layer proxy; it is
an approximation of a network flow, not the real thing. A model trained on raw
CICIDS2017 flows therefore sees a *different* distribution at runtime than at
training time (domain shift). That is why there are three training sources below.

A client needs at least 3 requests in the window before the model gives a verdict.

## How the model affects decisions (`ML_MODE`)

| Mode | Effect |
|---|---|
| `off` | model not used |
| `shadow` | scored and displayed, never changes a decision |
| `assist` (default) | adds up to **+30** to the rule score. ML alone can never reach `challenge` (40); it tips borderline clients |
| `enforce` | adds up to **+60** (ML alone can reach `challenge`) |

Windows: `set ML_MODE=shadow && npm run start:proxy`   (PowerShell: `$env:ML_MODE="shadow"; npm run start:proxy`)

## Training

Install once: `pip install pandas scikit-learn numpy`

### A. On your recorded traffic (matches what the proxy computes — recommended for the serving model)

1. Normal visitors. Start the proxy in recording mode and browse the demo site
   like a person for 5–10 minutes (several tabs, fast and slow clicking, cart, search):

   PowerShell:
   ```
   cd backend
   $env:ML_RECORD="ml/data/benign.jsonl"; $env:ML_RECORD_LABEL="benign"; npm run start:proxy
   ```
2. Attacks. Stop it, then start it again with label `attack` and run your attack
   tools at it (the simulator page's attack mode, `npm run sim:tcp-flood`, a small
   script that hammers `/search`, nping `--tcp-connect`, etc.):
   ```
   $env:ML_RECORD="ml/data/attack.jsonl"; $env:ML_RECORD_LABEL="attack"; npm run start:proxy
   ```
   In recording mode the proxy lets everything through, so the response sizes and
   timings come from the real site rather than from the proxy's own block pages.
3. Clear the variables (`Remove-Item Env:ML_RECORD; Remove-Item Env:ML_RECORD_LABEL`) and train:
   ```
   python ml/train_export.py --live-data ml/data/benign.jsonl ml/data/attack.jsonl
   ```
   Record from several *different* clients (different `X-Sim-Client` ids, phones/laptops).
   The train/test split keeps each client entirely on one side so the reported
   score is not inflated by near-duplicate windows.

### B. On the real CICIDS2017 CSVs (use for the offline evaluation chapter)

```
python ml/train_export.py --data-dir "K:\MP3\MachineLearningCSV\MachineLearningCVE"
```
Reports accuracy / precision / recall / F1 / false-alarm rate / ROC-AUC on a
held-out 25 %, per-attack-type recall, and a Logistic Regression baseline.

### C. Both together

```
python ml/train_export.py --data-dir "K:\...\MachineLearningCVE" --live-data ml/data/benign.jsonl ml/data/attack.jsonl
```

### D. No data at all (pipeline test only)

```
python ml/train_export.py --synthetic
```
The dashboard shows an amber "synthetic demo data" badge for such a model.

After training, **restart the proxy** — it loads `model.json` at start-up.

## Checking the export

```
node ml/verify-parity.js
```
Replays 60 held-out rows through the Node tree-walker and compares with
scikit-learn's own probabilities (they agree to ~1e-6), and checks that the
feature contributions add up to the prediction.

## About the explanation panel

Per-request contributions use tree-path attribution (Saabas): walking each
tree, the change in P(attack) at every split is credited to that split's
feature; contributions sum exactly to `P(attack) − bias`. It is **not** the
SHAP library's TreeSHAP, and the dashboard says so. If a reviewer wants real
SHAP, run `shap.TreeExplainer` offline on the test set for the report.

## Lesson learned: record "several people behind one IP" too

The first model was trained only on single-person clients and scored 0% false
alarms on its own test set — but when several people shared one IP (a college
NAT, or one laptop with the demo and dashboard tabs open) it flagged 50–67% of
normal browsing as attack-like. Adding shared-IP browsing sessions to the
training data fixed it: on households it had never seen, 82 of 82 requests were
allowed and only ~4% of windows scored above 0.5 (max 0.58).

So when you record your own "benign" data, include a mix: one person, 2–3
people on the same IP, and the dashboard open in another tab. A test set made
of the same kind of clients as the training set will always look better than
real life — report that limitation.

## Current model (what the dashboard shows)

Trained on 1,622 windows from 133 clients recorded from this proxy by scripted
browser and attacker clients (not CICIDS2017, not human volunteers): attack
recall 89.3%, precision 98.9%, false-alarm rate 2.0%, ROC-AUC 0.970 on a
group-held-out 458 rows. Treat these as a demonstration of the pipeline, not as
a benchmark. For the report's evaluation chapter use `--data-dir` (option B) on
the real CICIDS2017 CSVs, and re-record with real people on real devices.
