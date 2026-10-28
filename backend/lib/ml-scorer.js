/**
 * Live ML scoring — runs the exported Random Forest (ml/model.json) on each
 * client's recent traffic. No Python at runtime: train_export.py writes the
 * trees as plain arrays and this file walks them.
 *
 * ---- How a live client becomes a "flow" ----
 * CICIDS2017 rows are network flows. The proxy sees HTTP requests, so for each
 * client (fingerprint) it keeps a sliding 10-second window and derives the
 * same 7 features the model was trained on:
 *
 *   Flow Duration           window span, microseconds (floored at 50 ms)
 *   Total Fwd Packets       requests from the client in the window
 *   Total Backward Packets  responses finished in the window
 *   Flow Bytes/s            (request bytes + response bytes) / duration
 *   Flow Packets/s          (fwd + bwd) / duration
 *   Avg Packet Size         total bytes / (fwd + bwd)
 *   SYN Flag Count          new TCP connections from that IP in the window
 *                           (counted by tcp-monitor.js at the socket)
 *
 * This is an APPROXIMATION: one HTTP request/response is counted as one
 * "packet" in each direction. It is the honest limit of an application-layer
 * proxy, and is the main caveat to state in the report.
 *
 * ---- Explanations ----
 * For every scored request the per-feature contribution is computed by tree
 * path attribution (Saabas): walking a tree, each split's change in P(attack)
 * is credited to that split's feature. Contributions sum exactly to
 * P(attack) - bias. This is NOT the SHAP library's TreeSHAP (that needs a
 * heavier algorithm); the dashboard labels it accordingly.
 *
 * ---- Recording your own labelled data (env ML_RECORD / ML_RECORD_LABEL) ----
 * A model trained only on CICIDS2017 flows sees a different "world" from the
 * proxy's per-client HTTP windows (e.g. how many TCP connections a real
 * browser opens per request). To train on data that matches what the proxy
 * actually computes, start it in recording mode — every scored window is
 * appended to a .jsonl file with a fixed label:
 *
 *   ML_RECORD=ml/data/benign.jsonl ML_RECORD_LABEL=benign node proxy-server.js   (browse the demo site normally)
 *   ML_RECORD=ml/data/attack.jsonl ML_RECORD_LABEL=attack node proxy-server.js   (run the attack scripts)
 *
 * then: python ml/train_export.py --live-data ml/data/benign.jsonl ml/data/attack.jsonl
 *
 * ---- Modes (env ML_MODE) ----
 *   off      — model not used
 *   shadow   — scored and shown on the dashboard, never changes a decision
 *   assist   — (default) adds up to +30 to the rule score, so ML alone can
 *              never push a client past 'challenge' (40): it tips borderline
 *              clients, rules still do the heavy lifting
 *   enforce  — adds up to +60 (ML alone can reach 'challenge')
 */
const fs = require('fs');
const path = require('path');

const WINDOW_MS = 10_000;
const MIN_REQUESTS = 3;        // not enough evidence below this -> no ML verdict
const MIN_DURATION_MS = 50;
const TYPICAL_RESPONSE_BYTES = 2300;
const MAX_EVENTS_PER_CLIENT = 2000;

const RECORD_FILE = process.env.ML_RECORD || '';
const RECORD_LABEL = (process.env.ML_RECORD_LABEL || '').toLowerCase();
const recordLast = new Map(); // fp -> last time a window was written (throttle)
if (RECORD_FILE) {
  if (!['benign', 'attack'].includes(RECORD_LABEL)) {
    console.error('[ml] ML_RECORD is set but ML_RECORD_LABEL must be "benign" or "attack" — recording disabled.');
  } else {
    fs.mkdirSync(path.dirname(path.resolve(RECORD_FILE)), { recursive: true });
    console.log(`[ml] RECORDING every scored window as "${RECORD_LABEL}" -> ${RECORD_FILE}`);
  }
}

const MODE = (process.env.ML_MODE || 'assist').toLowerCase();
const MAX_BOOST = { off: 0, shadow: 0, assist: 40, enforce: 60 }[MODE] ?? 30;

let model = null;
try {
  model = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'ml', 'model.json'), 'utf8'));
  console.log(`[ml] model loaded — ${model.n_trees} trees, trained on: ${model.provenance.dataset} (mode: ${MODE})`);
  if (!model.provenance.is_real_dataset) {
    console.log('[ml] WARNING: this model was trained on SYNTHETIC data. Run ml/train_export.py --data-dir <CICIDS2017> for the real one.');
  }
} catch (e) {
  console.log('[ml] ml/model.json not found — ML scoring disabled. Run: python ml/train_export.py --synthetic (or --data-dir ...)');
}

const clients = new Map(); // fp -> [{ t, reqBytes, respBytes, done }]

/** Call once per incoming request. Returns a handle to wrap the response with. */
function begin(fp, req) {
  let reqBytes = Buffer.byteLength(`${req.method} ${req.originalUrl || req.url} HTTP/1.1\r\n`);
  for (const h of req.rawHeaders || []) reqBytes += Buffer.byteLength(h) + 2;
  reqBytes += Number(req.headers['content-length'] || 0);

  const ev = { t: Date.now(), reqBytes, respBytes: 0, done: false };
  let list = clients.get(fp);
  if (!list) { list = []; clients.set(fp, list); }
  list.push(ev);
  if (list.length > MAX_EVENTS_PER_CLIENT) list.splice(0, list.length - MAX_EVENTS_PER_CLIENT);
  return ev;
}

/** Count the bytes actually written to the client and mark the response done. */
function trackResponse(ev, res) {
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  const size = (chunk, enc) => (chunk == null || typeof chunk === 'function') ? 0 : Buffer.byteLength(chunk, typeof enc === 'string' ? enc : undefined);
  res.write = (chunk, enc, cb) => { ev.respBytes += size(chunk, enc); return write(chunk, enc, cb); };
  res.end = (chunk, enc, cb) => { ev.respBytes += size(chunk, enc); ev.done = true; return end(chunk, enc, cb); };
  res.on('close', () => { ev.done = true; });
}

/** The proxy served this request itself (block/challenge) instead of the real site. */
function markGate(ev) { ev.gate = true; }

function features(fp, ip, recentConnections, now = Date.now()) {
  const list = clients.get(fp);
  if (!list) return null;
  while (list.length && now - list[0].t > WINDOW_MS) list.shift();
  if (list.length < MIN_REQUESTS) return null;

  // Responses the gate itself generated (block / challenge pages) are tiny and
  // would drag "Avg Packet Size" towards zero for exactly the clients we are
  // blocking — the model would then call them benign. So the model is asked
  // about the client's BEHAVIOUR: a gate-served response is counted at the
  // size of this client's own real responses (or a typical page, if none).
  const real = list.filter((e) => !e.gate && e.done);
  const typical = real.length ? real.reduce((n, e) => n + e.respBytes, 0) / real.length : TYPICAL_RESPONSE_BYTES;

  const fwd = list.length;
  const bwd = list.filter((e) => e.done || e.gate).length;
  const durMs = Math.max(now - list[0].t, MIN_DURATION_MS);
  const durS = durMs / 1000;
  const bytes = list.reduce((n, e) => n + e.reqBytes + (e.gate ? typical : e.respBytes), 0);
  const pkts = fwd + bwd;
  const syn = Math.max(1, recentConnections(ip, WINDOW_MS));

  return { x: [durMs * 1000, fwd, bwd, bytes / durS, pkts / durS, bytes / Math.max(1, pkts), syn], requests: fwd, connections: syn, rps: fwd / durS };
}

/** Walk every tree: returns P(attack) and per-feature path contributions. */
function predict(x) {
  const nF = model.features.length;
  const contrib = new Array(nF).fill(0);
  let prob = 0;
  for (const t of model.trees) {
    let n = 0;
    while (t.l[n] !== -1) {
      const f = t.f[n];
      const next = x[f] <= t.t[n] ? t.l[n] : t.r[n];
      contrib[f] += t.v[next] - t.v[n];
      n = next;
    }
    prob += t.v[n];
  }
  const k = model.trees.length;
  return { prob: prob / k, contrib: contrib.map((c) => c / k) };
}

/**
 * Score a request. Returns null when ML has no verdict (disabled, or the
 * client hasn't made enough requests in the window to judge).
 */
function score(fp, ip, recentConnections) {
  const recording = RECORD_FILE && ['benign', 'attack'].includes(RECORD_LABEL);
  if ((!model || MODE === 'off') && !recording) return null;
  const f = features(fp, ip, recentConnections);
  if (!f) return null;
  const x = f.x;

  if (recording) {
    const now = Date.now();
    if (now - (recordLast.get(fp) || 0) >= 300) {   // ~3 windows/s per client is plenty
      recordLast.set(fp, now);
      fs.appendFileSync(RECORD_FILE, JSON.stringify({ x, label: RECORD_LABEL, group: fp, t: now }) + '\n');
    }
  }
  if (!model || MODE === 'off') return null;
  const { prob, contrib } = predict(x);

  const top = model.features
    .map((name, i) => ({ feature: name, value: x[i], contribution: contrib[i] }))
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    .slice(0, 5);

  const delta = prob >= model.threshold ? Math.round(MAX_BOOST * Math.min(1, (prob - 0.5) / 0.5)) : 0;
  return { prob: Number(prob.toFixed(4)), delta, mode: MODE, top, window: { requests: f.requests, connections: f.connections, rps: Number(f.rps.toFixed(1)) } };
}

function modelInfo() {
  if (!model) return { available: false, mode: MODE };
  return {
    available: true, mode: MODE, max_boost: MAX_BOOST,
    window_s: WINDOW_MS / 1000, min_requests: MIN_REQUESTS,
    n_trees: model.n_trees, max_depth: model.max_depth, features: model.features, bias: model.bias,
    provenance: model.provenance, metrics: model.metrics, importance: model.importance,
  };
}

// Housekeeping so idle clients don't pile up in memory.
setInterval(() => {
  const now = Date.now();
  for (const [fp, list] of clients) {
    while (list.length && now - list[0].t > WINDOW_MS) list.shift();
    if (!list.length) clients.delete(fp);
  }
}, 15_000).unref();

module.exports = { begin, trackResponse, markGate, score, modelInfo, predict: (x) => (model ? predict(x) : null) };
