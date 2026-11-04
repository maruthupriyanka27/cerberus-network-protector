# Signal Room — backend

## What this is
A real (if intentionally simple) version of the architecture you've been
designing: a reverse proxy that scores every request with a decaying
reputation score, and allows/challenges/blocks based on it — tested and
confirmed working end to end (see the terminal output in chat).

## Layout
```
backend/
  proxy-server.js      # the reverse proxy — scoring gate, PoW API, WebSocket feed (port 8080)
  demo-app-server.js    # the protected target app (port 3000)
  lib/
    fingerprint.js      # composite client key (IP/sim-id + headers)
    reputation.js        # sliding window + exponential decay + scoring
    pow.js               # real SHA-256 proof-of-work generate/verify
public/
  demo/                 # the protected site (demo-site.html + assets)
  console/              # dashboard.html, simulator.html, challenge.html (admin tooling, not scored)
```

## Running it
```bash
cd backend
npm install
npm run start:demo     # terminal 1 — the protected app on :3000
npm run start:proxy    # terminal 2 — the proxy + dashboard + scoring on :8080
```

Then open:
- `http://localhost:8080/` — the protected demo site, through the proxy
- `http://localhost:8080/_console/dashboard.html` — live dashboard (WebSocket-fed, real data)
- `http://localhost:8080/_console/simulator.html` — attack/legit traffic generator (fires real requests at the proxy)

Run the simulator in **legit mode** first, watch the dashboard stay green.
Then switch to **attack mode** and watch requests climb through allow →
challenge → block in real time — the exact demo moment your report is
built around.

## What's real vs. still a placeholder
**Real:** the scoring math (rate + headers + path-hammering + asset-loading
signals, with exponential decay), the allow/challenge/block tiering, the
proof-of-work puzzle generation and verification (actual SHA-256, not an
animation), the WebSocket feed to the dashboard.

**Still a placeholder, worth flagging honestly in your report:**
- Fingerprinting is IP + headers only (no TLS/JA3) — documented in
  `fingerprint.js` as the same kind of scoping simplification your threat
  model already calls out.
- The "ML confidence" chart and SHAP panel on the dashboard are not backed
  by a trained model — the confidence value is just average visitor score
  ÷ 100, and the SHAP bars are static sample values. If you want to make
  this real, `cicddos2019_sample.csv` is the right shape of data to train
  a small classifier on (ask and I'll build it).
- Reputation is stored in a plain in-memory `Map` — swap it for Redis when
  you want persistence across restarts / multiple proxy instances; the
  interface in `reputation.js` is written so that swap doesn't touch the
  scoring logic itself.
- The simulator can't spoof `User-Agent` from a browser (forbidden header),
  so the "missing headers" signal currently only checks for a missing
  `Accept` header — worth a one-line mention in your report's limitations
  section.
