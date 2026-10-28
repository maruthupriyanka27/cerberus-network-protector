const express = require('express');
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { WebSocketServer } = require('ws');

const { clientIp } = require('./lib/fingerprint');
const reputation = require('./lib/reputation');
const pow = require('./lib/pow');
const tcpMonitor = require('./lib/tcp-monitor');
const mlScorer = require('./lib/ml-scorer');

// ---- Two separate ports, one process ----
// PROXY_PORT is the ONLY thing meant to be internet/LAN-facing: the
// protected site, the scoring gate, and the PoW challenge page a real
// visitor is shown mid-request. ADMIN_PORT serves the dashboard and attack
// simulator — tooling nobody browsing the real site should be able to find
// or reach just by guessing a path on the public port. They share this one
// process (and therefore the same in-memory reputation/tcp-monitor/ML
// state) but are reachable, and firewallable, independently: when this
// goes on a real VPS, open PROXY_PORT to the world and leave ADMIN_PORT
// closed except to your own IP.
// HOSTED / SINGLE_PORT mode (Render etc.): the platform gives us ONE public
// port via PORT, sits a load balancer in front of us, and terminates TLS.
// So: admin console moves onto the same port behind ADMIN_TOKEN, client IPs
// come from X-Forwarded-For (trust proxy), and the raw-TCP monitor is OFF by
// default (it would only ever see the platform's load balancer, and could ban
// it). Locally / on a LAN / on your own VPS nothing changes: 8080 + 9000.
const SINGLE_PORT = process.env.SINGLE_PORT === '1' || !!process.env.RENDER;
const PROXY_PORT = process.env.PORT || process.env.PROXY_PORT || 8080;
const ADMIN_PORT = process.env.ADMIN_PORT || 9000;
const POW_BITS = Number(process.env.POW_BITS || 18);          // PoW difficulty (leading zero bits)
const ENABLE_LAB = (process.env.ENABLE_LAB || (SINGLE_PORT ? '0' : '1')) === '1'; // attack lab page on the public port (for the client PC)
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || SINGLE_PORT;
const TCP_MONITOR_ON = (process.env.TCP_MONITOR || (SINGLE_PORT ? 'off' : 'on')) !== 'off';
const crypto = require('crypto');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || (SINGLE_PORT ? crypto.randomBytes(9).toString('hex') : '');
const DEMO_APP_TARGET = process.env.DEMO_TARGET || 'http://localhost:3000';
const CONSOLE_DIR = path.join(__dirname, '..', 'public', 'console');
const DEMO_DIR = path.join(__dirname, '..', 'public', 'demo');

// ======================================================================
// Shared event bus — the scoring gate (public side) and the dashboard
// (admin side) need to talk to each other even though they're on
// different ports. broadcast() pushes to the admin WebSocket, the public
// alert WebSocket, and any Server-Sent Events subscribers on the demo site.
// ======================================================================
const wss = new WebSocketServer({ noServer: true }); // admin/dashboard feed
const sseClients = new Set();
const publicWss = new WebSocketServer({ noServer: true });

const securityState = {
  isAttacking: false,
  threatLevel: 'normal', // 'normal' | 'elevated' | 'critical'
  lastAttack: null,
  totalThreatsBlocked: 0,
  recentEvents: [],
};
let attackResetTimer = null;

function getSecuritySnapshot() {
  const isStale = securityState.lastAttack && (Date.now() - securityState.lastAttack.ts > 10000);
  if (isStale && securityState.isAttacking) {
    securityState.isAttacking = false;
    securityState.threatLevel = 'normal';
  }
  return {
    ...securityState,
    activeIpsBanned: tcpMonitor.snapshot().currentlyBannedIps || 0,
    activeSockets: tcpMonitor.snapshot().activeConnections || 0,
    timestamp: Date.now(),
  };
}

function broadcast(event) {
  const ts = event.ts || Date.now();
  event.ts = ts;

  // Track attack events for status and demo popups
  let isAttack = false;
  if (event.type === 'tcp') {
    isAttack = true;
    securityState.isAttacking = true;
    securityState.threatLevel = 'critical';
    securityState.totalThreatsBlocked++;
    securityState.lastAttack = {
      type: 'tcp',
      kind: event.kind,
      ip: event.ip,
      reason: event.reason || `${event.kind} detected`,
      ts,
    };
    securityState.recentEvents.unshift({ ...event, id: 'tcp_' + ts + '_' + Math.random().toString(36).slice(2, 6) });
  } else if (event.type === 'decision' && (event.tier === 'block' || event.tier === 'challenge' || (event.ml && event.ml.prob >= 0.65))) {
    isAttack = true;
    securityState.isAttacking = true;
    securityState.threatLevel = event.tier === 'block' ? 'critical' : 'elevated';
    securityState.totalThreatsBlocked++;
    securityState.lastAttack = {
      type: 'http',
      kind: event.tier,
      fp: event.fp,
      path: event.path,
      score: event.score,
      reasons: event.reasons,
      ml: event.ml,
      ts,
    };
    securityState.recentEvents.unshift({ ...event, id: 'http_' + ts + '_' + Math.random().toString(36).slice(2, 6) });
  }

  if (securityState.recentEvents.length > 60) securityState.recentEvents.pop();

  if (isAttack) {
    clearTimeout(attackResetTimer);
    attackResetTimer = setTimeout(() => {
      securityState.isAttacking = false;
      securityState.threatLevel = 'normal';
      broadcast({ type: 'status_update', ...getSecuritySnapshot() });
    }, 9000);
  }

  const msg = JSON.stringify(event);

  // Send to Admin WebSocket clients (port 9000)
  if (wss) {
    wss.clients.forEach((client) => {
      if (client.readyState === 1) client.send(msg);
    });
  }

  // Send to Public WebSocket clients (port 8080)
  if (publicWss) {
    publicWss.clients.forEach((client) => {
      if (client.readyState === 1) client.send(msg);
    });
  }

  // Send to Server-Sent Events subscribers on the demo site (port 8080)
  for (const client of sseClients) {
    try {
      client.write(`data: ${msg}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

function lanAddresses() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push({ name, address: a.address });
    }
  }
  return out;
}

// ======================================================================
// PUBLIC side (PROXY_PORT) — the protected site, the scoring gate, and
// the small set of console files a real visitor's browser actually needs
// mid-request (the PoW challenge page + its API, and shared CSS/JS). This
// app deliberately does NOT statically serve the whole /_console folder —
// dashboard.html / simulator.html / the model internals live only on the
// admin port.
// ======================================================================
const app = express();
const server = http.createServer(app);

// TCP-layer connection monitor — attached to the raw socket, ahead of
// Express and http-proxy-middleware. See lib/tcp-monitor.js.
if (TCP_MONITOR_ON) tcpMonitor.attach(server, {
  broadcast,
  // A TCP-layer ban is also an application-layer block, so the dashboard shows
  // ONE consistent state per client PC and both clear at the same moment.
  onBan: (ip, reason, until) => {
    reputation.forceBlock(ip, reason, 'tcp', until);
    broadcast({ type: 'visitor', action: 'blocked', source: 'tcp', ip, reason, until, ts: Date.now() });
  },
});
if (TRUST_PROXY) app.set('trust proxy', true); // req.ip = real client from X-Forwarded-For

// Attach public WebSocket upgrade on the proxy server (port 8080)
function cookieOf(req, name) {
  const m = (req.headers.cookie || '').split(/;\s*/).find((c) => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
function isAdminReq(req) {
  if (!SINGLE_PORT) return true; // separate admin port is its own boundary
  const tok = cookieOf(req, 'sr_admin') || req.headers['x-admin-token'] || '';
  return !!ADMIN_TOKEN && tok === ADMIN_TOKEN;
}
server.on('upgrade', (request, socket, head) => {
  if (SINGLE_PORT && request.url.startsWith('/_admin-ws')) {
    if (!isAdminReq(request)) return socket.destroy();
    return wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
  }
  if (request.url === '/_security/alerts-ws' || request.url === '/_security/ws') {
    publicWss.handleUpgrade(request, socket, head, (ws) => {
      publicWss.emit('connection', ws, request);
      ws.send(JSON.stringify({ type: 'status_update', ...getSecuritySnapshot() }));
    });
  } else {
    socket.destroy();
  }
});

// CORS: the admin-side Attack Simulator (a different port = a different
// origin) needs to call this server's endpoints from its own page and
// read the X-Score/X-Tier response headers back. Preflight (OPTIONS)
// requests are answered here, before the scoring gate, so they are never
// counted as traffic.
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-Sim-Client');
  res.set('Access-Control-Expose-Headers', 'X-Score, X-Tier, X-ML-Prob, X-Block-Until, X-Verified-Until, Retry-After');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json());

// ---- Public Security Notification & Alert Endpoints (Unscored) ----
// Real-time Server-Sent Events stream for demo website popups
app.get('/_security/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write('retry: 2000\n\n');
  res.write(`data: ${JSON.stringify({ type: 'status_update', ...getSecuritySnapshot() })}\n\n`);

  sseClients.add(res);
  req.on('close', () => {
    sseClients.delete(res);
  });
});

app.get('/_security/status', (req, res) => {
  res.json(getSecuritySnapshot());
});

app.get('/_security/alerts.js', (req, res) => {
  res.sendFile(path.join(DEMO_DIR, 'alerts.js'));
});
app.get('/alerts.js', (req, res) => {
  res.sendFile(path.join(DEMO_DIR, 'alerts.js'));
});

// Only the specific console assets a real visitor's browser needs while
// being challenged — not a blanket static mount of the whole folder.
app.get('/_console/style.css', (req, res) => res.sendFile(path.join(CONSOLE_DIR, 'style.css')));
app.get('/_console/app.js', (req, res) => res.sendFile(path.join(CONSOLE_DIR, 'app.js')));
app.get('/_console/challenge.html', (req, res) => res.sendFile(path.join(CONSOLE_DIR, 'challenge.html')));
// Attack Lab — runs in the CLIENT PC's browser, exempt from scoring so it stays
// usable (and shows the block timer) while the PC is being blocked.
if (ENABLE_LAB) {
  app.get('/_console/lab.html', (req, res) => res.sendFile(path.join(CONSOLE_DIR, 'lab.html')));
  app.get('/_lab', (req, res) => res.redirect('/_console/lab.html'));
}

// ---- Block page: styled page with a REAL countdown to the moment this PC is unblocked ----
const BLOCK_TEMPLATE = fs.readFileSync(path.join(CONSOLE_DIR, 'block.html'), 'utf8');
function esc(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function renderBlockPage(blockedUntil, reasons, ip) {
  const seconds = Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000));
  return {
    seconds,
    html: BLOCK_TEMPLATE
      .replace('__RETRY_SECONDS__', String(seconds))
      .replace('__CLIENT_IP__', esc(ip))
      .replace('__REASONS__', esc(reasons.join(' · ') || 'elevated request score')),
  };
}

// PoW challenge API — called by challenge.html, which a real visitor is
// served mid-request, so this has to stay public. Keyed by client IP.
const pendingPuzzles = new Map(); // ip -> puzzle

app.get('/_console/api/challenge/new', (req, res) => {
  const ip = clientIp(req);
  if (reputation.isBlocked(ip)) return res.status(429).json({ error: 'blocked' });
  const puzzle = pow.newPuzzle(POW_BITS);
  pendingPuzzles.set(ip, puzzle);
  res.json(puzzle);
});

app.post('/_console/api/challenge/verify', (req, res) => {
  const ip = clientIp(req);
  const puzzle = pendingPuzzles.get(ip);
  if (!puzzle) return res.status(400).json({ ok: false, error: 'no active puzzle for this client' });

  const ok = pow.verify(puzzle.nonce, puzzle.difficulty, String(req.body && req.body.solution));
  if (ok) {
    pendingPuzzles.delete(ip);
    if (!reputation.markVerified(ip)) return res.status(429).json({ ok: false, error: 'blocked' });
    const until = Date.now() + reputation.VERIFY_MS;
    broadcast({ type: 'visitor', action: 'verified', ip, until, ts: Date.now() });
    return res.json({ ok: true, verifiedForMs: reputation.VERIFY_MS, until });
  }
  res.json({ ok: false });
});

// ---- Admin console (hosted mode only: same port, token-gated, BEFORE the scoring gate so admin traffic is never scored) ----
const adminRouter = express.Router();
adminRouter.get('/api/snapshot', (req, res) => res.json(reputation.snapshot()));
adminRouter.get('/api/visitors', (req, res) => res.json({
  now: Date.now(), visitors: reputation.snapshot(),
  config: {
    blockMs: reputation.BLOCK_MS, verifyMs: reputation.VERIFY_MS, powBits: POW_BITS,
    tiers: { challenge: 40, block: 70 }, mlMode: mlScorer.modelInfo().mode, tcpMonitor: TCP_MONITOR_ON,
  },
}));
adminRouter.post('/api/unblock', (req, res) => {
  const ip = String((req.body && req.body.ip) || '');
  if (!ip) return res.status(400).json({ ok: false });
  const a = reputation.unblock(ip), b = tcpMonitor.unban(ip);
  broadcast({ type: 'visitor', action: 'unblocked', ip, ts: Date.now() });
  res.json({ ok: a || b });
});
adminRouter.post('/api/unblock-all', (req, res) => {
  let n = 0;
  for (const v of reputation.snapshot()) { if (v.blocked || v.verified || v.score) { reputation.unblock(v.ip); tcpMonitor.unban(v.ip); n++; } }
  broadcast({ type: 'visitor', action: 'unblocked', ip: 'all', ts: Date.now() });
  res.json({ ok: true, cleared: n });
});
adminRouter.get('/api/model', (req, res) => res.json(mlScorer.modelInfo()));
adminRouter.get('/api/tcp-snapshot', (req, res) => res.json({ ...tcpMonitor.snapshot(), tcpMonitorEnabled: TCP_MONITOR_ON }));
adminRouter.get('/api/security-status', (req, res) => res.json(getSecuritySnapshot()));
adminRouter.post('/api/test-alert', (req, res) => {
  const kind = (req.body && req.body.kind) || 'tcp';
  if (kind === 'tcp') {
    broadcast({ type: 'tcp', kind: 'flood', ip: '192.168.1.108', reason: '28 connections in 2000ms (concurrency limit tripped)', banned: true, ts: Date.now() });
  } else {
    broadcast({
      type: 'decision', fp: '203.0.113.' + Math.floor(Math.random() * 200 + 10), path: '/search?q=exploit',
      score: 85, tier: 'block', reasons: ['high request rate', 'hammering same path'], verified: false,
      ml: { prob: 0.94, delta: 30 }, ts: Date.now(),
    });
  }
  res.json({ ok: true, simulated: kind });
});
adminRouter.use(express.static(CONSOLE_DIR));

if (SINGLE_PORT) {
  // Same port as the site, but only reachable with the admin token. Anyone
  // without it gets a plain 404, so the console's existence isn't revealed.
  app.get('/_admin/login', (req, res) => {
    if (!ADMIN_TOKEN || req.query.key !== ADMIN_TOKEN) return res.status(404).send('Not found');
    res.set('Set-Cookie', `sr_admin=${encodeURIComponent(ADMIN_TOKEN)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${req.secure ? '; Secure' : ''}`);
    res.redirect('/_console/dashboard.html');
  });
  app.use('/_console', (req, res, next) => (isAdminReq(req) ? next() : res.status(404).send('Not found')), adminRouter);
}

// ---- Scoring gate in front of the demo app ----
// One decision per request, per client PC (IP):
//   1. rules   (lib/reputation.js)  -> rule score + reasons
//   2. ML      (lib/ml-scorer.js)   -> extra points when the traffic pattern looks like an attack
//   3. tiers   score <40 allow | 40-69 challenge (PoW, then 2 min pass) | 70+ block (5 min)
app.use((req, res, next) => {
  const ip = clientIp(req);

  const ev = mlScorer.begin(ip, req);
  mlScorer.trackResponse(ev, res);

  const rule = reputation.recordRequest(ip, { path: req.path, url: req.originalUrl, headers: req.headers });
  const ml = mlScorer.score(ip, ip, tcpMonitor.recentConnections);
  const mlDelta = !rule.blocked && ml ? ml.delta : 0;
  const d = reputation.decide(ip, rule, mlDelta, ml && ml.delta > 0 ? `ML: attack-like traffic pattern (p=${ml.prob})` : '');
  const { score, tier, reasons, verified } = d;

  res.set('X-Score', String(score));
  res.set('X-Tier', tier);
  if (ml) res.set('X-ML-Prob', String(ml.prob));
  if (tier === 'block') res.set('X-Block-Until', String(d.blockedUntil));
  if (verified) res.set('X-Verified-Until', String(reputation.verifiedUntilOf(ip) || ''));

  broadcast({ type: 'decision', fp: ip, ip, path: req.path, score, tier, reasons, verified, ml, ts: Date.now() });
  if (tier === 'block' && !rule.blocked) {
    broadcast({ type: 'visitor', action: 'blocked', source: 'http', ip, reason: reasons.join(' · '), until: d.blockedUntil, ts: Date.now() });
  }

  // Recording mode (ML_RECORD): let everything through so recorded response
  // sizes/timings come from the real site, not from our own block pages.
  if (process.env.ML_RECORD) return next();

  if (tier === 'block' || tier === 'challenge') mlScorer.markGate(ev);

  if (tier === 'block') {
    const { seconds, html } = renderBlockPage(d.blockedUntil, reasons, ip);
    res.set('Retry-After', String(seconds));
    res.set('Cache-Control', 'no-store');
    return res.status(429).send(html);
  }
  if (tier === 'challenge') {
    res.set('Cache-Control', 'no-store');
    return res.status(403).sendFile(path.join(CONSOLE_DIR, 'challenge.html'));
  }
  next();
});

// Keep-alive to the upstream app. Without an explicit agent, http-proxy forces
// `Connection: close` on every proxied request AND copies it back to the
// client, so every single request opened a brand-new TCP connection. A real
// reverse proxy reuses connections — and the TCP monitor / ML "connections"
// feature only mean something if clients can actually reuse them.
const upstreamAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
app.use('/', createProxyMiddleware({ target: DEMO_APP_TARGET, changeOrigin: true, agent: upstreamAgent }));

// ======================================================================
// ADMIN side (ADMIN_PORT) — dashboard, attack simulator, and the
// read-only "what does the system currently think" APIs they call. This
// is the port you do NOT want open to the public internet later: it
// shows per-visitor scores/fingerprints and lets anyone fire the attack
// simulator at your site. Firewall this to your own IP when you deploy.
// ======================================================================
const adminApp = express();
const adminServer = http.createServer(adminApp);
adminServer.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
});

if (!SINGLE_PORT) {
  adminApp.use(express.json());
  adminApp.use('/_console', adminRouter);
}

// ======================================================================
// Start both
// ======================================================================
server.listen(PROXY_PORT, '0.0.0.0', () => {
  console.log(`PUBLIC reverse proxy listening on http://localhost:${PROXY_PORT}  (mode: ${SINGLE_PORT ? 'HOSTED single-port' : 'LAN/dual-port'}, TCP monitor: ${TCP_MONITOR_ON ? 'ON' : 'OFF'}, trust proxy: ${TRUST_PROXY})`);
  if (SINGLE_PORT) {
    console.log(`  ADMIN login (open once per browser): /_admin/login?key=${ADMIN_TOKEN}`);
    console.log('  -> then dashboard at /_console/dashboard.html and simulator at /_console/simulator.html');
  }
  console.log(`  forwarding verified requests to the protected site at: ${DEMO_APP_TARGET}`);
  if (DEMO_APP_TARGET.includes('localhost') || DEMO_APP_TARGET.includes('127.0.0.1')) {
    console.log('  (this is pointing at THIS machine — set DEMO_TARGET=http://<website-pc-ip>:3000 if the demo website is running on a different PC)');
  }
});

if (!SINGLE_PORT) adminServer.listen(ADMIN_PORT, () => {
  console.log(`ADMIN console listening on http://localhost:${ADMIN_PORT}`);
  console.log(`  dashboard:  http://localhost:${ADMIN_PORT}/_console/dashboard.html`);
  console.log(`  simulator:  http://localhost:${ADMIN_PORT}/_console/simulator.html`);

  const addrs = lanAddresses();
  if (addrs.length) {
    console.log('\nReachable from OTHER PCs on the same network/Wi-Fi at:');
    for (const a of addrs) {
      console.log(`  site/proxy:  http://${a.address}:${PROXY_PORT}/   (interface: ${a.name})`);
      console.log(`  admin:       http://${a.address}:${ADMIN_PORT}/_console/dashboard.html`);
    }
    console.log('If other PCs cannot connect, allow inbound TCP on both ports in your firewall for now (the admin port can be locked down later, on a real deployment).\n');
  } else {
    console.log('\nNo LAN-facing network interface detected — other PCs will not be able to reach this.\n');
  }
});
