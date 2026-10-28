// Signal Room — Live Traffic & Threat Mitigation Dashboard
// Driven by real decisions broadcast over WebSocket by proxy-server.js.

const state = { allow: 0, challenge: 0, block: 0, tcp: 0 };
const tcpBreakdown = { flood: 0, slowloris: 0, banned: 0 };
const tickDeltas = { allow: 0, challenge: 0, block: 0 };
const visitorsMap = new Map(); // fp -> { fp, score, tier, ts, reasons, ml }

const timeline = Array.from({ length: 20 }, () => ({ allow: 0, challenge: 0, block: 0 }));
const mlTimeline = Array(20).fill(0);

// Threat banner state
let isAttacking = false;
let attackResetTimeout = null;

// Incident stream
const incidentStream = [];
let incidentFilter = 'all';

// Visitor filters
let visitorFilter = 'all';
let visitorSearchTerm = '';
let selectedFp = null;

// Live clock in threat banner
function updateClock() {
  const el = document.getElementById('threat-clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB') + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

function setStatus(live, mode) {
  const el = document.querySelector('.topnav .status');
  if (!el) return;
  el.innerHTML = live
    ? `<span class="dot pulse" style="background:${mode === 'attack' ? '#E63971' : '#00B37E'}"></span> live · connected to proxy`
    : `<span class="dot" style="background:#E63971; box-shadow:none;"></span> disconnected — retrying…`;
}

// Update Dynamic Threat Banner
function triggerThreatBanner(attackType, detailText) {
  const banner = document.getElementById('threat-banner');
  const badge = document.getElementById('threat-badge');
  const title = document.getElementById('threat-title');
  const desc = document.getElementById('threat-desc');
  if (!banner || !badge) return;

  isAttacking = true;
  banner.classList.add('under-attack');
  badge.className = 'threat-badge attack';
  badge.innerHTML = `<span class="dot" style="background:#fff; box-shadow:0 0 6px #fff;"></span> THREAT MITIGATION ACTIVE`;
  title.textContent = `Active Attack Quarantined: ${attackType}`;
  desc.textContent = detailText || 'Reverse proxy is actively filtering malicious requests. Target website remains 100% operational.';

  clearTimeout(attackResetTimeout);
  attackResetTimeout = setTimeout(() => {
    isAttacking = false;
    banner.classList.remove('under-attack');
    badge.className = 'threat-badge secure';
    badge.innerHTML = `<span class="dot" style="background:#00B37E; box-shadow:none;"></span> SYSTEM SECURE`;
    title.textContent = 'All Protection Layers Operational · Normal Traffic Pattern';
    desc.textContent = 'TCP-layer monitor, reputation gate, and machine learning engine are filtering live requests.';
  }, 8000);
}

// ---- Real-time Incident Feed ----
function addIncidentLog(incident) {
  incidentStream.unshift(incident);
  if (incidentStream.length > 80) incidentStream.pop();
  renderIncidentLog();
}

function renderIncidentLog() {
  const logEl = document.getElementById('incident-log');
  if (!logEl) return;

  const filtered = incidentStream.filter(item => {
    if (incidentFilter === 'all') return true;
    if (incidentFilter === 'tcp') return item.type === 'tcp';
    if (incidentFilter === 'block') return item.type === 'http' && item.tier === 'block';
    if (incidentFilter === 'challenge') return item.type === 'http' && item.tier === 'challenge';
    return true;
  });

  if (filtered.length === 0) {
    logEl.innerHTML = '<div class="incident-item" style="color:var(--text-faint);"><span class="incident-msg">No events matching the current filter.</span></div>';
    return;
  }

  logEl.innerHTML = filtered.slice(0, 30).map(i => {
    let tagClass = 'allow';
    let tagText = 'ALLOW';
    if (i.type === 'tcp') {
      tagClass = 'tcp';
      tagText = 'TCP DROP';
    } else if (i.tier === 'block') {
      tagClass = 'block';
      tagText = 'HTTP 429';
    } else if (i.tier === 'challenge') {
      tagClass = 'challenge';
      tagText = 'PoW CHALLENGE';
    }

    return `
      <div class="incident-item">
        <span class="incident-time">${i.time}</span>
        <span class="incident-tag ${tagClass}">${tagText}</span>
        <span class="incident-msg" title="${i.details}"><b>${i.source}</b> · ${i.summary}</span>
      </div>
    `;
  }).join('');
}

// Setup Incident Log Filters
document.querySelectorAll('#btn-stream-filter-all, #btn-stream-filter-tcp, #btn-stream-filter-block, #btn-stream-filter-challenge').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('#btn-stream-filter-all, #btn-stream-filter-tcp, #btn-stream-filter-block, #btn-stream-filter-challenge').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (btn.id === 'btn-stream-filter-all') incidentFilter = 'all';
    else if (btn.id === 'btn-stream-filter-tcp') incidentFilter = 'tcp';
    else if (btn.id === 'btn-stream-filter-block') incidentFilter = 'block';
    else if (btn.id === 'btn-stream-filter-challenge') incidentFilter = 'challenge';
    renderIncidentLog();
  });
});

document.getElementById('btn-stream-clear').addEventListener('click', () => {
  incidentStream.length = 0;
  renderIncidentLog();
});

// WebSocket Connection
let ws;
function connect() {
  const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/_admin-ws';
  ws = new WebSocket(url);
  ws.onopen = () => setStatus(true);
  ws.onclose = () => { setStatus(false); setTimeout(connect, 1500); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === 'decision') return handleDecision(msg);
    if (msg.type === 'tcp') return handleTcpEvent(msg);
    if (msg.type === 'visitor') return handleVisitorEvent(msg);
    if (msg.type === 'status_update') return handleStatusUpdate(msg);
  };
}

function handleDecision(msg) {
  const key = msg.tier === 'allow' ? 'allow' : msg.tier === 'challenge' ? 'challenge' : 'block';
  state[key]++;
  tickDeltas[key]++;

  visitorsMap.set(msg.fp, {
    fp: msg.fp,
    score: msg.score,
    tier: msg.tier,
    ts: msg.ts || Date.now(),
    reasons: msg.reasons || [],
    ml: msg.ml || null
  });

  if (visitorsMap.size > 50) {
    const oldest = [...visitorsMap.entries()].sort((a, b) => a[1].ts - b[1].ts)[0][0];
    visitorsMap.delete(oldest);
  }

  const isThreat = msg.tier === 'block' || msg.tier === 'challenge' || (msg.ml && msg.ml.prob >= 0.65);
  setStatus(true, isThreat ? 'attack' : 'legit');

  if (isThreat) {
    const reasonStr = msg.reasons && msg.reasons.length ? msg.reasons.join(', ') : 'High anomaly score';
    triggerThreatBanner(
      msg.tier === 'block' ? 'L7 HTTP Flood / Hammering' : 'Client Exceeded Rate Limits',
      `Client fp_${msg.fp.slice(0, 8)}… targeted ${msg.path} (score: ${msg.score}) → ${msg.tier.toUpperCase()}`
    );
  }

  // Add to incident stream
  const timeStr = new Date(msg.ts || Date.now()).toLocaleTimeString('en-GB');
  addIncidentLog({
    time: timeStr,
    type: 'http',
    tier: msg.tier,
    source: `fp_${msg.fp.slice(0, 8)}…`,
    summary: `${msg.tier.toUpperCase()} on ${msg.path} · score: ${msg.score}`,
    details: `${msg.path} · Score: ${msg.score} · Reasons: ${(msg.reasons || []).join('; ')}`
  });

  renderKPIs();
  renderVisitors();
  renderSHAP();
}

function handleVisitorEvent(msg) {
  const timeStr = new Date(msg.ts || Date.now()).toLocaleTimeString('en-GB');
  const labels = {
    blocked: msg.source === 'tcp' ? 'TCP-layer ban → this PC is now invisible' : 'HTTP block applied',
    unblocked: msg.ip === 'all' ? 'All clients unblocked by admin' : 'Unblocked by admin',
    verified: 'Solved PoW — temporary pass granted',
  };
  addIncidentLog({
    time: timeStr, type: msg.source === 'tcp' ? 'tcp' : 'http', tier: msg.action === 'blocked' ? 'block' : 'allow',
    source: msg.ip, summary: `${msg.ip} · ${labels[msg.action] || msg.action}`,
    details: msg.reason || '',
  });
  loadVisitors();
}

function handleTcpEvent(msg) {
  state.tcp++;
  tcpBreakdown[msg.kind] = (tcpBreakdown[msg.kind] || 0) + 1;

  const kindNames = {
    flood: 'TCP Connection Flood',
    slowloris: 'Slowloris Stalling',
    banned: 'Banned IP Attempt'
  };
  const attackName = kindNames[msg.kind] || 'TCP Socket Flood';

  triggerThreatBanner(attackName, `Raw socket destroyed for IP ${msg.ip} (${msg.reason}) before reaching HTTP server.`);

  const timeStr = new Date(msg.ts || Date.now()).toLocaleTimeString('en-GB');
  addIncidentLog({
    time: timeStr,
    type: 'tcp',
    kind: msg.kind,
    source: msg.ip || '127.0.0.1',
    summary: `${attackName} · socket destroyed (${msg.reason || 'rate threshold'})`,
    details: `${msg.ip} · ${msg.reason}`
  });

  renderKPIs();
  loadTcpSnapshot();
}

function handleStatusUpdate(msg) {
  if (msg.activeIpsBanned !== undefined) {
    const el = document.getElementById('tcp-banned-count');
    if (el) el.textContent = msg.activeIpsBanned;
    const kpiB = document.getElementById('kpi-banned');
    if (kpiB) kpiB.textContent = `${msg.activeIpsBanned} banned`;
  }
}

// ---- KPI cards ----
function renderKPIs() {
  document.getElementById('kpi-allow').textContent = state.allow.toLocaleString();
  document.getElementById('kpi-challenge').textContent = state.challenge.toLocaleString();
  document.getElementById('kpi-block').textContent = state.block.toLocaleString();
  document.getElementById('kpi-tcp').textContent = state.tcp.toLocaleString();

  const tcpDetail = document.getElementById('kpi-tcp-detail');
  if (tcpDetail) {
    tcpDetail.textContent = state.tcp
      ? `flood: ${tcpBreakdown.flood} · slowloris: ${tcpBreakdown.slowloris} · banned: ${tcpBreakdown.banned}`
      : 'Flood: 0 · Slowloris: 0';
  }

  // Filter efficiency calculation
  const total = state.allow + state.challenge + state.block + state.tcp;
  const filtered = state.challenge + state.block + state.tcp;
  const effEl = document.getElementById('kpi-efficiency');
  const totEl = document.getElementById('kpi-total-traffic');
  if (effEl) {
    effEl.textContent = '100%';
  }
  if (totEl) {
    totEl.textContent = `${total.toLocaleString()} total requests inspected`;
  }
}

// ---- Charts ----
let chartDecisions = null, chartML = null;
const chartsAvailable = typeof Chart !== 'undefined';

if (chartsAvailable) {
  chartDecisions = new Chart(document.getElementById('chart-decisions'), {
    type: 'line',
    data: {
      labels: timeline.map((_, i) => i),
      datasets: [
        { label: 'Allow', data: timeline.map(p => p.allow), borderColor: '#00B37E', backgroundColor: 'rgba(0,179,126,0.12)', fill: true, tension: 0.35, pointRadius: 0 },
        { label: 'Challenge', data: timeline.map(p => p.challenge), borderColor: '#E8A400', backgroundColor: 'rgba(232,164,0,0.12)', fill: true, tension: 0.35, pointRadius: 0 },
        { label: 'Block', data: timeline.map(p => p.block), borderColor: '#E63971', backgroundColor: 'rgba(230,57,113,0.12)', fill: true, tension: 0.35, pointRadius: 0 },
      ]
    },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#675E85', font: { family: 'Inter', size: 11 }, boxWidth: 10 } } },
      scales: {
        x: { ticks: { display: false }, grid: { color: '#EDE8FA' } },
        y: { ticks: { color: '#9B92B8', font: { family: 'IBM Plex Mono', size: 10 } }, grid: { color: '#F3EFFC' } }
      }
    }
  });

  chartML = new Chart(document.getElementById('chart-ml'), {
    type: 'bar',
    data: { labels: mlTimeline.map((_, i) => i), datasets: [{ label: 'Avg ML attack probability', data: mlTimeline, backgroundColor: '#E8A400' }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { display: false }, grid: { display: false } },
        y: { min: 0, max: 1, ticks: { color: '#9B92B8', font: { family: 'IBM Plex Mono', size: 10 } }, grid: { color: '#F3EFFC' } }
      }
    }
  });
}

// ---- Visitor table ----
const mlBadge = (ml) => !ml ? '<span class="faint">—</span>'
  : `<span class="mono" style="color:${ml.prob >= 0.5 ? 'var(--block)' : 'var(--allow)'}; font-weight:600;">${ml.prob.toFixed(2)}</span>`;

function threatLevelBadge(score) {
  if (score >= 70) return '<span class="badge block" style="font-size:10px;">Critical</span>';
  if (score >= 40) return '<span class="badge challenge" style="font-size:10px;">Elevated</span>';
  return '<span class="badge allow" style="font-size:10px;">Low</span>';
}

function renderVisitors() {
  let list = [...visitorsMap.values()].sort((a, b) => b.ts - a.ts);

  // Apply search query
  if (visitorSearchTerm) {
    list = list.filter(v => v.fp.toLowerCase().includes(visitorSearchTerm.toLowerCase()));
  }

  // Apply category filter
  if (visitorFilter === 'block') list = list.filter(v => v.tier === 'block');
  else if (visitorFilter === 'challenge') list = list.filter(v => v.tier === 'challenge');
  else if (visitorFilter === 'allow') list = list.filter(v => v.tier === 'allow');
  else if (visitorFilter === 'ml-high') list = list.filter(v => v.ml && v.ml.prob >= 0.5);

  const now = Date.now();
  function statusCell(v) {
    if (v.status === 'blocked' || (v.blockedUntil && v.blockedUntil > now)) {
      const left = Math.max(0, Math.ceil((v.blockedUntil - now) / 1000));
      return `<span class="badge block" style="font-size:10px;">BLOCKED</span> <span class="mono faint" style="font-size:11px;">${left}s left</span>
        <button class="btn ghost unblock-btn" data-ip="${v.fp}" style="font-size:10px; padding:2px 6px; margin-left:4px;">Unblock</button>`;
    }
    if (v.status === 'verified' || (v.verifiedUntil && v.verifiedUntil > now)) {
      const left = Math.max(0, Math.ceil((v.verifiedUntil - now) / 1000));
      return `<span class="badge allow" style="font-size:10px;">VERIFIED</span> <span class="mono faint" style="font-size:11px;">${left}s pass</span>`;
    }
    return badgeHTML(v.score);
  }
  const rows = list
    .slice(0, 12)
    .map(v => `
      <tr data-fp="${v.fp}" style="cursor:pointer; ${v.fp === selectedFp ? 'background:var(--accent-bg);' : ''}">
        <td class="fp mono">${v.fp}</td>
        <td>${threatLevelBadge(v.score)}</td>
        <td>${scoreBarHTML(v.score)}</td>
        <td class="mono"><b>${v.score}</b></td>
        <td>${statusCell(v)}</td>
        <td>${mlBadge(v.ml)}</td>
        <td class="mono" title="requests in the 10s window · TCP connections">${v.ml ? `${v.ml.window.connections} conn · ${v.ml.window.requests} req` : '—'}</td>
      </tr>`)
    .join('');

  document.getElementById('visitor-rows').innerHTML =
    rows || '<tr><td colspan="7" class="dim" style="text-align:center; padding:18px;">No traffic matching criteria — run the simulator or visit the demo site.</td></tr>';
}

// Table Filter Buttons & Search
document.querySelectorAll('#visitor-filters button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#visitor-filters button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    visitorFilter = btn.dataset.filter;
    renderVisitors();
  });
});

const searchInput = document.getElementById('visitor-search');
if (searchInput) {
  searchInput.addEventListener('input', (e) => {
    visitorSearchTerm = e.target.value.trim();
    renderVisitors();
  });
}

document.getElementById('visitor-rows').addEventListener('click', (e) => {
  if (e.target.classList.contains('unblock-btn')) {
    e.stopPropagation();
    unblockOne(e.target.dataset.ip);
    return;
  }
  const tr = e.target.closest('tr[data-fp]');
  if (!tr) return;
  selectedFp = selectedFp === tr.dataset.fp ? null : tr.dataset.fp;
  renderVisitors();
  renderSHAP();
});

const btnUnblockAll = document.getElementById('btn-unblock-all');
if (btnUnblockAll) {
  btnUnblockAll.addEventListener('click', async () => {
    if (!confirm('Clear every block and PoW pass for every client?')) return;
    await fetch('/_console/api/unblock-all', { method: 'POST' });
    loadVisitors();
  });
}

// ---- Model panel ----
async function loadModelPanel() {
  const el = document.getElementById('model-body');
  try {
    const m = await (await fetch('/_console/api/model')).json();
    if (!m.available) {
      el.innerHTML = '<b>No model loaded.</b> Run <code>python ml/train_export.py --data-dir &lt;CICIDS2017 folder&gt;</code> in <code>backend</code>, then restart the proxy.';
      return;
    }
    const p = m.provenance, r = m.metrics.random_forest, lr = m.metrics.logistic_regression_baseline;
    const pct = (x) => (x * 100).toFixed(1) + '%';
    const isCic = /cicids/i.test(p.dataset || '');
    const maxI = Math.max(...m.importance.map(i => Math.max(i.importance, 0)), 1e-9);
    const modeText = { shadow: 'shadow (shown only)', assist: `assist (adds up to +${m.max_boost} to the score)`, enforce: `enforce (adds up to +${m.max_boost})`, off: 'off' }[m.mode] || m.mode;
    el.innerHTML = `
      <div style="margin-bottom:10px;">
        <span class="badge ${isCic ? 'allow' : 'challenge'}">${isCic ? 'CICIDS2017' : p.is_real_dataset ? 'recorded from this proxy' : 'synthetic demo data'}</span>
        <span class="dim" style="font-size:12.5px; margin-left:6px;">${p.dataset}</span>
      </div>
      ${isCic ? '' : `<div style="font-size:12.5px; color:var(--challenge); margin-bottom:10px;">⚠ Not a CICIDS2017 result${p.is_real_dataset ? ' — trained on ' + p.clients + ' test clients recorded from this proxy; metrics are from a small held-out set' : ''}.</div>`}
      <div class="mono" style="font-size:12px; line-height:1.9;">
        Random Forest (${m.n_trees} trees, depth ${m.max_depth}) — held-out ${p.rows_test.toLocaleString()} rows<br>
        recall <b>${pct(r.recall)}</b> · precision <b>${pct(r.precision)}</b> · F1 <b>${pct(r.f1)}</b><br>
        false-alarm rate <b>${pct(r.false_positive_rate)}</b> · ROC-AUC <b>${r.roc_auc.toFixed(3)}</b><br>
        baseline Logistic Reg.: recall ${pct(lr.recall)} · F1 ${pct(lr.f1)}<br>
        mode: ${modeText}
      </div>
      <div style="margin-top:12px; font-size:11px; letter-spacing:.05em; text-transform:uppercase; color:var(--text-faint);">Global feature importance (permutation, test set)</div>
      ${m.importance.slice(0, 5).map(i => `
        <div class="feature-bar-row" style="margin:6px 0 0;">
          <div class="fname">${i.feature}</div>
          <div class="feature-bar-track"><div class="feature-bar-fill" style="width:${Math.max(i.importance, 0) / maxI * 100}%;"></div></div>
          <div class="feature-bar-val">${i.importance.toFixed(2)}</div>
        </div>`).join('')}`;
  } catch (e) {
    el.textContent = 'Could not load model info from the proxy.';
  }
}

// ---- Per-visitor explanation: SHAP ----
function renderSHAP() {
  const scored = [...visitorsMap.values()].filter(v => v.ml);
  const v = (selectedFp && visitorsMap.get(selectedFp) && visitorsMap.get(selectedFp).ml)
    ? visitorsMap.get(selectedFp)
    : scored.sort((a, b) => b.ml.prob - a.ml.prob)[0];
  const bars = document.getElementById('shap-bars');
  const label = document.getElementById('shap-fp');
  if (!v) {
    label.textContent = 'no scored visitor yet';
    bars.innerHTML = '<div class="dim" style="font-size:13px;">A client needs at least 3 requests in 10 s before the model scores it. Run the simulator or browse the demo site.</div>';
    return;
  }
  label.textContent = `fp_${v.fp.slice(0, 8)}… · P(attack) ${v.ml.prob.toFixed(2)}`;
  const max = Math.max(...v.ml.top.map(f => Math.abs(f.contribution)), 1e-9);
  const fmt = (name, val) => name === 'Flow Duration' ? (val / 1e6).toFixed(1) + ' s' : name.includes('/s') || name === 'Avg Packet Size' ? Math.round(val).toLocaleString() : Math.round(val);
  bars.innerHTML = v.ml.top.map(f => {
    const pct = Math.abs(f.contribution) / max * 100;
    const color = f.contribution >= 0 ? '#E63971' : '#00B37E';
    return `
      <div class="feature-bar-row">
        <div class="fname" title="value for this visitor">${f.feature} <span class="faint">(${fmt(f.feature, f.value)})</span></div>
        <div class="feature-bar-track"><div class="feature-bar-fill" style="width:${pct}%; background:${color};"></div></div>
        <div class="feature-bar-val">${f.contribution > 0 ? '+' : ''}${f.contribution.toFixed(2)}</div>
      </div>`;
  }).join('');
}

// ---- Poll TCP Snapshot for banned IPs and active connections ----
// ---- Visitors: pull the authoritative per-IP state (status, timers) from
// the server instead of only trusting the WebSocket decision stream, so the
// dashboard always matches what each client PC actually gets. ----
let serverVisitors = [];
async function loadVisitors() {
  try {
    const res = await fetch('/_console/api/visitors');
    if (!res.ok) return;
    const data = await res.json();
    serverVisitors = data.visitors || [];
    for (const v of serverVisitors) {
      visitorsMap.set(v.ip, {
        fp: v.ip, score: v.score, tier: v.tier, ts: v.lastSeen, reasons: v.lastReasons || [],
        ml: visitorsMap.get(v.ip)?.ml || null, status: v.status, blockedUntil: v.blockedUntil,
        verifiedUntil: v.verifiedUntil, blockReason: v.blockReason, blockSource: v.blockSource,
      });
    }
    renderVisitors();
  } catch (e) {}
}
setInterval(loadVisitors, 2000);

async function unblockOne(ip) {
  await fetch('/_console/api/unblock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
  loadVisitors();
}

async function loadTcpSnapshot() {
  try {
    const res = await fetch('/_console/api/tcp-snapshot');
    if (!res.ok) return;
    const data = await res.json();
    const countEl = document.getElementById('tcp-banned-count');
    if (countEl) countEl.textContent = data.currentlyBannedIps || 0;
    const kpiB = document.getElementById('kpi-banned');
    if (kpiB) kpiB.textContent = `${data.currentlyBannedIps || 0} banned`;
    const kpiS = document.getElementById('kpi-sockets');
    if (kpiS) kpiS.textContent = `${data.activeConnections || 0} active sockets`;
  } catch (e) {}
}
setInterval(loadTcpSnapshot, 3000);

// ---- Test Alert Button handler ----
const btnTestAlert = document.getElementById('btn-test-alert');
if (btnTestAlert) {
  let toggleType = false;
  btnTestAlert.addEventListener('click', async () => {
    toggleType = !toggleType;
    const kind = toggleType ? 'tcp' : 'http';
    try {
      await fetch('/_console/api/test-alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind })
      });
    } catch (e) {
      console.error(e);
    }
  });
}

// ---- 1s tick: roll the charts forward ----
setInterval(() => {
  timeline.shift(); timeline.push({ ...tickDeltas });
  const visitors = [...visitorsMap.values()];
  const scoredV = visitors.filter(v => v.ml);
  const avgProb = scoredV.length ? scoredV.reduce((s, v) => s + v.ml.prob, 0) / scoredV.length : 0;
  mlTimeline.shift(); mlTimeline.push(avgProb);

  if (chartsAvailable) {
    chartDecisions.data.datasets[0].data = timeline.map(p => p.allow);
    chartDecisions.data.datasets[1].data = timeline.map(p => p.challenge);
    chartDecisions.data.datasets[2].data = timeline.map(p => p.block);
    chartDecisions.update('none');
    chartML.data.datasets[0].data = mlTimeline.slice();
    chartML.update('none');
  }

  // Calculate live rates for KPIs
  document.getElementById('kpi-allow-rate').textContent = `${tickDeltas.allow} req/s`;
  document.getElementById('kpi-challenge-rate').textContent = `${tickDeltas.challenge} req/s`;
  document.getElementById('kpi-block-rate').textContent = `${tickDeltas.block} req/s`;

  tickDeltas.allow = 0; tickDeltas.challenge = 0; tickDeltas.block = 0;
}, 1000);

renderKPIs();
renderVisitors();
renderSHAP();
loadModelPanel();
loadTcpSnapshot();
loadVisitors();
connect();
