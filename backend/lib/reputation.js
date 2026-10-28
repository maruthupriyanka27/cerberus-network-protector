/**
 * Application-layer (HTTP) reputation engine — one record per client IP.
 *
 *  score 0-100, halves every 30 s of good behaviour.
 *    0-39  allow       the real site
 *    40-69 challenge   proof-of-work page; solving it = VERIFY_MS (2 min) without
 *                      being challenged again
 *    70+   block       blocked for BLOCK_MS (5 min, fixed — more requests do
 *                      NOT extend it); afterwards the record is wiped clean
 *
 * Rules add points per request (see recordRequest). The ML model adds a
 * boost on top of this (proxy-server.js). Everything the dashboard shows
 * (timers, reasons, counters) is exposed through snapshot().
 */
const BLOCK_MS = Number(process.env.BLOCK_MS || 5 * 60_000);
const VERIFY_MS = Number(process.env.VERIFY_MS || 2 * 60_000);

const DECAY_HALF_LIFE_MS = 30_000;
const RATE_WINDOW_MS = 2_000;
const RATE_THRESHOLD = 8;          // page/API requests within 2 s  (> 4 pages/s)
const SUSTAINED_WINDOW_MS = 10_000;
const SUSTAINED_THRESHOLD = 30;    // page/API requests within 10 s (> 3 pages/s for 10 s)
const ASSET_RATE_THRESHOLD = 40;   // static files within 2 s
const SAME_URL_COUNT = 6;          // identical URLs in a row ...
const SAME_URL_SPAN_MS = 4_000;    // ... within this span (a refresh-spammer / hammer)
const ASSET_GRACE_REQUESTS = 8;    // don't penalise "no assets" until this many requests
const TOOL_UA_RE = /\b(curl|wget|python-requests|python-urllib|aiohttp|go-http-client|okhttp|libwww-perl|java\/|httpclient|scrapy|nikto|sqlmap|slowhttptest|siege|apachebench|ab\/|wrk|hey\/|vegeta|locust)\b/i;
const ASSET_RE = /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|map)$/i;

const store = new Map(); // ip -> record

function fresh() {
  return {
    score: 0, lastUpdated: Date.now(),
    hits: [], assetHits: [], recent: [], // recent = [{t,url}]
    sawAsset: false, totalRequests: 0,
    verifiedUntil: 0, blockedUntil: 0, blockReason: '', blockSource: '',
    firstSeen: Date.now(), lastSeen: Date.now(), lastPath: '', lastReasons: [],
    counts: { allow: 0, challenge: 0, block: 0 }, blocks: 0, verifications: 0,
  };
}
function getRecord(ip) {
  let r = store.get(ip);
  if (!r) { r = fresh(); store.set(ip, r); }
  return r;
}
function decay(r, now) {
  r.score *= Math.pow(0.5, (now - r.lastUpdated) / DECAY_HALF_LIFE_MS);
  r.lastUpdated = now;
}
function tierFor(score) {
  if (score >= 70) return 'block';
  if (score >= 40) return 'challenge';
  return 'allow';
}
function clearBlock(r, now) {
  r.blockedUntil = 0; r.blockReason = ''; r.blockSource = '';
  r.score = 0; r.lastUpdated = now;
  r.hits = []; r.assetHits = []; r.recent = []; r.sawAsset = false; r.totalRequests = 0;
  r.verifiedUntil = 0;
}

/**
 * Step 1 (rules). Returns { blocked:true } for a visitor serving a block
 * sentence, otherwise { ruleScore, reasons }. Tier is NOT decided here —
 * the gate adds the ML boost first and then calls decide().
 */
function recordRequest(ip, { path, url, headers }) {
  const now = Date.now();
  const r = getRecord(ip);
  r.lastSeen = now; r.lastPath = path;

  // Serving a block sentence: fixed length, nothing counted, nothing extended.
  if (r.blockedUntil && now < r.blockedUntil) {
    return { blocked: true, blockedUntil: r.blockedUntil, reasons: [r.blockReason || 'blocked'] };
  }
  if (r.blockedUntil && now >= r.blockedUntil) clearBlock(r, now); // sentence served -> clean slate

  decay(r, now);
  const isAsset = ASSET_RE.test(path);
  const bucket = isAsset ? 'assetHits' : 'hits';
  r[bucket].push(now);
  r[bucket] = r[bucket].filter((t) => now - t <= (isAsset ? RATE_WINDOW_MS : SUSTAINED_WINDOW_MS));
  if (isAsset) r.sawAsset = true;
  else { r.recent.push({ t: now, url: url || path }); if (r.recent.length > SAME_URL_COUNT) r.recent.shift(); }
  r.totalRequests++;

  let delta = 0;
  const reasons = [];
  const pageIn2s = r.hits.filter((t) => now - t <= RATE_WINDOW_MS).length;

  if (pageIn2s > RATE_THRESHOLD || r.assetHits.length > ASSET_RATE_THRESHOLD) {
    delta += 20; reasons.push('high request rate');
  } else if (r.hits.length > SUSTAINED_THRESHOLD) {
    delta += 15; reasons.push('sustained high rate');
  }
  if (!headers['user-agent'] || !headers['accept']) {
    delta += 15; reasons.push('missing browser headers');
  } else if (TOOL_UA_RE.test(headers['user-agent'])) {
    delta += 10; reasons.push('automation tool user-agent');
  }
  if (!isAsset && r.recent.length === SAME_URL_COUNT
      && r.recent.every((x) => x.url === r.recent[0].url)
      && now - r.recent[0].t <= SAME_URL_SPAN_MS) {
    delta += 20; reasons.push('hammering same URL');
  }
  if (r.totalRequests > ASSET_GRACE_REQUESTS && !r.sawAsset && !isAsset) {
    delta += 15; reasons.push('never loads static assets');
  }

  r.score = Math.max(0, Math.min(100, r.score + delta));
  if (reasons.length) r.lastReasons = reasons;
  return { blocked: false, ruleScore: r.score, reasons };
}

/**
 * Step 2 (decision). rule = result of recordRequest, mlDelta = boost from
 * the ML model (0 if none). Applies the tier table and the block / verified
 * timers, and returns what the gate must do.
 */
function decide(ip, rule, mlDelta = 0, mlReason = '') {
  const now = Date.now();
  const r = getRecord(ip);
  if (rule.blocked) {
    r.counts.block++;
    return { score: 100, tier: 'block', reasons: rule.reasons, verified: false, blockedUntil: rule.blockedUntil, rawScore: 100, ruleScore: 100 };
  }
  const score = Math.min(100, rule.ruleScore + mlDelta);
  const reasons = [...rule.reasons];
  if (mlDelta > 0 && mlReason) reasons.push(mlReason);
  const verified = r.verifiedUntil > now;
  let tier = tierFor(score);
  if (tier === 'block') {
    r.blockedUntil = now + BLOCK_MS;
    r.blockReason = reasons.join(' · ') || 'elevated score';
    r.blockSource = 'http';
    r.blocks++; r.verifiedUntil = 0; // a block voids any earlier PoW pass
  } else if (tier === 'challenge' && verified) {
    tier = 'allow'; // solved the PoW within the last VERIFY_MS
  }
  r.counts[tier]++;
  return { score: Math.round(score), tier, reasons, verified: verified && tier !== 'block', blockedUntil: tier === 'block' ? r.blockedUntil : 0, rawScore: Math.round(score), ruleScore: Math.round(rule.ruleScore) };
}

function markVerified(ip, ms = VERIFY_MS) {
  const r = getRecord(ip), now = Date.now();
  if (r.blockedUntil > now) return false;
  r.verifiedUntil = now + ms; r.verifications++;
  // A genuinely fresh start: solving the puzzle clears the rule-side history
  // too, not just the score — otherwise the very next request re-triggers
  // the same "high rate" / "same URL" reasons that earned the challenge a
  // moment ago, and a legit visitor who just verified gets blocked anyway.
  r.score = 0; r.hits = []; r.assetHits = []; r.recent = [];
  r.lastUpdated = now;
  return true;
}

/** TCP layer (or admin) says: this IP is blocked until `until`. */
function forceBlock(ip, reason, source = 'tcp', until = Date.now() + BLOCK_MS) {
  const r = getRecord(ip);
  r.blockedUntil = until; r.blockReason = reason; r.blockSource = source; r.score = 100; r.blocks++; r.verifiedUntil = 0;
  r.lastSeen = Date.now();
}
function unblock(ip) {
  const r = store.get(ip);
  if (!r) return false;
  clearBlock(r, Date.now());
  return true;
}
function verifiedUntilOf(ip) { const r = store.get(ip); return r && r.verifiedUntil > Date.now() ? r.verifiedUntil : 0; }
function isBlocked(ip) { const r = store.get(ip); return !!(r && r.blockedUntil > Date.now()); }

function snapshot() {
  const now = Date.now();
  return [...store.entries()].map(([ip, r]) => {
    const blocked = r.blockedUntil > now;
    const verified = r.verifiedUntil > now;
    const live = blocked ? 100 : r.score * Math.pow(0.5, (now - r.lastUpdated) / DECAY_HALF_LIFE_MS);
    const status = blocked ? 'blocked' : verified ? 'verified' : tierFor(live) === 'challenge' ? 'challenged' : 'allowed';
    return {
      ip, status, score: Math.round(live), tier: blocked ? 'block' : tierFor(live), verified, blocked,
      blockedUntil: blocked ? r.blockedUntil : 0, verifiedUntil: verified ? r.verifiedUntil : 0,
      blockReason: blocked ? r.blockReason : '', blockSource: blocked ? r.blockSource : '',
      lastReasons: r.lastReasons, lastPath: r.lastPath, firstSeen: r.firstSeen, lastSeen: r.lastSeen,
      totalRequests: r.totalRequests, counts: r.counts, blocks: r.blocks, verifications: r.verifications,
    };
  }).sort((a, b) => b.lastSeen - a.lastSeen);
}

// drop idle, unblocked records after 30 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of store) if (now - r.lastSeen > 30 * 60_000 && r.blockedUntil < now) store.delete(ip);
}, 60_000).unref();

module.exports = { verifiedUntilOf, recordRequest, decide, markVerified, forceBlock, unblock, isBlocked, snapshot, tierFor, BLOCK_MS, VERIFY_MS };
