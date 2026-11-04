/**
 * TCP-layer connection monitor — runs AHEAD of the HTTP proxy.
 *
 * Node's http.Server is built directly on top of the `net` module: before
 * any HTTP request is parsed, Node already has a raw net.Socket for the
 * TCP connection. This module hooks `server.on('connection', ...)`, which
 * fires at that raw-socket moment — before Express, before
 * http-proxy-middleware, before a single byte of the HTTP request has been
 * read. That is "the TCP layer" in the sense this project scopes it to:
 * connection-level behaviour, inspected and acted on before the
 * application layer ever sees the request.
 *
 * Three things happen here, in order, for every new connection:
 *
 *   0. Ban check — if this IP is currently banned (see below), the socket
 *      is destroyed immediately, with no further work. This is what makes
 *      the protection "proper" rather than just reactive: a repeat
 *      offender stops being let back in to be re-evaluated every time.
 *   1. Connection-rate / concurrency flood check — one IP opening far
 *      more connections than any real browser would in the window, or
 *      holding too many open at once.
 *   2. Slow-connection / Slowloris-style check — a connection that opens
 *      and then sends little or no data for an extended period, tying up
 *      a server slot without ever completing a request.
 *
 * An IP that trips (1) or (2) repeatedly within a short window is placed
 * on a temporary ban list — every future connection from it is dropped
 * immediately (step 0) until the ban expires, instead of re-running the
 * full check on every single reconnect attempt a flooder fires.
 *
 * ---- Honest scope note ----
 * This does NOT inspect individual TCP packets (SYN flags, sequence
 * numbers, handshake retransmits). That requires raw sockets / packet
 * capture (e.g. libpcap) with OS-level privileges, which Node's event
 * loop does not expose and which a self-hosted Node application would not
 * normally be granted. This module works at the connection level — which
 * is the layer Node CAN see, and the layer Slowloris-style and basic
 * connection-flood attacks actually operate at. True SYN-flood defence
 * (spoofed-source packet floods) is normally handled by the OS/network
 * layer (SYN cookies, firewalls) or infrastructure in front of the app —
 * that remains out of scope here, same as it is for any single self-hosted
 * Node process.
 */

const CONN_RATE_WINDOW_MS = 2_000;    // flood-detection window
const CONN_RATE_THRESHOLD = 20;       // connections from one IP within that window
const MAX_CONCURRENT_PER_IP = 15;     // simultaneous open sockets from one IP
const SLOW_DATA_TIMEOUT_MS = 4_000;   // a connection must send *something* within this long

const VIOLATIONS_BEFORE_BAN = 3;      // strikes within VIOLATION_WINDOW_MS before a ban
const VIOLATION_WINDOW_MS = 30_000;   // window the strikes are counted in
const BAN_DURATION_MS = Number(process.env.BLOCK_MS || 5 * 60_000); // how long a banned IP is dropped outright (5 min)
// A browser keeps 1-2 idle "spare" connections open, so ONE silent socket is
// normal. Slowloris holds dozens. A silent/unfinished socket only counts as a
// strike when this many unfinished sockets from the same IP exist at once.
const SLOW_MIN_STALLED = Number(process.env.SLOW_MIN_STALLED || 4);
const IDLE_REAP_MS = 15_000;          // lone unfinished sockets are closed (without a strike) after this

const connTimestamps = new Map();   // ip -> [recent connection timestamps]
const concurrentByIp = new Map();   // ip -> currently-open socket count
const violationsByIp = new Map();   // ip -> [recent violation timestamps]
const bannedUntil = new Map();      // ip -> ban-expiry timestamp
const banInfo = new Map();          // ip -> { reason, kind, at }
const pendingByIp = new Map();      // ip -> Set of sockets that have not completed an HTTP request yet
let onBanCb = null;
const connLog = new Map();          // ip -> connection timestamps (last CONN_LOG_MS), used as the ML "SYN count"
const CONN_LOG_MS = 10_000;

const stats = {
  activeConnections: 0,
  totalConnections: 0,
  floodBlocked: 0,
  slowlorisBlocked: 0,
  bannedConnections: 0, // connections dropped instantly because the IP was already banned
  currentlyBannedIps: 0,
};

function pruneOld(list, now, windowMs) {
  while (list.length && now - list[0] > windowMs) list.shift();
}

function ipOf(socket) {
  // Strip the ::ffff: IPv4-mapped-IPv6 prefix Node sometimes adds so
  // 127.0.0.1 and ::ffff:127.0.0.1 count as the same client.
  const raw = socket.remoteAddress || 'unknown';
  return raw.replace(/^::ffff:/, '');
}

function isBanned(ip, now) {
  const until = bannedUntil.get(ip);
  if (!until) return false;
  if (now >= until) {
    bannedUntil.delete(ip);
    return false;
  }
  return true;
}

/**
 * Record a strike against an IP (a flood or slowloris trip). If it has
 * accumulated enough strikes within the violation window, ban it.
 * Returns true if this strike caused a new ban.
 */
function strike(ip, now, kind = 'flood', reason = '') {
  const list = violationsByIp.get(ip) || [];
  pruneOld(list, now, VIOLATION_WINDOW_MS);
  list.push(now);
  violationsByIp.set(ip, list);

  if (list.length >= VIOLATIONS_BEFORE_BAN && !bannedUntil.has(ip)) {
    bannedUntil.set(ip, now + BAN_DURATION_MS);
    banInfo.set(ip, { reason: reason || kind, kind, at: now });
    if (onBanCb) onBanCb(ip, `TCP layer: ${kind}${reason ? ' (' + reason + ')' : ''}`, now + BAN_DURATION_MS);
    return true;
  }
  return false;
}

/**
 * Attach the monitor to an http.Server (or any net.Server). Call this
 * BEFORE server.listen(). `broadcast` is the same function proxy-server.js
 * uses to push events to the dashboard over WebSocket — tcp events use
 * `{ type: 'tcp', kind: 'flood' | 'slowloris' | 'banned', ip, ts }` so
 * dashboard.js can tell them apart from HTTP-layer `{ type: 'decision' }`
 * events.
 */
function attach(server, { broadcast, onBan } = {}) {
  onBanCb = onBan || null;
  server.on('connection', (socket) => {
    const ip = ipOf(socket);
    const now = Date.now();

    // Log every connection attempt (even ones dropped below) so the ML
    // scorer can use "new TCP connections from this IP lately" as its
    // SYN-flag-count feature.
    const log = connLog.get(ip) || [];
    pruneOld(log, now, CONN_LOG_MS);
    log.push(now);
    connLog.set(ip, log);

    // ---- 0. Already-banned IP: drop instantly, do no further work ----
    if (isBanned(ip, now)) {
      stats.bannedConnections++;
      stats.totalConnections++;
      if (broadcast) {
        broadcast({ type: 'tcp', kind: 'banned', ip, ts: now, reason: 'IP is temporarily banned' });
      }
      socket.destroy();
      return;
    }

    // ---- 1. Connection-rate / concurrency flood check ----
    const timestamps = connTimestamps.get(ip) || [];
    pruneOld(timestamps, now, CONN_RATE_WINDOW_MS);
    timestamps.push(now);
    connTimestamps.set(ip, timestamps);

    const concurrent = (concurrentByIp.get(ip) || 0) + 1;
    concurrentByIp.set(ip, concurrent);
    stats.activeConnections++;
    stats.totalConnections++;

    const floodByRate = timestamps.length > CONN_RATE_THRESHOLD;
    const floodByConcurrency = concurrent > MAX_CONCURRENT_PER_IP;

    if (floodByRate || floodByConcurrency) {
      stats.floodBlocked++;
      const why = floodByRate ? `${timestamps.length} connections in ${CONN_RATE_WINDOW_MS}ms` : `${concurrent} concurrent connections`;
      const banned = strike(ip, now, 'flood', why);
      if (broadcast) {
        broadcast({
          type: 'tcp', kind: 'flood', ip, ts: now, banned,
          reason: why,
        });
      }
      socket.destroy(); // never reaches the HTTP proxy
      concurrentByIp.set(ip, Math.max(0, concurrent - 1));
      stats.activeConnections = Math.max(0, stats.activeConnections - 1);
      stats.currentlyBannedIps = bannedUntil.size;
      return;
    }

    // ---- 2. Slowloris-style check: a connection must COMPLETE an HTTP request.
    // Silent sockets and drip-fed partial headers both stay "pending". One
    // pending socket is a normal browser spare connection; SLOW_MIN_STALLED+
    // pending sockets from one IP is Slowloris.
    let pend = pendingByIp.get(ip);
    if (!pend) { pend = new Set(); pendingByIp.set(ip, pend); }
    pend.add(socket);
    const slowTimer = setTimeout(() => {
      if (socket.destroyed || !pend.has(socket)) return;
      if (pend.size >= SLOW_MIN_STALLED) {
        stats.slowlorisBlocked++;
        const why = `${pend.size} unfinished connections, no complete request within ${SLOW_DATA_TIMEOUT_MS}ms`;
        const banned = strike(ip, Date.now(), 'slowloris', why);
        if (broadcast) broadcast({ type: 'tcp', kind: 'slowloris', ip, ts: Date.now(), banned, reason: why });
        socket.destroy();
        stats.currentlyBannedIps = bannedUntil.size;
      }
    }, SLOW_DATA_TIMEOUT_MS);
    const reapTimer = setTimeout(() => { if (!socket.destroyed && pend.has(socket)) socket.destroy(); }, IDLE_REAP_MS);
    socket._tcpDone = () => { pend.delete(socket); clearTimeout(slowTimer); clearTimeout(reapTimer); };

    socket.once('close', () => {
      clearTimeout(slowTimer); clearTimeout(reapTimer);
      pend.delete(socket); if (!pend.size) pendingByIp.delete(ip);
      const c = (concurrentByIp.get(ip) || 1) - 1;
      if (c <= 0) concurrentByIp.delete(ip); else concurrentByIp.set(ip, c);
      stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    });
  });

  // A socket that has produced a complete HTTP request is no longer "pending".
  const seen = (req) => { const sk = req.socket; if (sk && sk._tcpDone) { sk._tcpDone(); sk._tcpDone = null; } };
  server.on('request', seen);
  server.on('upgrade', seen);

  // Periodic housekeeping so these maps don't grow forever on a long-running
  // server — drop entries that are fully stale/expired.
  setInterval(() => {
    const now = Date.now();
    for (const [ip, until] of bannedUntil) {
      if (now >= until) { bannedUntil.delete(ip); banInfo.delete(ip); }
    }
    for (const [ip, list] of connTimestamps) {
      pruneOld(list, now, CONN_RATE_WINDOW_MS);
      if (list.length === 0) connTimestamps.delete(ip);
    }
    for (const [ip, list] of connLog) {
      pruneOld(list, now, CONN_LOG_MS);
      if (list.length === 0) connLog.delete(ip);
    }
    for (const [ip, list] of violationsByIp) {
      pruneOld(list, now, VIOLATION_WINDOW_MS);
      if (list.length === 0) violationsByIp.delete(ip);
    }
    stats.currentlyBannedIps = bannedUntil.size;
  }, 10_000).unref();
}

function bannedList() {
  const now = Date.now();
  return [...bannedUntil.entries()].filter(([, u]) => u > now).map(([ip, until]) => ({ ip, until, ...(banInfo.get(ip) || {}) }));
}
function unban(ip) {
  const had = bannedUntil.delete(ip);
  banInfo.delete(ip); violationsByIp.delete(ip); connTimestamps.delete(ip);
  return had;
}
function snapshot() {
  return {
    ...stats,
    banDurationMs: BAN_DURATION_MS,
    limits: { connRate: CONN_RATE_THRESHOLD, connWindowMs: CONN_RATE_WINDOW_MS, maxConcurrent: MAX_CONCURRENT_PER_IP, slowTimeoutMs: SLOW_DATA_TIMEOUT_MS, slowMinStalled: SLOW_MIN_STALLED, strikes: VIOLATIONS_BEFORE_BAN },
    banned: bannedList(),
    trackedIps: concurrentByIp.size,
    currentlyBannedIps: bannedUntil.size,
  };
}

/** Exposed for tests/manual use — not called by proxy-server.js itself. */
function isIpBanned(ip) {
  return isBanned(ip, Date.now());
}

/** How many TCP connections this IP opened in the last windowMs (<= 10 s of history kept). */
function recentConnections(ip, windowMs = CONN_LOG_MS) {
  const list = connLog.get(String(ip).replace(/^::ffff:/, ''));
  if (!list) return 0;
  const now = Date.now();
  return list.filter((t) => now - t <= windowMs).length;
}

module.exports = { attach, snapshot, isIpBanned, recentConnections, bannedList, unban };
