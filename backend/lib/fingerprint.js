/**
 * Visitor identity.
 *
 * Each client PC is ONE visitor, identified by its IP address — NOT by
 * IP + browser. That is what makes the protection coherent: the browser
 * showing the Northbank site on a PC and the attack tools running on that same
 * PC are the same visitor, so when the dashboard blocks that PC, the website
 * in that PC's browser is blocked too.
 *
 * Behind a platform load balancer (TRUST_PROXY=1) req.ip is the real client
 * from X-Forwarded-For. Otherwise it is the TCP peer address.
 *
 * ALLOW_SIM_IDS=1 lets a request choose its own identity with the
 * X-Sim-Client header (only useful to fake many visitors from ONE machine;
 * leave it off for the real two-PC demo — an attacker must never be able to
 * pick a fresh identity).
 */
const ALLOW_SIM_IDS = process.env.ALLOW_SIM_IDS === '1';

function normalizeIp(raw) {
  let ip = String(raw || 'unknown').replace(/^::ffff:/, '');
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function clientIp(req) {
  if (ALLOW_SIM_IDS && req.headers['x-sim-client']) return 'sim:' + req.headers['x-sim-client'];
  return normalizeIp(req.ip || (req.socket && req.socket.remoteAddress));
}

// Kept for compatibility: the "fingerprint" IS the client IP now.
function fingerprint(req) { return clientIp(req); }

module.exports = { fingerprint, clientIp, normalizeIp };
