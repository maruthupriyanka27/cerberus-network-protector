// Shared helpers — no backend. All data here is mocked in-browser
// so every page can be previewed on its own.

function randFingerprint(){
  const hex = "0123456789abcdef";
  let s = "fp_";
  for (let i=0;i<8;i++) s += hex[Math.floor(Math.random()*16)];
  s += "...";
  for (let i=0;i<4;i++) s += hex[Math.floor(Math.random()*16)];
  return s;
}

function bandFor(score){
  if (score >= 70) return { band: "block", label: "Block" };
  if (score >= 40) return { band: "challenge", label: "Challenge" };
  return { band: "allow", label: "Allow" };
}

function scoreBarHTML(score){
  const { band } = bandFor(score);
  const pct = Math.min(100, score);
  return `<div class="scorebar"><div class="fill band-${band}" style="width:${pct}%"></div></div>`;
}

function badgeHTML(score){
  const { band, label } = bandFor(score);
  return `<span class="badge ${band}">${label}</span>`;
}

function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }

// ---- Cross-port console helpers ----
// The admin console (dashboard.html / simulator.html / this file) is served
// on its own port, separate from the public-facing proxy (the real site +
// the scoring gate + the PoW challenge page). Any link/fetch that needs to
// reach the OTHER side has to go cross-origin explicitly — same hostname,
// different port. Keep these two numbers in sync with PROXY_PORT /
// ADMIN_PORT in backend/proxy-server.js if you ever change them.
const PUBLIC_PORT = 8080;
const ADMIN_PORT = 9000;

// Dual-port (LAN/VPS): hostname:8080 <-> hostname:9000. Hosted single-port
// (Render etc.): everything is one origin, so just use location.origin.
function publicOrigin(){ return location.port === String(ADMIN_PORT) ? `${location.protocol}//${location.hostname}:${PUBLIC_PORT}` : location.origin; }
function adminOrigin(){ return location.port === String(PUBLIC_PORT) ? `${location.protocol}//${location.hostname}:${ADMIN_PORT}` : location.origin; }

// Any <a data-origin="public" href="/path"> or data-origin="admin" gets its
// href rewritten on load to point at the other port, same hostname. Plain
// relative links with no data-origin are left alone (same-origin as the
// page they're on).
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('a[data-origin]').forEach((a) => {
    const base = a.dataset.origin === 'public' ? publicOrigin() : adminOrigin();
    a.setAttribute('href', base + a.getAttribute('href'));
  });
});