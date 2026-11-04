/**
 * Signal Room — on-page security notice for the Northbank demo storefront.
 *
 * Two jobs, kept deliberately separate:
 *  1. "Is this about ME?" — polled every few seconds via /_security/mystatus
 *     (a plain lookup, not scored). If this browser's own access just got
 *     worse, don't just pop a toast and leave the visitor stuck on a stale
 *     page — take them straight to the real page that explains it (the PoW
 *     challenge, or the block page with its own live countdown).
 *  2. "Someone ELSE is being blocked somewhere on this site" — a soft,
 *     reassuring, rate-limited notice. Not every request is pushed here —
 *     only clean one-shot events (a visitor got blocked / unblocked /
 *     verified), so a flood against one visitor never spams everyone else's
 *     browser with a popup per request.
 */
(function () {
  if (window.__SIGNAL_ROOM_ALERTS_INITIALIZED__) return;
  window.__SIGNAL_ROOM_ALERTS_INITIALIZED__ = true;

  const SSE_ENDPOINT = '/_security/events';
  const MYSTATUS_ENDPOINT = '/_security/mystatus';
  const WHOAMI_ENDPOINT = '/_security/whoami';
  const POLL_MS = 3000;
  const OTHER_NOTICE_COOLDOWN_MS = 8000;

  let myIp = null;
  let myTier = null; // null until we know; prevents a false "you got worse" on first load
  let lastOtherNoticeAt = 0;
  let toastEl = null;
  let toastTimer = null;

  function injectStyles() {
    if (document.getElementById('sr-alert-styles')) return;
    const style = document.createElement('style');
    style.id = 'sr-alert-styles';
    style.textContent = [
      '.sr-toast-wrap{ position:fixed; top:16px; left:50%; transform:translateX(-50%); z-index:99999;',
      '  width:92%; max-width:420px; pointer-events:none; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }',
      '.sr-toast{ pointer-events:auto; background:#fff; border-radius:12px; padding:14px 16px;',
      '  box-shadow:0 12px 36px rgba(34,28,53,.22); display:flex; gap:12px; align-items:flex-start;',
      '  border-left:5px solid #6C47FF; animation:sr-in .25s cubic-bezier(.16,1,.3,1); }',
      '.sr-toast.warn{ border-left-color:#E8A400; }',
      '.sr-toast.bad{ border-left-color:#E63971; }',
      '.sr-toast.good{ border-left-color:#00B37E; }',
      '.sr-toast .icon{ font-size:20px; line-height:1; flex:none; }',
      '.sr-toast .msg{ font-size:13.5px; line-height:1.45; color:#221C35; font-weight:500; }',
      '.sr-toast .msg b{ font-weight:700; }',
      '.sr-toast .close{ background:none; border:none; color:#9B92B8; font-size:16px; cursor:pointer;',
      '  padding:0 2px; margin-left:auto; flex:none; }',
      '@keyframes sr-in{ from{opacity:0; transform:translateY(-16px);} to{opacity:1; transform:translateY(0);} }',
      '@keyframes sr-out{ from{opacity:1;} to{opacity:0; transform:translateY(-12px);} }'
    ].join('\n');
    document.head.appendChild(style);
  }

  function wrap() {
    let w = document.querySelector('.sr-toast-wrap');
    if (!w) { w = document.createElement('div'); w.className = 'sr-toast-wrap'; document.body.appendChild(w); }
    return w;
  }

  function showToast(icon, message, kind, autoHideMs) {
    const w = wrap();
    if (toastEl) { try { w.removeChild(toastEl); } catch (e) {} }
    clearTimeout(toastTimer);

    const card = document.createElement('div');
    card.className = 'sr-toast' + (kind ? ' ' + kind : '');
    card.innerHTML = '<span class="icon">' + icon + '</span><span class="msg">' + message + '</span><button class="close" aria-label="Dismiss">\u2715</button>';
    w.appendChild(card);
    toastEl = card;

    card.querySelector('.close').onclick = function () { dismiss(card); };
    if (autoHideMs) toastTimer = setTimeout(function () { dismiss(card); }, autoHideMs);
    return card;
  }
  function dismiss(card) {
    if (!card || !card.parentNode) return;
    card.style.animation = 'sr-out .2s ease forwards';
    setTimeout(function () {
      try { card.parentNode.removeChild(card); } catch (e) {}
      if (toastEl === card) toastEl = null;
    }, 200);
  }

  function fmtWait(ms) {
    const s = Math.max(1, Math.round(ms / 1000));
    if (s >= 60) { const m = Math.ceil(s / 60); return m + ' minute' + (m > 1 ? 's' : ''); }
    return s + ' seconds';
  }

  async function pollMyStatus() {
    try {
      const res = await fetch(MYSTATUS_ENDPOINT, { cache: 'no-store' });
      if (!res.ok) return;
      const s = await res.json();
      const prevTier = myTier;
      myTier = s.tier;
      if (prevTier === null) return; // first read — just establish a baseline, no popup

      if (prevTier === 'allow' && s.tier === 'challenge') {
        showToast('\u{1F50E}', "We need to double-check you're not a bot \u2014 this only takes a few seconds\u2026", 'warn', 0);
        setTimeout(function () { location.reload(); }, 1100);
      } else if (s.tier === 'block' && prevTier !== 'block') {
        if (s.blockSource === 'tcp') {
          const until = s.blockedUntil || (Date.now() + 5 * 60000);
          showToast('\u{1F6AB}', 'This device sent too much raw network traffic and was paused for <b>' + fmtWait(until - Date.now()) + '</b>. It will reconnect on its own.', 'bad', 0);
          const wait = Math.max(500, until - Date.now() + 500);
          setTimeout(function () { location.reload(); }, wait);
        } else {
          showToast('\u{1F6AB}', 'This device is being paused for a moment due to unusually fast browsing \u2014 taking you there now\u2026', 'bad', 0);
          setTimeout(function () { location.reload(); }, 1100);
        }
      }
    } catch (e) { /* server unreachable - nothing useful to show */ }
  }

  function showOtherNotice(sourceLabel) {
    const now = Date.now();
    if (now - lastOtherNoticeAt < OTHER_NOTICE_COOLDOWN_MS) return;
    lastOtherNoticeAt = now;
    showToast('\u{1F6E1}\uFE0F', "We noticed unusual traffic from another visitor (" + sourceLabel + ") and handled it automatically \u2014 you're not affected.", 'info', 5000);
  }

  function handlePublicEvent(ev) {
    if (!ev || ev.type !== 'visitor') return;
    if (ev.ip && myIp && ev.ip === myIp) { pollMyStatus(); return; }
    if (ev.action === 'blocked') showOtherNotice(ev.source === 'tcp' ? 'a connection flood' : 'a request flood');
  }

  function initEventStream() {
    if (typeof EventSource === 'undefined') return;
    try {
      const es = new EventSource(SSE_ENDPOINT);
      es.onmessage = function (e) {
        try { handlePublicEvent(JSON.parse(e.data)); } catch (err) {}
      };
      es.onerror = function () {};
    } catch (err) {}
  }

  async function start() {
    injectStyles();
    try {
      const who = await (await fetch(WHOAMI_ENDPOINT, { cache: 'no-store' })).json();
      myIp = who.ip;
    } catch (e) {}
    pollMyStatus();
    setInterval(pollMyStatus, POLL_MS);
    initEventStream();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
