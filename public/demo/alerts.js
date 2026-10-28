/**
 * Signal Room — Real-time Security Alert & Mitigation Popup
 * Injected into the Northbank demo storefront and demo pages.
 * Listens for live TCP-layer and L7 HTTP attacks via Server-Sent Events (SSE)
 * or WebSocket directly from the reverse proxy (port 8080).
 */
(function () {
  if (window.__SIGNAL_ROOM_ALERTS_INITIALIZED__) return;
  window.__SIGNAL_ROOM_ALERTS_INITIALIZED__ = true;

  // Configuration
  const SSE_ENDPOINT = '/_security/events';
  const STATUS_ENDPOINT = '/_security/status';
  const WS_ENDPOINT = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/_security/alerts-ws';

  let alertContainer = null;
  let shieldWidget = null;
  let activePopup = null;
  let autoDismissTimer = null;
  let recentEvents = [];
  let isUnderAttack = false;
  let attackCount = 0;
  let soundEnabled = true;

  // Sound generator using Web Audio API (gentle, non-intrusive alert tone)
  function playAlertSound(isTcp) {
    if (!soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      if (ctx.state === 'suspended') {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = isTcp ? 'sawtooth' : 'sine';
      osc.frequency.setValueAtTime(isTcp ? 440 : 580, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(isTcp ? 220 : 880, ctx.currentTime + 0.22);
      gain.gain.setValueAtTime(0.06, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.24);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    } catch (e) {
      // Audio autoplay policies or unsupported browser
    }
  }

  // Inject CSS styles for the Alert System
  function injectStyles() {
    if (document.getElementById('sr-alert-styles')) return;
    const style = document.createElement('style');
    style.id = 'sr-alert-styles';
    style.textContent = `
      /* Security Alert System Styles */
      :root {
        --sr-allow: #00B37E;
        --sr-challenge: #E8A400;
        --sr-block: #E63971;
        --sr-accent: #6C47FF;
        --sr-dark: #1A1428;
      }

      /* Floating Shield Widget (Bottom Right) */
      .sr-shield-widget {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 99998;
        display: flex;
        align-items: center;
        gap: 10px;
        background: rgba(255, 255, 255, 0.96);
        border: 1px solid #E3DCF7;
        box-shadow: 0 6px 28px rgba(108, 71, 255, 0.16);
        border-radius: 999px;
        padding: 8px 16px 8px 12px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13px;
        color: #221C35;
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        backdrop-filter: blur(12px);
      }
      .sr-shield-widget:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 32px rgba(108, 71, 255, 0.24);
        border-color: #6C47FF;
      }
      .sr-shield-icon {
        width: 26px;
        height: 26px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(0, 179, 126, 0.12);
        color: var(--sr-allow);
        font-size: 14px;
        transition: all 0.3s ease;
        flex-shrink: 0;
      }
      .sr-shield-widget.under-attack {
        border-color: var(--sr-block);
        box-shadow: 0 0 0 3px rgba(230, 57, 113, 0.2), 0 8px 30px rgba(230, 57, 113, 0.3);
        background: #FFF5F7;
      }
      .sr-shield-widget.under-attack .sr-shield-icon {
        background: var(--sr-block);
        color: #fff;
        animation: sr-pulse-icon 1s infinite alternate;
      }
      .sr-shield-text {
        display: flex;
        flex-direction: column;
        line-height: 1.25;
      }
      .sr-shield-title {
        font-weight: 700;
        font-size: 12px;
        letter-spacing: 0.02em;
      }
      .sr-shield-sub {
        font-size: 11px;
        color: #675E85;
      }
      .sr-shield-widget.under-attack .sr-shield-title {
        color: var(--sr-block);
      }
      @keyframes sr-pulse-icon {
        from { transform: scale(1); }
        to { transform: scale(1.15); box-shadow: 0 0 12px rgba(230, 57, 113, 0.8); }
      }

      /* Alert Modal / Popup (Top Center) */
      .sr-alert-wrapper {
        position: fixed;
        top: 24px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 99999;
        width: 92%;
        max-width: 540px;
        pointer-events: none;
      }
      .sr-popup-card {
        pointer-events: auto;
        background: #FFFFFF;
        border-radius: 12px;
        box-shadow: 0 16px 48px rgba(34, 28, 53, 0.24), 0 0 0 1px rgba(230, 57, 113, 0.3);
        overflow: hidden;
        border-left: 6px solid var(--sr-block);
        animation: sr-slide-down 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #221C35;
      }
      .sr-popup-card.type-tcp {
        border-left-color: #E63971;
      }
      .sr-popup-card.type-challenge {
        border-left-color: #E8A400;
      }
      @keyframes sr-slide-down {
        from { opacity: 0; transform: translateY(-30px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }
      @keyframes sr-fade-out {
        from { opacity: 1; transform: translateY(0) scale(1); }
        to { opacity: 0; transform: translateY(-20px) scale(0.96); }
      }

      .sr-popup-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 18px 12px;
        background: #FAF8FF;
        border-bottom: 1px solid #ECE7FA;
      }
      .sr-popup-badge-group {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .sr-badge-live {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: rgba(230, 57, 113, 0.12);
        color: var(--sr-block);
      }
      .sr-badge-live.challenge {
        background: rgba(232, 164, 0, 0.12);
        color: var(--sr-challenge);
      }
      .sr-live-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: currentColor;
        box-shadow: 0 0 6px currentColor;
        animation: sr-blink 1s infinite alternate;
      }
      @keyframes sr-blink { from { opacity: 1; } to { opacity: 0.3; } }

      .sr-popup-title {
        font-size: 14px;
        font-weight: 700;
        color: #221C35;
        margin: 0;
      }
      .sr-popup-close {
        background: transparent;
        border: none;
        color: #9B92B8;
        font-size: 18px;
        font-weight: 700;
        cursor: pointer;
        padding: 2px 6px;
        border-radius: 4px;
        line-height: 1;
      }
      .sr-popup-close:hover {
        color: #221C35;
        background: #ECE7FA;
      }

      .sr-popup-body {
        padding: 16px 18px;
        font-size: 13px;
        line-height: 1.5;
      }
      .sr-popup-desc {
        margin: 0 0 14px;
        color: #493F68;
        font-weight: 500;
      }
      .sr-popup-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        background: #F8F6FD;
        border: 1px solid #E8E2F7;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 12px;
        font-size: 12px;
      }
      .sr-grid-item {
        display: flex;
        flex-direction: column;
      }
      .sr-grid-label {
        font-size: 10.5px;
        text-transform: uppercase;
        color: #8E84AA;
        font-weight: 600;
        letter-spacing: 0.04em;
        margin-bottom: 3px;
      }
      .sr-grid-val {
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 12px;
        color: #221C35;
        font-weight: 600;
        word-break: break-all;
      }
      .sr-grid-val.red { color: var(--sr-block); }
      .sr-grid-val.orange { color: var(--sr-challenge); }
      .sr-grid-val.green { color: var(--sr-allow); }

      .sr-status-strip {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 11.5px;
        color: #00B37E;
        background: rgba(0, 179, 126, 0.08);
        border: 1px solid rgba(0, 179, 126, 0.2);
        border-radius: 6px;
        padding: 7px 10px;
        font-weight: 600;
      }

      .sr-progress-bar {
        height: 3px;
        background: #ECE7FA;
        width: 100%;
        overflow: hidden;
      }
      .sr-progress-fill {
        height: 100%;
        width: 100%;
        background: var(--sr-block);
        transition: width 7s linear;
      }

      /* Inspector History Modal (When Clicking Shield) */
      .sr-history-modal {
        position: fixed;
        bottom: 80px;
        right: 20px;
        width: 380px;
        max-height: 480px;
        background: #FFFFFF;
        border-radius: 12px;
        border: 1px solid #E3DCF7;
        box-shadow: 0 16px 40px rgba(34, 28, 53, 0.22);
        z-index: 99998;
        display: none;
        flex-direction: column;
        overflow: hidden;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        animation: sr-slide-up 0.25s ease-out;
      }
      .sr-history-modal.open {
        display: flex;
      }
      @keyframes sr-slide-up {
        from { opacity: 0; transform: translateY(15px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .sr-history-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        background: #FAF8FF;
        border-bottom: 1px solid #E8E2F7;
      }
      .sr-history-title {
        font-size: 13px;
        font-weight: 700;
        color: #221C35;
      }
      .sr-history-list {
        padding: 10px 14px;
        overflow-y: auto;
        max-height: 340px;
        font-size: 12px;
      }
      .sr-history-item {
        padding: 8px 0;
        border-bottom: 1px solid #F0ECFA;
      }
      .sr-history-item:last-child {
        border-bottom: none;
      }
      .sr-h-time {
        color: #9B92B8;
        font-size: 10.5px;
        font-family: monospace;
      }
      .sr-h-title {
        font-weight: 600;
        margin: 2px 0;
      }
      .sr-h-detail {
        color: #675E85;
        font-size: 11px;
      }
    `;
    document.head.appendChild(style);
  }

  // Create or retrieve the alert wrapper
  function getAlertWrapper() {
    if (!alertContainer) {
      alertContainer = document.createElement('div');
      alertContainer.className = 'sr-alert-wrapper';
      document.body.appendChild(alertContainer);
    }
    return alertContainer;
  }

  // Create the floating shield widget
  function createShieldWidget() {
    if (shieldWidget) return;
    shieldWidget = document.createElement('div');
    shieldWidget.className = 'sr-shield-widget';
    shieldWidget.title = 'Click to inspect DDoS Protection details';
    shieldWidget.innerHTML = `
      <div class="sr-shield-icon">🛡️</div>
      <div class="sr-shield-text">
        <span class="sr-shield-title" id="sr-shield-title">Anti-DDoS Active</span>
        <span class="sr-shield-sub" id="sr-shield-sub">Normal Traffic · 0 Attacks</span>
      </div>
    `;

    // History modal
    const historyModal = document.createElement('div');
    historyModal.className = 'sr-history-modal';
    historyModal.id = 'sr-history-modal';
    historyModal.innerHTML = `
      <div class="sr-history-head">
        <span class="sr-history-title">🛡️ Reverse Proxy Threat Inspector</span>
        <button class="sr-popup-close" id="sr-close-history">✕</button>
      </div>
      <div class="sr-history-list" id="sr-history-list">
        <div style="color:#8E84AA; padding: 20px 0; text-align:center;">No security incidents recorded recently. System operating normally.</div>
      </div>
    `;

    document.body.appendChild(shieldWidget);
    document.body.appendChild(historyModal);

    shieldWidget.onclick = () => {
      historyModal.classList.toggle('open');
      renderHistoryList();
    };

    document.getElementById('sr-close-history').onclick = (e) => {
      e.stopPropagation();
      historyModal.classList.remove('open');
    };
  }

  // Render the recent incident history in the modal
  function renderHistoryList() {
    const list = document.getElementById('sr-history-list');
    if (!list) return;
    if (recentEvents.length === 0) {
      list.innerHTML = '<div style="color:#8E84AA; padding: 20px 0; text-align:center;">No security incidents recorded. System normal.</div>';
      return;
    }
    list.innerHTML = recentEvents.slice(0, 15).map(e => `
      <div class="sr-history-item">
        <span class="sr-h-time">${new Date(e.ts).toLocaleTimeString()}</span>
        <div class="sr-h-title" style="color:${e.type === 'tcp' ? 'var(--sr-block)' : e.tier === 'block' ? 'var(--sr-block)' : 'var(--sr-challenge)'}">
          ${e.title}
        </div>
        <div class="sr-h-detail">${e.detail}</div>
      </div>
    `).join('');
  }

  // Update Shield Widget State
  function updateShield(isAttack, titleText, subText) {
    if (!shieldWidget) return;
    if (isAttack) {
      shieldWidget.classList.add('under-attack');
      document.getElementById('sr-shield-title').textContent = titleText || '⚠️ Attack Mitigated';
      document.getElementById('sr-shield-sub').textContent = subText || `${attackCount} threats blocked at proxy`;
    } else {
      shieldWidget.classList.remove('under-attack');
      document.getElementById('sr-shield-title').textContent = 'Anti-DDoS Active';
      document.getElementById('sr-shield-sub').textContent = attackCount ? `${attackCount} threats mitigated` : 'Normal Traffic · 0 Threats';
    }
  }

  // Display the Pop-Up Alert Message
  function showPopupAlert(data) {
    const wrapper = getAlertWrapper();
    if (activePopup) {
      try { wrapper.removeChild(activePopup); } catch (e) {}
    }
    clearTimeout(autoDismissTimer);

    attackCount++;
    isUnderAttack = true;
    playAlertSound(data.isTcp);

    const isTcp = data.isTcp;
    const card = document.createElement('div');
    card.className = `sr-popup-card ${isTcp ? 'type-tcp' : 'type-challenge'}`;

    card.innerHTML = `
      <div class="sr-popup-head">
        <div class="sr-popup-badge-group">
          <span class="sr-badge-live ${isTcp ? '' : 'challenge'}">
            <span class="sr-live-dot"></span>
            ${data.badge || 'ATTACK DETECTED'}
          </span>
          <h4 class="sr-popup-title">${data.heading}</h4>
        </div>
        <button class="sr-popup-close" title="Dismiss Alert">✕</button>
      </div>

      <div class="sr-popup-body">
        <p class="sr-popup-desc">${data.description}</p>
        
        <div class="sr-popup-grid">
          <div class="sr-grid-item">
            <span class="sr-grid-label">Attack Vector</span>
            <span class="sr-grid-val red">${data.vector}</span>
          </div>
          <div class="sr-grid-item">
            <span class="sr-grid-label">Source Identifier</span>
            <span class="sr-grid-val">${data.source}</span>
          </div>
          <div class="sr-grid-item">
            <span class="sr-grid-label">Trigger Rule</span>
            <span class="sr-grid-val">${data.reason}</span>
          </div>
          <div class="sr-grid-item">
            <span class="sr-grid-label">Mitigation Action</span>
            <span class="sr-grid-val ${isTcp ? 'red' : 'orange'}">${data.action}</span>
          </div>
        </div>

        <div class="sr-status-strip">
          <span style="font-size:14px;">🛡️</span>
          <span><b>Target Website Status:</b> Fully operational. Attack isolated and quarantined before impacting legitimate users.</span>
        </div>
      </div>
      <div class="sr-progress-bar"><div class="sr-progress-fill" id="sr-pfill"></div></div>
    `;

    wrapper.appendChild(card);
    activePopup = card;

    // Close button
    card.querySelector('.sr-popup-close').onclick = () => {
      dismissPopup(card);
    };

    // Auto-dismiss countdown
    const fill = card.querySelector('#sr-pfill');
    setTimeout(() => { if (fill) fill.style.width = '0%'; }, 50);

    autoDismissTimer = setTimeout(() => {
      dismissPopup(card);
    }, 7000);

    // Update floating widget
    updateShield(true, `⚠️ ${data.shortTitle || 'Attack Mitigated'}`, `Source: ${data.source}`);

    // Add to history
    recentEvents.unshift({
      ts: Date.now(),
      type: isTcp ? 'tcp' : 'http',
      tier: data.tier || 'block',
      title: data.heading,
      detail: `${data.vector} from ${data.source} (${data.reason}) → ${data.action}`
    });
    if (recentEvents.length > 30) recentEvents.pop();

    // Reset attack state after 10s of quiet
    setTimeout(() => {
      if (Date.now() - (data.ts || Date.now()) >= 9000) {
        isUnderAttack = false;
        updateShield(false);
      }
    }, 10000);
  }

  function dismissPopup(card) {
    if (!card) return;
    card.style.animation = 'sr-fade-out 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards';
    setTimeout(() => {
      try {
        if (card.parentNode) card.parentNode.removeChild(card);
        if (activePopup === card) activePopup = null;
      } catch (e) {}
    }, 250);
  }

  // Handle incoming TCP-layer events
  function handleTcpEvent(ev) {
    const kindLabel = {
      flood: 'TCP SYN / Connection Flood',
      slowloris: 'Slowloris (Slow Data Timeout)',
      banned: 'Banned IP Reconnection Attempt'
    }[ev.kind] || 'TCP-Level Attack';

    showPopupAlert({
      isTcp: true,
      badge: 'TCP ATTACK MITIGATED',
      heading: '⚠️ Security Alert: TCP-Layer Attack Detected',
      shortTitle: 'TCP Flood Blocked',
      description: `A malicious raw TCP connection attempt was detected from IP <b>${ev.ip}</b>. The Anti-DDoS monitor terminated the socket ahead of the web server.`,
      vector: kindLabel,
      source: ev.ip || '127.0.0.1',
      reason: ev.reason || 'Exceeded connection concurrency / rate threshold',
      action: 'Socket Destroyed (Layer 4)',
      ts: ev.ts || Date.now()
    });
  }

  // Handle incoming HTTP-layer decisions (blocks and challenges)
  function handleDecisionEvent(ev) {
    // Only pop up when someone is actually attacking (block, challenge, or high ML score)
    if (ev.tier === 'allow' && (!ev.ml || ev.ml.prob < 0.65)) return;

    const isBlock = ev.tier === 'block';
    const reasonsStr = (ev.reasons && ev.reasons.length) ? ev.reasons.join(' · ') : 'Anomalous request volume';

    showPopupAlert({
      isTcp: false,
      badge: isBlock ? 'HTTP FLOOD BLOCKED' : 'CHALLENGE ISSUED',
      heading: isBlock ? '🛡️ Security Alert: Website Attack Blocked' : '⚠️ Security Alert: Client Challenged',
      shortTitle: isBlock ? 'HTTP Attack Blocked' : 'PoW Challenge Triggered',
      description: `Someone is attempting to attack the website with rapid/suspicious requests. The scoring gate intercepted client <b>fp_${ev.fp.slice(0, 8)}…</b> on <code>${ev.path}</code>.`,
      vector: 'L7 HTTP Flood / Hammering',
      source: `fp_${ev.fp.slice(0, 8)}…`,
      reason: reasonsStr,
      action: isBlock ? `Blocked (HTTP 429 · Score: ${ev.score})` : `PoW Challenge Issued (Score: ${ev.score})`,
      tier: ev.tier,
      ts: ev.ts || Date.now()
    });
  }

  // Initialize event stream (Server-Sent Events)
  function initEventStream() {
    if (typeof EventSource !== 'undefined') {
      try {
        const es = new EventSource(SSE_ENDPOINT);
        es.onmessage = function (e) {
          try {
            const data = JSON.parse(e.data);
            if (data.type === 'tcp') handleTcpEvent(data);
            else if (data.type === 'decision') handleDecisionEvent(data);
            else if (data.type === 'test_alert') {
              if (data.kind === 'tcp') handleTcpEvent({ kind: 'flood', ip: '192.168.1.105', reason: '24 connections in 2000ms', ts: Date.now() });
              else handleDecisionEvent({ tier: 'block', fp: 'sim_test_client', path: '/search?q=exploit', score: 85, reasons: ['high request rate', 'hammering same path'], ts: Date.now() });
            }
          } catch (err) {}
        };
        es.onerror = function () {
          // If SSE fails or restarts, reconnect automatically
        };
        return;
      } catch (err) {}
    }

    // Fallback: poll status every 2.5 seconds
    setInterval(async () => {
      try {
        const res = await fetch(STATUS_ENDPOINT);
        if (!res.ok) return;
        const data = await res.json();
        if (data.isAttacking && data.lastAttack && Date.now() - data.lastAttack.ts < 3500) {
          if (data.lastAttack.type === 'tcp') handleTcpEvent(data.lastAttack);
          else handleDecisionEvent(data.lastAttack);
        }
      } catch (e) {}
    }, 2500);
  }

  // Start everything when DOM is ready
  function start() {
    injectStyles();
    createShieldWidget();
    initEventStream();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
