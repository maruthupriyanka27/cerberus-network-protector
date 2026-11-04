/**
 * Traffic generators shared by (a) tools/record-training-data.js, which feeds
 * the ML model, and (b) tools/selftest.js. Each profile is one visitor.
 * `id` is sent as X-Sim-Client, which the proxy only honours when started with
 * ALLOW_SIM_IDS=1 (training / selftest runs) — never in the real demo.
 */
const http = require('http');

const CHROME = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0'];
const PAGES = ['/', '/search?q=jacket', '/search?cat=Camp', '/product/field-jacket', '/product/trail-pack-22', '/product/wool-beanie',
  '/product/camp-mug', '/product/steel-bottle', '/product/ridge-boots', '/login', '/search?q=boots', '/search?cat=Packs'];
const ASSETS = ['/northbank.css', '/northbank.js', '/alerts.js'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = (a, b) => a + Math.random() * (b - a);
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

function makeClient({ host = 'localhost', port = 8080, id, ua, keepAlive = true, maxSockets = 6, bind } = {}) {
  const agent = new http.Agent({ keepAlive, maxSockets, localAddress: bind });
  const stats = { sent: 0, tiers: {}, statuses: {}, firstNonAllowAt: null, firstBlockAt: null, lastTier: null, startedAt: Date.now(), maxScore: 0 };
  function get(path, headers = {}) {
    return new Promise((resolve) => {
      const h = { ...(id ? { 'X-Sim-Client': id } : {}), ...headers };
      if (ua) h['User-Agent'] = ua;
      const req = http.request({ host, port, path, method: 'GET', agent, headers: h, localAddress: bind, timeout: 8000 }, (res) => {
        res.resume();
        res.on('end', () => {
          const tier = res.headers['x-tier'] || (res.statusCode === 429 ? 'block' : '?');
          stats.sent++; stats.lastTier = tier;
          stats.tiers[tier] = (stats.tiers[tier] || 0) + 1;
          stats.statuses[res.statusCode] = (stats.statuses[res.statusCode] || 0) + 1;
          stats.maxScore = Math.max(stats.maxScore, Number(res.headers['x-score'] || 0));
          const t = Date.now() - stats.startedAt;
          if (tier !== 'allow' && stats.firstNonAllowAt === null) stats.firstNonAllowAt = { ms: t, req: stats.sent };
          if (tier === 'block' && stats.firstBlockAt === null) stats.firstBlockAt = { ms: t, req: stats.sent };
          resolve({ status: res.statusCode, tier, score: Number(res.headers['x-score'] || 0), ml: res.headers['x-ml-prob'] });
        });
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => { stats.sent++; stats.tiers.error = (stats.tiers.error || 0) + 1; resolve({ status: 0, tier: 'error', score: 0 }); });
      req.end();
    });
  }
  return { get, stats, agent, destroy: () => agent.destroy() };
}

const BROWSER_PAGE = { Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9' };
const BROWSER_ASSET = { Accept: '*/*', 'Accept-Language': 'en-US,en;q=0.9' };

/** A real person: opens a page, the browser fetches its assets, then they read. */
async function pageView(c, path, firstVisit) {
  const r = await c.get(path, BROWSER_PAGE);
  if (firstVisit) await Promise.all(ASSETS.map((a) => c.get(a, BROWSER_ASSET)));
  else if (Math.random() < 0.3) await c.get(pick(ASSETS), BROWSER_ASSET); // revalidations
  return r;
}

const BENIGN = {
  casual:  async (c, secs) => { const end = Date.now() + secs * 1000; let first = true; while (Date.now() < end) { await pageView(c, pick(PAGES), first); first = false; await sleep(rnd(2000, 7000)); } },
  fast:    async (c, secs) => { const end = Date.now() + secs * 1000; let first = true; while (Date.now() < end) { await pageView(c, pick(PAGES), first); first = false; await sleep(rnd(500, 1400)); } },
  searcher: async (c, secs) => { const end = Date.now() + secs * 1000; let first = true, i = 0; while (Date.now() < end) { await pageView(c, '/search?q=' + pick(['jacket','boots','pack','mug','lantern','beanie','bottle']) + (i++ % 3), first); first = false; await sleep(rnd(1500, 3500)); } },
  refresher: async (c, secs) => { const end = Date.now() + secs * 1000; await pageView(c, '/', true); const p = pick(PAGES); while (Date.now() < end) { await pageView(c, p, false); await sleep(rnd(1800, 3200)); } },
  tabbed:  async (c, secs) => { const end = Date.now() + secs * 1000; let first = true; while (Date.now() < end) { await Promise.all([pageView(c, pick(PAGES), first), pageView(c, pick(PAGES), false)]); first = false; await sleep(rnd(2500, 6000)); } },
};

const bare = { 'User-Agent': undefined };
const ATTACK = {
  // identical URL, no Accept header, as fast as possible
  sameUrlFlood:  async (c, secs) => { const end = Date.now() + secs * 1000; const p = '/search?q=a'; while (Date.now() < end) { await Promise.all(Array.from({ length: 4 }, () => c.get(p, {}))); await sleep(rnd(0, 40)); } },
  // proper headers, rotating URLs (cache-busting) - the "smart" flood
  smartFlood:    async (c, secs) => { const end = Date.now() + secs * 1000; await pageView(c, '/', true); let i = 0; while (Date.now() < end) { await Promise.all(Array.from({ length: 3 }, () => c.get('/search?q=' + (i++) + Math.random().toString(36).slice(2, 5), BROWSER_PAGE))); await sleep(rnd(20, 120)); } },
  // crawler: many different pages, never loads css/js
  scraper:       async (c, secs) => { const end = Date.now() + secs * 1000; let i = 0; while (Date.now() < end) { await c.get(PAGES[i++ % PAGES.length], BROWSER_PAGE); await sleep(rnd(60, 220)); } },
  // static-file hammering
  assetFlood:    async (c, secs) => { const end = Date.now() + secs * 1000; while (Date.now() < end) { await Promise.all(Array.from({ length: 6 }, () => c.get(pick(ASSETS), BROWSER_ASSET))); await sleep(rnd(0, 30)); } },
  // new TCP connection per request (no keep-alive): HTTP flood that also looks like a connection flood
  noKeepAlive:   async (c, secs) => { const end = Date.now() + secs * 1000; while (Date.now() < end) { await Promise.all(Array.from({ length: 3 }, () => c.get('/', BROWSER_PAGE))); await sleep(rnd(30, 120)); } },
  // slower bot, tool user-agent, no assets
  slowBot:       async (c, secs) => { const end = Date.now() + secs * 1000; let i = 0; while (Date.now() < end) { await c.get(PAGES[i++ % PAGES.length], { Accept: '*/*' }); await sleep(rnd(250, 450)); } },
};

module.exports = { makeClient, BENIGN, ATTACK, pageView, sleep, rnd, pick, CHROME, PAGES, ASSETS, BROWSER_PAGE, BROWSER_ASSET };
