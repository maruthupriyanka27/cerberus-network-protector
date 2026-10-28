/**
 * Northbank — the protected demo storefront (the "target app").
 *
 * This is deliberately a believable small web app, not a placeholder: real
 * product catalogue, working search/filter/sort, product pages, a cart, and
 * a sign-in form. Its job in the project is to be a realistic thing worth
 * protecting — every page view here arrives via the reverse proxy on :8080,
 * which scores it, and the interesting endpoints for attacks are the
 * expensive/abusable ones: /search (cheap to hammer) and POST /login
 * (credential-stuffing target).
 *
 * Page weight is kept low on purpose (one CSS + one JS file, inline SVG
 * art, no image files) because the proxy scores EVERY request including
 * static assets — a heavy page would make a normal visitor look busy.
 */
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.DEMO_PORT || 3000;

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public', 'demo')));

/* ------------------------------------------------------------------ */
/* Catalogue                                                           */
/* ------------------------------------------------------------------ */
const PRODUCTS = [
  { id: 'field-jacket',  name: 'Field Jacket',    cat: 'Jackets',     price: 129, rating: 4.8, reviews: 214, tag: 'Bestseller', art: 'jacket', c1: '#C9D6B5', c2: '#7C9A6A', blurb: 'Waxed canvas shell with a quilted lining. Four colours, built to be worn hard.', details: ['12 oz waxed canvas', 'Quilted recycled lining', '4 zipped pockets', 'Machine wash cold'] },
  { id: 'trail-pack-22', name: 'Trail Pack 22L',  cat: 'Packs',       price: 89,  rating: 4.7, reviews: 168, tag: 'New',        art: 'pack',   c1: '#F2D4B0', c2: '#D98C4A', blurb: 'Ripstop nylon day pack with a ventilated back panel and hip-belt pockets.', details: ['22 litre capacity', 'Ripstop nylon, DWR coated', 'Hydration sleeve', '720 g'] },
  { id: 'wool-beanie',   name: 'Wool Beanie',     cat: 'Accessories', price: 29,  rating: 4.9, reviews: 392, tag: null,         art: 'beanie', c1: '#E7C6C0', c2: '#B8574B', blurb: 'Merino-blend rib knit. Warm when wet, soft against the skin.', details: ['70% merino / 30% recycled poly', 'One size', 'Made in Portugal'] },
  { id: 'camp-mug',      name: 'Camp Mug',        cat: 'Camp',        price: 18,  rating: 4.6, reviews: 120, tag: null,         art: 'mug',    c1: '#CFE0E6', c2: '#5E8FA3', blurb: 'Enamel-coated steel, 350 ml. Survives drops, fires and dishwashers.', details: ['350 ml', 'Enamel on steel', 'Stackable'] },
  { id: 'steel-bottle',  name: 'Steel Bottle 1L', cat: 'Camp',        price: 34,  rating: 4.8, reviews: 276, tag: 'Bestseller', art: 'bottle', c1: '#D8E4D2', c2: '#6B8F71', blurb: 'Double-wall insulated. Cold for 24 hours, hot for 12.', details: ['1 litre', 'Double-wall vacuum', 'Leak-proof lid'] },
  { id: 'ember-lantern', name: 'Ember Lantern',   cat: 'Camp',        price: 46,  rating: 4.5, reviews: 88,  tag: 'New',        art: 'lantern',c1: '#F4E3B1', c2: '#D9A21B', blurb: 'Rechargeable LED lantern with a warm dimmable glow and 40 hour battery.', details: ['USB-C rechargeable', '300 lumens max', 'IPX4 splash-proof'] },
  { id: 'ridge-boots',   name: 'Ridge Boots',     cat: 'Footwear',    price: 159, rating: 4.7, reviews: 143, tag: null,         art: 'boot',   c1: '#E4D3C2', c2: '#8A6A4F', blurb: 'Full-grain leather hiking boots with a resoleable Vibram outsole.', details: ['Full-grain leather', 'Vibram outsole', 'Waterproof membrane'] },
  { id: 'dune-bag',      name: 'Dune Sleeping Bag', cat: 'Camp',      price: 119, rating: 4.6, reviews: 97,  tag: null,         art: 'bag',    c1: '#D9D3EE', c2: '#7A6BB8', blurb: 'Three-season synthetic bag rated to −2 °C. Packs down to the size of a loaf.', details: ['−2 °C comfort', 'Recycled synthetic fill', 'Compression sack included'] },
];
const CATEGORIES = ['Jackets', 'Packs', 'Footwear', 'Camp', 'Accessories'];

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function esc(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const money = (n) => `$${n.toFixed(0)}`;

// Simple inline-SVG product illustrations (no image requests to score).
const ART = {
  jacket: '<path d="M60 40l22-10c6 10 30 10 36 0l22 10 18 28-18 10-6-10v54H66V68l-6 10-18-10z" fill="#fff" fill-opacity=".92"/><path d="M100 36v80" stroke="currentColor" stroke-opacity=".35" stroke-width="3"/><rect x="74" y="86" width="20" height="4" rx="2" fill="currentColor" fill-opacity=".3"/><rect x="106" y="86" width="20" height="4" rx="2" fill="currentColor" fill-opacity=".3"/>',
  pack: '<rect x="62" y="28" width="76" height="98" rx="26" fill="#fff" fill-opacity=".92"/><rect x="74" y="78" width="52" height="34" rx="10" fill="currentColor" fill-opacity=".25"/><path d="M86 28c0-14 28-14 28 0" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round"/><path d="M62 70h-8v34h8M138 70h8v34h-8" stroke="#fff" stroke-opacity=".7" stroke-width="6" fill="none" stroke-linecap="round"/>',
  beanie: '<path d="M54 92c0-36 20-56 46-56s46 20 46 56z" fill="#fff" fill-opacity=".92"/><rect x="50" y="88" width="100" height="22" rx="9" fill="#fff"/><g stroke="currentColor" stroke-opacity=".28" stroke-width="3"><path d="M62 94v10M74 94v10M86 94v10M98 94v10M110 94v10M122 94v10M134 94v10"/></g><circle cx="100" cy="32" r="10" fill="#fff"/>',
  mug: '<path d="M62 48h70v58a16 16 0 0 1-16 16H78a16 16 0 0 1-16-16z" fill="#fff" fill-opacity=".92"/><path d="M132 62h10a14 14 0 0 1 0 32h-10" fill="none" stroke="#fff" stroke-width="9" stroke-linecap="round"/><rect x="58" y="42" width="78" height="9" rx="4.5" fill="currentColor" fill-opacity=".35"/>',
  bottle: '<rect x="84" y="20" width="32" height="14" rx="5" fill="currentColor" fill-opacity=".45"/><path d="M88 34h24v10c14 8 18 18 18 34v44a10 10 0 0 1-10 10H80a10 10 0 0 1-10-10V78c0-16 4-26 18-34z" fill="#fff" fill-opacity=".92"/><rect x="78" y="82" width="44" height="22" rx="5" fill="currentColor" fill-opacity=".22"/>',
  lantern: '<circle cx="100" cy="82" r="54" fill="#fff" fill-opacity=".28"/><path d="M82 30a18 18 0 0 1 36 0" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/><rect x="72" y="44" width="56" height="12" rx="4" fill="#fff"/><rect x="76" y="56" width="48" height="52" rx="6" fill="#fff" fill-opacity=".85"/><rect x="72" y="106" width="56" height="12" rx="4" fill="#fff"/><circle cx="100" cy="82" r="11" fill="currentColor" fill-opacity=".5"/>',
  boot: '<path d="M64 26h40l4 46c18 4 40 10 40 28v14a6 6 0 0 1-6 6H60a6 6 0 0 1-6-6V50z" fill="#fff" fill-opacity=".92"/><rect x="54" y="112" width="100" height="14" rx="5" fill="currentColor" fill-opacity=".4"/><path d="M72 44h26M72 56h26M72 68h26" stroke="currentColor" stroke-opacity=".3" stroke-width="3" stroke-linecap="round"/>',
  bag: '<rect x="44" y="52" width="112" height="62" rx="31" fill="#fff" fill-opacity=".92"/><g stroke="currentColor" stroke-opacity=".28" stroke-width="3" stroke-linecap="round"><path d="M80 58v50M100 56v54M120 58v50"/></g><circle cx="146" cy="83" r="9" fill="currentColor" fill-opacity=".3"/>',
};
function art(p, cls = '') {
  return `<div class="art ${cls}" style="--c1:${p.c1};--c2:${p.c2}" role="img" aria-label="${esc(p.name)}"><svg viewBox="0 0 200 150" style="color:${p.c2}" aria-hidden="true">${ART[p.art]}</svg></div>`;
}
function stars(r) {
  const full = Math.round(r);
  return `<span class="stars" aria-label="${r} out of 5">${'★'.repeat(full)}${'☆'.repeat(5 - full)}</span>`;
}
function card(p) {
  return `
  <article class="pcard">
    <a class="pcard-link" href="/product/${p.id}">
      ${p.tag ? `<span class="ptag">${esc(p.tag)}</span>` : ''}
      ${art(p)}
      <div class="pbody">
        <div class="pcat">${esc(p.cat)}</div>
        <h3>${esc(p.name)}</h3>
        <div class="prate">${stars(p.rating)} <span>${p.rating} (${p.reviews})</span></div>
      </div>
    </a>
    <div class="pfoot">
      <strong>${money(p.price)}</strong>
      <button class="btn small" data-add="${p.id}" data-name="${esc(p.name)}" data-price="${p.price}">Add to cart</button>
    </div>
  </article>`;
}

function layout({ title, body, active = '', q = '' }) {
  const link = (href, label, key) => `<a href="${href}"${active === key ? ' class="on" aria-current="page"' : ''}>${label}</a>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Northbank</title>
<meta name="description" content="Northbank — durable outdoor gear for people who actually go outside.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%232F4A3A'/%3E%3Cpath d='M6 23l7-12 4 7 3-4 6 9z' fill='%23F4EFE6'/%3E%3C/svg%3E">
<link rel="stylesheet" href="/northbank.css">
</head>
<body>
<div class="announce">Free shipping on orders over $75 · 30-day returns</div>
<header class="site-head">
  <div class="wrap head-row">
    <a class="logo" href="/"><svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#2F4A3A"/><path d="M6 23l7-12 4 7 3-4 6 9z" fill="#F4EFE6"/></svg><span>Northbank</span></a>
    <nav class="main-nav" aria-label="Main">
      ${link('/search', 'Shop all', 'shop')}
      ${CATEGORIES.map((c) => link('/search?cat=' + encodeURIComponent(c), c, 'cat-' + c)).join('')}
    </nav>
    <form class="head-search" action="/search" method="GET" role="search">
      <input type="search" name="q" value="${esc(q)}" placeholder="Search gear" aria-label="Search products" autocomplete="off">
    </form>
    <a class="head-link" href="/login">Sign in</a>
    <button class="cart-btn" id="cart-open" aria-label="Open cart">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6h15l-1.5 9h-12z"/><path d="M6 6L5 3H2"/><circle cx="9" cy="20" r="1.5"/><circle cx="18" cy="20" r="1.5"/></svg>
      <span class="cart-count" id="cart-count" hidden>0</span>
    </button>
  </div>
</header>

<main>${body}</main>

<footer class="site-foot">
  <div class="wrap foot-grid">
    <div><div class="logo small"><span>Northbank</span></div><p>Durable gear for people who actually go outside. Repair-first, ship-light.</p></div>
    <div><h4>Shop</h4>${CATEGORIES.map((c) => `<a href="/search?cat=${encodeURIComponent(c)}">${c}</a>`).join('')}</div>
    <div><h4>Help</h4><a href="/login">Account</a><a href="/search">All products</a><a href="/healthz">Status</a></div>
  </div>
  <div class="wrap foot-base">
    <span>© 2026 Northbank. Demo storefront — no real orders are taken.</span>
    <span class="shield"><i></i> Traffic protected by <a href="/_console/dashboard.html">Signal Room</a></span>
  </div>
</footer>

<aside class="drawer" id="drawer" aria-hidden="true" aria-label="Shopping cart">
  <div class="drawer-head"><h3>Your cart</h3><button class="icon-btn" id="cart-close" aria-label="Close cart">✕</button></div>
  <div class="drawer-body" id="cart-items"></div>
  <div class="drawer-foot">
    <div class="sum"><span>Subtotal</span><strong id="cart-total">$0</strong></div>
    <button class="btn block" id="checkout">Checkout</button>
    <p class="fine">Demo only — checkout does not place an order.</p>
  </div>
</aside>
<div class="scrim" id="scrim"></div>
<div class="toast" id="toast" role="status"></div>
<script src="/northbank.js" defer></script>
<script src="/alerts.js" defer></script>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* Pages                                                               */
/* ------------------------------------------------------------------ */
app.get('/', (req, res) => {
  const featured = PRODUCTS.slice(0, 4);
  res.send(layout({
    title: 'Outdoor gear built to last',
    active: '',
    body: `
<section class="hero">
  <div class="wrap hero-grid">
    <div>
      <span class="eyebrow">Autumn collection</span>
      <h1>Gear for the long way round.</h1>
      <p class="lead">Honest materials, repairable design, and a lifetime of trips. Everything we make is tested on the trails behind our workshop.</p>
      <div class="cta-row">
        <a class="btn" href="/search">Shop the collection</a>
        <a class="btn ghost" href="/search?cat=Camp">Camp essentials</a>
      </div>
      <ul class="hero-stats">
        <li><strong>4.8★</strong><span>from 1,400+ reviews</span></li>
        <li><strong>10 yr</strong><span>repair guarantee</span></li>
        <li><strong>48 h</strong><span>dispatch time</span></li>
      </ul>
    </div>
    <div class="hero-art" aria-hidden="true">
      ${art(PRODUCTS[0], 'big')}
      ${art(PRODUCTS[1], 'sm a')}
      ${art(PRODUCTS[4], 'sm b')}
    </div>
  </div>
</section>

<section class="trust">
  <div class="wrap trust-row">
    <div><strong>Free shipping</strong><span>on orders over $75</span></div>
    <div><strong>30-day returns</strong><span>no questions asked</span></div>
    <div><strong>Repair-first</strong><span>we fix, not replace</span></div>
    <div><strong>Secure checkout</strong><span>encrypted &amp; protected</span></div>
  </div>
</section>

<section class="section">
  <div class="wrap">
    <div class="sec-head"><h2>Bestsellers</h2><a href="/search">View all →</a></div>
    <div class="pgrid">${featured.map(card).join('')}</div>
  </div>
</section>

<section class="section tint">
  <div class="wrap">
    <div class="sec-head"><h2>Shop by category</h2></div>
    <div class="cat-grid">
      ${CATEGORIES.map((c) => {
        const p = PRODUCTS.find((x) => x.cat === c);
        return `<a class="cat-tile" href="/search?cat=${encodeURIComponent(c)}">${art(p)}<span>${c}</span></a>`;
      }).join('')}
    </div>
  </div>
</section>

<section class="section">
  <div class="wrap quote">
    <p>“Wore the Field Jacket through three winters of lambing season. Still looks better than the day it arrived.”</p>
    <span>— Rhea, verified buyer</span>
  </div>
</section>`,
  }));
});

app.get('/search', (req, res) => {
  const q = String(req.query.q || '').trim();
  const cat = CATEGORIES.includes(req.query.cat) ? req.query.cat : '';
  const sort = ['price-asc', 'price-desc', 'rating'].includes(req.query.sort) ? req.query.sort : 'featured';

  let list = PRODUCTS.filter((p) =>
    (!cat || p.cat === cat) &&
    (!q || `${p.name} ${p.cat} ${p.blurb}`.toLowerCase().includes(q.toLowerCase())));
  if (sort === 'price-asc') list = [...list].sort((a, b) => a.price - b.price);
  if (sort === 'price-desc') list = [...list].sort((a, b) => b.price - a.price);
  if (sort === 'rating') list = [...list].sort((a, b) => b.rating - a.rating);

  const qs = (over) => {
    const params = new URLSearchParams({ ...(q && { q }), ...(cat && { cat }), ...(sort !== 'featured' && { sort }), ...over });
    for (const [k, v] of [...params]) if (!v) params.delete(k);
    const s = params.toString();
    return '/search' + (s ? '?' + s : '');
  };
  const heading = q ? `Results for “${esc(q)}”` : cat ? esc(cat) : 'All products';

  res.send(layout({
    title: q ? `Search: ${q}` : cat || 'Shop all',
    active: cat ? 'cat-' + cat : 'shop',
    q,
    body: `
<section class="page-top"><div class="wrap">
  <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> / <span>${heading}</span></nav>
  <h1>${heading}</h1>
  <p class="muted">${list.length} product${list.length === 1 ? '' : 's'}</p>
</div></section>
<section class="section tight"><div class="wrap shop-layout">
  <aside class="filters" aria-label="Filters">
    <h4>Category</h4>
    <a href="${qs({ cat: '' })}" class="${!cat ? 'on' : ''}">All</a>
    ${CATEGORIES.map((c) => `<a href="${qs({ cat: c })}" class="${cat === c ? 'on' : ''}">${c}</a>`).join('')}
    <h4>Sort by</h4>
    <a href="${qs({ sort: '' })}" class="${sort === 'featured' ? 'on' : ''}">Featured</a>
    <a href="${qs({ sort: 'price-asc' })}" class="${sort === 'price-asc' ? 'on' : ''}">Price: low to high</a>
    <a href="${qs({ sort: 'price-desc' })}" class="${sort === 'price-desc' ? 'on' : ''}">Price: high to low</a>
    <a href="${qs({ sort: 'rating' })}" class="${sort === 'rating' ? 'on' : ''}">Top rated</a>
  </aside>
  <div>
    ${list.length
      ? `<div class="pgrid three">${list.map(card).join('')}</div>`
      : `<div class="empty"><h3>No matches for “${esc(q)}”</h3><p class="muted">Try a broader term, or browse a category.</p><a class="btn" href="/search">Clear filters</a></div>`}
  </div>
</div></section>`,
  }));
});

app.get('/product/:id', (req, res) => {
  const p = PRODUCTS.find((x) => x.id === req.params.id);
  if (!p) return notFound(req, res);
  const related = PRODUCTS.filter((x) => x.id !== p.id && x.cat === p.cat).concat(PRODUCTS.filter((x) => x.id !== p.id && x.cat !== p.cat)).slice(0, 4);
  res.send(layout({
    title: p.name,
    active: 'cat-' + p.cat,
    body: `
<section class="page-top slim"><div class="wrap">
  <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> / <a href="/search?cat=${encodeURIComponent(p.cat)}">${esc(p.cat)}</a> / <span>${esc(p.name)}</span></nav>
</div></section>
<section class="section tight"><div class="wrap pdp">
  <div>${art(p, 'pdp-art')}</div>
  <div class="pdp-info">
    ${p.tag ? `<span class="ptag static">${esc(p.tag)}</span>` : ''}
    <h1>${esc(p.name)}</h1>
    <div class="prate big">${stars(p.rating)} <span>${p.rating} · ${p.reviews} reviews</span></div>
    <div class="price">${money(p.price)}</div>
    <p class="lead small">${esc(p.blurb)}</p>
    <ul class="ticks">${p.details.map((d) => `<li>${esc(d)}</li>`).join('')}</ul>
    <div class="cta-row">
      <button class="btn" data-add="${p.id}" data-name="${esc(p.name)}" data-price="${p.price}">Add to cart — ${money(p.price)}</button>
      <a class="btn ghost" href="/search?cat=${encodeURIComponent(p.cat)}">More ${esc(p.cat.toLowerCase())}</a>
    </div>
    <div class="assure"><span>✓ Free shipping over $75</span><span>✓ 30-day returns</span><span>✓ 10-year repair guarantee</span></div>
  </div>
</div></section>
<section class="section tint"><div class="wrap">
  <div class="sec-head"><h2>You might also like</h2></div>
  <div class="pgrid">${related.map(card).join('')}</div>
</div></section>`,
  }));
});

function loginPage({ message = '', email = '' } = {}) {
  return layout({
    title: 'Sign in',
    body: `
<section class="auth"><div class="wrap auth-grid">
  <div class="auth-side">
    <span class="eyebrow">Northbank account</span>
    <h1>Welcome back.</h1>
    <p class="lead small">Track orders, save your sizes and get early access to new drops.</p>
    <ul class="ticks"><li>Faster checkout</li><li>Order history &amp; repairs</li><li>Member-only restocks</li></ul>
  </div>
  <form class="auth-card" action="/login" method="POST">
    <h2>Sign in</h2>
    ${message ? `<div class="notice">${message}</div>` : ''}
    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="${esc(email)}" placeholder="you@example.com" autocomplete="email" required>
    <label for="password">Password</label>
    <input id="password" type="password" name="password" placeholder="••••••••" autocomplete="current-password" required>
    <button class="btn block" type="submit">Sign in</button>
    <p class="fine">Demo only — this form never authenticates or stores anything. It exists as a realistic target (POST /login) for the proxy to protect.</p>
  </form>
</div></section>`,
  });
}
app.get('/login', (req, res) => res.send(loginPage()));
app.post('/login', (req, res) => {
  // Demo only — never actually authenticates or stores anything.
  const email = String((req.body && req.body.email) || '');
  res.send(layout({
    title: 'Signed in',
    body: `
<section class="auth"><div class="wrap narrow center">
  <div class="success-mark" aria-hidden="true">✓</div>
  <h1>You're signed in</h1>
  <p class="lead small">Signed in as <strong>${esc(email) || 'guest'}</strong> (demo — no real authentication happened).</p>
  <div class="cta-row center"><a class="btn" href="/">Continue shopping</a><a class="btn ghost" href="/search">Browse all gear</a></div>
</div></section>`,
  }));
});

/* JSON endpoints — handy extra traffic for the simulator and for testing */
app.get('/api/products', (req, res) => res.json(PRODUCTS.map(({ id, name, cat, price, rating }) => ({ id, name, cat, price, rating }))));
app.get('/healthz', (req, res) => res.json({ ok: true, app: 'northbank-demo', time: new Date().toISOString() }));

function notFound(req, res) {
  res.status(404).send(layout({
    title: 'Page not found',
    body: `
<section class="auth"><div class="wrap narrow center">
  <div class="big404">404</div>
  <h1>We couldn't find that page</h1>
  <p class="lead small">The trail seems to have ended. Let's get you back to base camp.</p>
  <div class="cta-row center"><a class="btn" href="/">Back to home</a><a class="btn ghost" href="/search">Shop all</a></div>
</div></section>`,
  }));
}
app.use(notFound);

app.listen(PORT, () => {
  console.log(`Northbank demo app (the protected target) listening on http://localhost:${PORT}`);
});
