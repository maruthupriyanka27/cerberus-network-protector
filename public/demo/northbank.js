/* Northbank storefront behaviour — cart drawer. Cart lives in localStorage
   (wrapped in try/catch so the page still works if storage is blocked). */
(function () {
  var KEY = 'northbank.cart';
  var cart = [];
  try { cart = JSON.parse(localStorage.getItem(KEY)) || []; } catch (e) { cart = []; }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(cart)); } catch (e) {} }

  var $ = function (id) { return document.getElementById(id); };
  var drawer = $('drawer'), scrim = $('scrim'), toastEl = $('toast');

  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  function render() {
    var count = cart.reduce(function (n, i) { return n + i.qty; }, 0);
    var total = cart.reduce(function (n, i) { return n + i.qty * i.price; }, 0);
    var badge = $('cart-count');
    badge.textContent = count; badge.hidden = count === 0;
    $('cart-total').textContent = '$' + total.toFixed(0);
    $('cart-items').innerHTML = cart.length ? cart.map(function (i) {
      return '<div class="ci"><div class="nm">' + esc(i.name) + '<span>$' + i.price + ' each</span></div>' +
        '<button data-dec="' + esc(i.id) + '" aria-label="Decrease">−</button><span>' + i.qty + '</span>' +
        '<button data-inc="' + esc(i.id) + '" aria-label="Increase">+</button>' +
        '<button class="rm" data-rm="' + esc(i.id) + '" aria-label="Remove">✕</button></div>';
    }).join('') : '<div class="cart-empty">Your cart is empty.</div>';
    $('checkout').disabled = !cart.length;
  }
  function open(on) {
    drawer.classList.toggle('on', on); scrim.classList.toggle('on', on);
    drawer.setAttribute('aria-hidden', String(!on));
  }
  var timer;
  function toast(msg) {
    toastEl.textContent = msg; toastEl.classList.add('on');
    clearTimeout(timer); timer = setTimeout(function () { toastEl.classList.remove('on'); }, 1800);
  }
  function find(id) { return cart.filter(function (i) { return i.id === id; })[0]; }

  document.addEventListener('click', function (e) {
    var t = e.target.closest('[data-add],[data-inc],[data-dec],[data-rm]');
    if (!t) return;
    if (t.dataset.add) {
      var id = t.dataset.add, item = find(id);
      if (item) item.qty++; else cart.push({ id: id, name: t.dataset.name, price: Number(t.dataset.price), qty: 1 });
      save(); render(); toast('Added ' + t.dataset.name + ' to cart');
    } else if (t.dataset.inc) { find(t.dataset.inc).qty++; save(); render(); }
    else if (t.dataset.dec) { var it = find(t.dataset.dec); it.qty--; if (it.qty < 1) cart = cart.filter(function (i) { return i !== it; }); save(); render(); }
    else if (t.dataset.rm) { cart = cart.filter(function (i) { return i.id !== t.dataset.rm; }); save(); render(); }
  });
  $('cart-open').addEventListener('click', function () { open(true); });
  $('cart-close').addEventListener('click', function () { open(false); });
  scrim.addEventListener('click', function () { open(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') open(false); });
  $('checkout').addEventListener('click', function () { open(false); toast('Demo store — no order was placed'); });
  render();
})();
