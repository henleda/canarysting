// Meridian Supply Co. storefront SPA — vanilla ES module, no build step
// (restraint ladder: static serving + fetch cover this; a framework isn't
// justified for ~7 views). Client owns routing, cart state, and catalog
// data; every shopping action fires POST /api/transaction with
// persona=standard&action=<name> so it drives real east-west mesh traffic
// through the existing gatewayCaller seam (design doc §3/§5.2).

const CART_KEY = 'meridian-cart-v1';
const PERSONA_KEY = 'meridian-persona-v1';
const ORDERS_KEY = 'meridian-orders-v1';

let catalog = [];
let dashboardUrl = '';

const app = document.getElementById('app');
const activityEl = document.getElementById('activity');
const cartCountEl = document.getElementById('cart-count');
const accountLinkEl = document.getElementById('account-link');
const redteamBanner = document.getElementById('redteam-banner');
const redteamStatus = document.getElementById('redteam-status');
const dashboardLinkEl = document.getElementById('dashboard-link');
const productTpl = document.getElementById('product-card-tpl');

// ---- persistence ----

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function loadCart() {
  return loadJSON(CART_KEY, {});
}

function saveCart(cart) {
  localStorage.setItem(CART_KEY, JSON.stringify(cart));
  updateCartBadge();
}

function loadOrders() {
  return loadJSON(ORDERS_KEY, []);
}

function saveOrders(orders) {
  localStorage.setItem(ORDERS_KEY, JSON.stringify(orders));
}

function updateCartBadge() {
  const cart = loadCart();
  const count = Object.values(cart).reduce((n, qty) => n + qty, 0);
  cartCountEl.textContent = String(count);
}

// ---- persona switcher ----

function getPersona() {
  return localStorage.getItem(PERSONA_KEY) || 'standard';
}

function setPersona(mode) {
  localStorage.setItem(PERSONA_KEY, mode);
  applyPersonaUI();
}

function applyPersonaUI() {
  const mode = getPersona();
  document.getElementById('persona-standard').classList.toggle('active', mode === 'standard');
  document.getElementById('persona-redteam').classList.toggle('active', mode === 'redteam');
  redteamBanner.hidden = mode !== 'redteam';
}

// ---- activity / receipt indicator ----

let activityTimer = null;

function showActivity(text, isError) {
  activityEl.textContent = text;
  activityEl.classList.toggle('error', Boolean(isError));
  activityEl.classList.add('show');
  clearTimeout(activityTimer);
  activityTimer = setTimeout(() => activityEl.classList.remove('show'), 3500);
}

// ---- backend action wiring (the point of the exercise) ----

// fireAction drives one storefront action against the mesh via
// POST /api/transaction persona=standard&action=<name>. URLSearchParams sets
// its own Content-Type — never construct the body by hand here (that was
// the earlier Buy-button bug: a missing Content-Type made the server see
// "unknown or missing persona").
async function fireAction(action) {
  try {
    const res = await fetch('/api/transaction', {
      method: 'POST',
      body: new URLSearchParams({ persona: 'standard', action }),
    });
    const receipt = await res.json();
    if (!res.ok) {
      showActivity(`${action} rejected (${res.status})`, true);
      return null;
    }
    showActivity(`${action} → ${(receipt.paths || []).join(', ')}`);
    return receipt;
  } catch (err) {
    showActivity(`${action} failed: ${err.message}`, true);
    return null;
  }
}

async function runSecurityTest() {
  redteamStatus.textContent = 'launching…';
  try {
    const res = await fetch('/api/transaction', {
      method: 'POST',
      body: new URLSearchParams({ persona: 'redteam' }),
    });
    const receipt = await res.json();
    if (!res.ok) {
      redteamStatus.textContent = `error (${res.status})`;
      return;
    }
    redteamStatus.textContent = `run ${receipt.run_id} in progress`;
    if (dashboardUrl) {
      dashboardLinkEl.href = dashboardUrl;
      dashboardLinkEl.hidden = false;
    }
  } catch (err) {
    redteamStatus.textContent = `error: ${err.message}`;
  }
}

// ---- routing (hash-based; the SPA never asks the server for a route) ----

function parseRoute() {
  const hash = location.hash.replace(/^#/, '') || '/browse';
  const [pathPart, queryPart] = hash.split('?');
  const segments = pathPart.split('/').filter(Boolean);
  return { segments, params: new URLSearchParams(queryPart || '') };
}

function render() {
  const { segments, params } = parseRoute();
  const [root, id] = segments;
  app.innerHTML = '';
  switch (root) {
    case 'product':
      renderProduct(id);
      break;
    case 'search':
      renderSearch(params.get('q') || '');
      break;
    case 'cart':
      renderCart();
      break;
    case 'checkout':
      renderCheckout();
      break;
    case 'login':
      renderLogin();
      break;
    case 'orders':
      renderOrders();
      break;
    case 'confirmation':
      renderConfirmation(id);
      break;
    case 'browse':
    default:
      renderBrowse(params.get('category') || '');
      break;
  }
}

// ---- shared helpers ----

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : str;
  return div.innerHTML;
}

function productCard(product) {
  const node = productTpl.content.cloneNode(true);
  node.querySelector('.product-link').href = `#/product/${product.id}`;
  node.querySelector('.product-art').textContent = product.art;
  node.querySelector('.product-name').textContent = product.name;
  node.querySelector('.product-price').textContent = `$${product.price.toFixed(2)}`;
  node.querySelector('.add-cart-btn').addEventListener('click', () => addToCart(product.id));
  node.querySelector('.buy-btn').addEventListener('click', () => {
    addToCart(product.id);
    location.hash = '#/cart';
  });
  return node;
}

function heroBlock(html) {
  const hero = document.createElement('div');
  hero.className = 'hero';
  hero.innerHTML = html;
  app.appendChild(hero);
  return hero;
}

// ---- views ----

function renderBrowse(category) {
  fireAction('browse');
  const items = category ? catalog.filter((p) => p.category === category) : catalog;
  const heading = category ? category[0].toUpperCase() + category.slice(1) : 'All gear';
  heroBlock(`<h1>${escapeHtml(heading)}</h1><p>${items.length} products for your next trip.</p>`);

  const grid = document.createElement('div');
  grid.className = 'catalog-grid';
  items.forEach((p) => grid.appendChild(productCard(p)));
  app.appendChild(grid);
}

function renderSearch(query) {
  fireAction('search');
  const q = query.trim().toLowerCase();
  const results = q
    ? catalog.filter((p) => p.name.toLowerCase().includes(q) || p.blurb.toLowerCase().includes(q))
    : [];
  heroBlock(`<h1>Search results</h1><p>${results.length} matches for "${escapeHtml(query)}".</p>`);

  if (!results.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'No products matched. Try another term.';
    app.appendChild(empty);
    return;
  }
  const grid = document.createElement('div');
  grid.className = 'catalog-grid';
  results.forEach((p) => grid.appendChild(productCard(p)));
  app.appendChild(grid);
}

function renderProduct(id) {
  const product = catalog.find((p) => p.id === id);
  if (!product) {
    app.innerHTML = '<p class="empty-state">Product not found.</p>';
    return;
  }
  fireAction('product');

  const wrap = document.createElement('div');
  wrap.className = 'product-detail';
  wrap.innerHTML = `
    <div class="product-art">${product.art}</div>
    <div class="product-detail-info">
      <h1>${escapeHtml(product.name)}</h1>
      <p class="product-price">$${product.price.toFixed(2)}</p>
      <p>${escapeHtml(product.blurb)}</p>
      <div class="qty-picker">
        <label for="qty">Qty</label>
        <input id="qty" type="number" min="1" value="1">
      </div>
      <button type="button" class="buy-btn" id="detail-add-cart">Add to Cart</button>
    </div>`;
  app.appendChild(wrap);
  wrap.querySelector('#detail-add-cart').addEventListener('click', () => {
    const qty = Math.max(1, parseInt(wrap.querySelector('#qty').value, 10) || 1);
    addToCart(product.id, qty);
    location.hash = '#/cart';
  });

  const related = catalog.filter((p) => p.category === product.category && p.id !== product.id).slice(0, 3);
  if (related.length) {
    const relatedWrap = document.createElement('div');
    relatedWrap.innerHTML = '<h2>Related items</h2>';
    const grid = document.createElement('div');
    grid.className = 'catalog-grid';
    related.forEach((p) => grid.appendChild(productCard(p)));
    relatedWrap.appendChild(grid);
    app.appendChild(relatedWrap);
  }
}

function addToCart(id, qty) {
  const cart = loadCart();
  cart[id] = (cart[id] || 0) + (qty || 1);
  saveCart(cart);
  fireAction('cart');
}

function changeQty(id, delta) {
  const cart = loadCart();
  cart[id] = (cart[id] || 0) + delta;
  if (cart[id] <= 0) delete cart[id];
  saveCart(cart);
  render();
}

function removeFromCart(id) {
  const cart = loadCart();
  delete cart[id];
  saveCart(cart);
  render();
}

function renderCart() {
  fireAction('cart');
  const cart = loadCart();
  const entries = Object.entries(cart).filter(([, qty]) => qty > 0);
  heroBlock('<h1>Your cart</h1>');

  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'Your cart is empty. Go find something for your next trip.';
    app.appendChild(empty);
    return;
  }

  let subtotal = 0;
  const list = document.createElement('div');
  entries.forEach(([id, qty]) => {
    const product = catalog.find((p) => p.id === id);
    if (!product) return;
    subtotal += product.price * qty;
    const row = document.createElement('div');
    row.className = 'cart-row';
    row.innerHTML = `
      <div class="product-art">${product.art}</div>
      <div class="name">${escapeHtml(product.name)} <small>(${escapeHtml(product.category)})</small></div>
      <div>
        <button type="button" class="qty-minus" aria-label="Decrease quantity">-</button>
        <span class="qty-value">${qty}</span>
        <button type="button" class="qty-plus" aria-label="Increase quantity">+</button>
      </div>
      <div>$${(product.price * qty).toFixed(2)}</div>
      <button type="button" class="remove-btn" aria-label="Remove">Remove</button>`;
    row.querySelector('.qty-minus').addEventListener('click', () => changeQty(id, -1));
    row.querySelector('.qty-plus').addEventListener('click', () => changeQty(id, 1));
    row.querySelector('.remove-btn').addEventListener('click', () => removeFromCart(id));
    list.appendChild(row);
  });
  app.appendChild(list);

  const summary = document.createElement('div');
  summary.className = 'cart-summary';
  summary.innerHTML = `<p class="subtotal">Subtotal: $${subtotal.toFixed(2)}</p>
    <button type="button" class="buy-btn" id="proceed-checkout">Proceed to checkout</button>`;
  app.appendChild(summary);
  summary.querySelector('#proceed-checkout').addEventListener('click', () => {
    location.hash = '#/checkout';
  });
}

function renderLogin() {
  heroBlock('<h1>Sign in</h1><p>Demo credentials are prefilled &mdash; this is presentational auth, not a real session system.</p>');

  const form = document.createElement('form');
  form.className = 'login-form';
  form.innerHTML = `
    <label>Email <input type="email" name="email" value="demo@example.com" required></label>
    <label>Password <input type="password" name="password" value="demo-password" required></label>
    <button type="submit" class="buy-btn">Sign in</button>
    <p id="login-status"></p>`;
  app.appendChild(form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const receipt = await fireAction('login');
    if (receipt && receipt.ok) {
      accountLinkEl.textContent = 'demo@example.com';
      form.querySelector('#login-status').textContent = 'Signed in.';
    }
  });
}

function renderCheckout() {
  const cart = loadCart();
  const entries = Object.entries(cart).filter(([, qty]) => qty > 0);
  if (!entries.length) {
    app.innerHTML = '<p class="empty-state">Your cart is empty &mdash; add something before checking out.</p>';
    return;
  }
  let subtotal = 0;
  entries.forEach(([id, qty]) => {
    const product = catalog.find((p) => p.id === id);
    if (product) subtotal += product.price * qty;
  });

  heroBlock(`<h1>Checkout</h1><p>Order total: $${subtotal.toFixed(2)}</p>`);

  const form = document.createElement('form');
  form.className = 'checkout-form';
  form.innerHTML = `
    <label>Shipping address <input type="text" name="address" value="123 Trailhead Ave, Boulder, CO" required></label>
    <p>Demo payment on file &mdash; no card entry needed for this demo.</p>
    <button type="submit" class="buy-btn">Place order</button>`;
  app.appendChild(form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const receipt = await fireAction('checkout');
    if (!receipt || !receipt.ok) return;
    const orderNo = `MSC-${Date.now().toString(36).toUpperCase()}`;
    const orders = loadOrders();
    orders.unshift({ id: orderNo, total: subtotal, items: entries.length, placedAt: new Date().toISOString() });
    saveOrders(orders);
    saveCart({});
    location.hash = `#/confirmation/${orderNo}`;
  });
}

function renderConfirmation(orderNo) {
  heroBlock(`<h1>Order confirmed</h1><p>Order <strong>${escapeHtml(orderNo)}</strong> is on its way.</p>`);
  const link = document.createElement('a');
  link.href = '#/orders';
  link.className = 'buy-btn';
  link.textContent = 'View your orders';
  app.appendChild(link);
}

function renderOrders() {
  fireAction('orders');
  const orders = loadOrders();
  heroBlock('<h1>Your orders</h1>');
  if (!orders.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'No orders yet this session.';
    app.appendChild(empty);
    return;
  }
  const list = document.createElement('ul');
  list.className = 'order-list';
  orders.forEach((o) => {
    const li = document.createElement('li');
    li.textContent = `${o.id} — $${o.total.toFixed(2)} — ${o.items} item(s)`;
    list.appendChild(li);
  });
  app.appendChild(list);
}

// ---- static wiring ----

document.getElementById('persona-standard').addEventListener('click', () => setPersona('standard'));
document.getElementById('persona-redteam').addEventListener('click', () => setPersona('redteam'));
document.getElementById('run-security-test').addEventListener('click', runSecurityTest);
document.getElementById('search-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const q = document.getElementById('search-input').value;
  location.hash = `#/search?q=${encodeURIComponent(q)}`;
});
window.addEventListener('hashchange', render);

// ---- boot ----

async function boot() {
  applyPersonaUI();
  updateCartBadge();
  try {
    const [catalogRes, configRes] = await Promise.all([
      fetch('/catalog.json'),
      fetch('/api/store/config'),
    ]);
    catalog = await catalogRes.json();
    const config = await configRes.json();
    dashboardUrl = config.dashboard_url || '';
  } catch (err) {
    showActivity(`failed to load storefront data: ${err.message}`, true);
    catalog = [];
  }
  render();
}

boot();
