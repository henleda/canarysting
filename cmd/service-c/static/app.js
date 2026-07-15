// Meridian Supply Co. storefront SPA — vanilla ES module, no build step
// (restraint ladder: static serving + fetch cover this; a framework isn't
// justified for ~7 views). Client owns routing and persona UI; catalog,
// cart, and order state live server-side (P2: /api/store/*, session-scoped
// via the sid cookie) — every shopping action still fires
// POST /api/transaction with persona=standard&action=<name> so it drives
// real east-west mesh traffic through the existing gatewayCaller seam
// (design doc §3/§5.2), independent of the real cart/order calls below.

const PERSONA_KEY = 'meridian-persona-v1';

let catalog = [];
let dashboardUrl = '';
let lastConfirmedOrder = null;

const app = document.getElementById('app');
const activityEl = document.getElementById('activity');
const cartCountEl = document.getElementById('cart-count');
const accountLinkEl = document.getElementById('account-link');
const redteamBanner = document.getElementById('redteam-banner');
const redteamStatus = document.getElementById('redteam-status');
const dashboardLinkEl = document.getElementById('dashboard-link');
const productTpl = document.getElementById('product-card-tpl');

// ---- persona switcher (client-only UI preference; no server state) ----

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

// ---- mesh-traffic wiring (unchanged: every action still fires the
// existing gateway-fanout transaction, independent of the store calls) ----

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

// ---- server-backed cart (P2: real state behind the sid cookie, not
// localStorage — GET/POST /api/store/cart) ----

async function fetchCartSnapshot() {
  const res = await fetch('/api/store/cart');
  const snap = await res.json();
  if (!res.ok) {
    throw new Error(snap.error || `cart fetch failed (${res.status})`);
  }
  return snap;
}

async function postCartDelta(productId, delta) {
  const res = await fetch('/api/store/cart', {
    method: 'POST',
    body: new URLSearchParams({ product_id: productId, delta: String(delta) }),
  });
  const snap = await res.json();
  if (!res.ok) {
    throw new Error(snap.error || `cart update failed (${res.status})`);
  }
  return snap;
}

function applyCartBadge(snapshot) {
  cartCountEl.textContent = String(snapshot.count);
}

async function updateCartBadge() {
  try {
    applyCartBadge(await fetchCartSnapshot());
  } catch {
    // leave the badge as-is; showActivity already covers user-visible
    // failures on the call sites that matter (add/remove/checkout).
  }
}

async function addToCart(id, qty) {
  try {
    applyCartBadge(await postCartDelta(id, qty || 1));
  } catch (err) {
    showActivity(`add to cart failed: ${err.message}`, true);
    return;
  }
  fireAction('cart');
}

async function changeQty(id, delta) {
  try {
    applyCartBadge(await postCartDelta(id, delta));
  } catch (err) {
    showActivity(`update quantity failed: ${err.message}`, true);
    return;
  }
  render();
}

async function removeFromCart(id, qty) {
  try {
    applyCartBadge(await postCartDelta(id, -qty));
  } catch (err) {
    showActivity(`remove failed: ${err.message}`, true);
    return;
  }
  render();
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

// escapeHtml is required (F4) for every server-returned string spliced into
// an innerHTML template — catalog fields (name/category/blurb/art) and cart
// item fields all originate server-side via /api/store/*. Fields assigned
// through textContent (order numbers/totals/list rows below) are safe by
// construction and don't need it.
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
  node.querySelector('.add-cart-btn').addEventListener('click', () => addToCart(product.id, 1));
  node.querySelector('.buy-btn').addEventListener('click', async () => {
    await addToCart(product.id, 1);
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
    <div class="product-art">${escapeHtml(product.art)}</div>
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
  wrap.querySelector('#detail-add-cart').addEventListener('click', async () => {
    const qty = Math.max(1, parseInt(wrap.querySelector('#qty').value, 10) || 1);
    await addToCart(product.id, qty);
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

async function renderCart() {
  fireAction('cart');
  heroBlock('<h1>Your cart</h1>');

  let snap;
  try {
    snap = await fetchCartSnapshot();
  } catch (err) {
    const errEl = document.createElement('p');
    errEl.className = 'empty-state';
    errEl.textContent = `Could not load your cart: ${err.message}`;
    app.appendChild(errEl);
    return;
  }
  applyCartBadge(snap);

  if (!snap.items.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'Your cart is empty. Go find something for your next trip.';
    app.appendChild(empty);
    return;
  }

  const list = document.createElement('div');
  snap.items.forEach((item) => {
    const product = catalog.find((p) => p.id === item.product_id);
    const art = product ? product.art : '';
    const category = product ? product.category : '';
    const row = document.createElement('div');
    row.className = 'cart-row';
    row.innerHTML = `
      <div class="product-art">${escapeHtml(art)}</div>
      <div class="name">${escapeHtml(item.name)} <small>(${escapeHtml(category)})</small></div>
      <div>
        <button type="button" class="qty-minus" aria-label="Decrease quantity">-</button>
        <span class="qty-value"></span>
        <button type="button" class="qty-plus" aria-label="Increase quantity">+</button>
      </div>
      <div class="line-total"></div>
      <button type="button" class="remove-btn" aria-label="Remove">Remove</button>`;
    row.querySelector('.qty-value').textContent = String(item.qty);
    row.querySelector('.line-total').textContent = `$${item.line_total.toFixed(2)}`;
    row.querySelector('.qty-minus').addEventListener('click', () => changeQty(item.product_id, -1));
    row.querySelector('.qty-plus').addEventListener('click', () => changeQty(item.product_id, 1));
    row.querySelector('.remove-btn').addEventListener('click', () => removeFromCart(item.product_id, item.qty));
    list.appendChild(row);
  });
  app.appendChild(list);

  const summary = document.createElement('div');
  summary.className = 'cart-summary';
  summary.innerHTML = '<p class="subtotal">Subtotal: <span class="subtotal-value"></span></p>' +
    '<button type="button" class="buy-btn" id="proceed-checkout">Proceed to checkout</button>';
  summary.querySelector('.subtotal-value').textContent = `$${snap.subtotal.toFixed(2)}`;
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

async function renderCheckout() {
  let snap;
  try {
    snap = await fetchCartSnapshot();
  } catch (err) {
    const p = document.createElement('p');
    p.className = 'empty-state';
    p.textContent = `Could not load your cart: ${err.message}`;
    app.appendChild(p);
    return;
  }
  if (!snap.items.length) {
    const p = document.createElement('p');
    p.className = 'empty-state';
    p.textContent = 'Your cart is empty — add something before checking out.';
    app.appendChild(p);
    return;
  }

  const hero = heroBlock('<h1>Checkout</h1><p>Order total: <span class="checkout-total"></span></p>');
  hero.querySelector('.checkout-total').textContent = `$${snap.subtotal.toFixed(2)}`;

  const form = document.createElement('form');
  form.className = 'checkout-form';
  form.innerHTML = `
    <label>Shipping address <input type="text" name="address" value="123 Trailhead Ave, Boulder, CO" required></label>
    <p>Demo payment on file &mdash; no card entry needed for this demo.</p>
    <button type="submit" class="buy-btn">Place order</button>`;
  app.appendChild(form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    fireAction('checkout'); // mesh traffic, independent of the real order below
    try {
      const res = await fetch('/api/store/checkout', { method: 'POST' });
      const body = await res.json();
      if (!res.ok) {
        showActivity(body.error || `checkout failed (${res.status})`, true);
        return;
      }
      lastConfirmedOrder = body.order;
      updateCartBadge();
      location.hash = `#/confirmation/${body.order.number}`;
    } catch (err) {
      showActivity(`checkout failed: ${err.message}`, true);
    }
  });
}

function renderConfirmation(orderNo) {
  const order = lastConfirmedOrder && lastConfirmedOrder.number === orderNo ? lastConfirmedOrder : null;
  const hero = heroBlock(order
    ? '<h1>Order confirmed</h1><p>Order <strong class="order-number"></strong> is on its way. Total: <span class="order-total"></span></p>'
    : '<h1>Order confirmed</h1><p>Order <strong class="order-number"></strong> is on its way.</p>');
  hero.querySelector('.order-number').textContent = orderNo;
  if (order) {
    hero.querySelector('.order-total').textContent = `$${order.total.toFixed(2)}`;
  }

  const link = document.createElement('a');
  link.href = '#/orders';
  link.className = 'buy-btn';
  link.textContent = 'View your orders';
  app.appendChild(link);
}

async function renderOrders() {
  fireAction('orders');
  heroBlock('<h1>Your orders</h1>');

  let orders;
  try {
    const res = await fetch('/api/store/orders');
    orders = await res.json();
    if (!res.ok) {
      throw new Error((orders && orders.error) || `orders fetch failed (${res.status})`);
    }
  } catch (err) {
    const errEl = document.createElement('p');
    errEl.className = 'empty-state';
    errEl.textContent = `Could not load orders: ${err.message}`;
    app.appendChild(errEl);
    return;
  }

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
    li.textContent = `${o.number} — $${o.total.toFixed(2)} — ${o.items.length} item(s)`;
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
  try {
    const [productsRes, configRes] = await Promise.all([
      fetch('/api/store/products'),
      fetch('/api/store/config'),
    ]);
    catalog = await productsRes.json();
    const config = await configRes.json();
    dashboardUrl = config.dashboard_url || '';
  } catch (err) {
    showActivity(`failed to load storefront data: ${err.message}`, true);
    catalog = [];
  }
  await updateCartBadge();
  render();
}

boot();
