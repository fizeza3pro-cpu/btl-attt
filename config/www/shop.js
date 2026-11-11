// Lab Shop - frontend goi API that tren may chu B (/api/...). Moi thao tac deu di qua mang:
// neu may khach bi firewall chan, thao tac se that bai va den trang thai chuyen do.
const API_TIMEOUT_MS = 3000;
// const ADMIN_API_KEY = 'ls_live_7f3a9c2e51b84d06a1e9';   // TODO: chuyen sang bien moi truong (dung cho /api/admin/orders)
const fmt = (v) => v.toLocaleString('vi-VN') + ' ₫';
const stars = (r) => '★★★★★'.slice(0, Math.round(r)) + '☆☆☆☆☆'.slice(0, 5 - Math.round(r));

async function api(path, opts = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), API_TIMEOUT_MS);
  const t0 = performance.now();
  try {
    const res = await fetch(path, {
      ...opts, signal: ctl.signal, cache: 'no-store', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
    const data = await res.json().catch(() => ({}));
    setServer(true, Math.round(performance.now() - t0));
    if (!res.ok) throw Object.assign(new Error(data.error || ('HTTP ' + res.status)), { http: res.status });
    return data;
  } catch (e) {
    if (!e.http) setServer(false);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- Den trang thai may chu ----------
function setServer(ok, ms) {
  document.querySelectorAll('[data-srv]').forEach((el) => {
    el.classList.toggle('down', !ok);
    el.textContent = ok ? `● Máy chủ trực tuyến · ${ms} ms` : '● Mất kết nối máy chủ';
  });
}
function startHealth() {
  const tick = () => api('/api/health').catch(() => {});
  tick();
  setInterval(tick, 3000);
}

// ---------- Thong bao ----------
function toast(msg, bad = false) {
  let t = document.querySelector('.toast');
  if (!t) { t = document.createElement('div'); t.className = 'toast'; document.body.appendChild(t); }
  t.textContent = msg; t.classList.toggle('bad', bad); t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2600);
}
function setBadge(n) { document.querySelectorAll('[data-cart-count]').forEach((el) => (el.textContent = n)); }
async function refreshBadge() { try { setBadge((await api('/api/cart')).count); } catch (e) {} }

// ---------- San pham ----------
async function renderProducts(el) {
  el.innerHTML = '<p style="color:#667085">Đang tải sản phẩm từ máy chủ…</p>';
  try {
    const { products } = await api('/api/products');
    el.innerHTML = products.map((p) => `
      <div class="card">
        ${p.tag ? `<span class="badge${p.tag === 'Mới' ? ' new' : ''}">${p.tag}</span>` : ''}
        <div class="thumb" style="background:${p.color}">${p.icon}</div>
        <div class="b">
          <h3>${p.name}</h3>
          <div class="stars">${stars(p.rate)}<small>${p.rate} (${p.n})</small></div>
          <div class="prices"><span class="price">${fmt(p.price)}</span>${p.old ? `<span class="old">${fmt(p.old)}</span>` : ''}</div>
          <button class="btn" onclick="addToCart(${p.id})">Thêm vào giỏ</button>
        </div>
      </div>`).join('');
  } catch (e) {
    el.innerHTML = '<div class="panel err">⚠️ Không tải được sản phẩm: không kết nối được máy chủ.</div>';
  }
}
async function addToCart(id) {
  try {
    const r = await api('/api/cart', { method: 'POST', body: JSON.stringify({ id }) });
    setBadge(r.count);
    toast(`Đã thêm "${r.added}" vào giỏ`);
  } catch (e) {
    toast('Không thêm được vào giỏ — mất kết nối máy chủ', true);
  }
}

// ---------- Gio hang ----------
async function renderCart(el) {
  el.innerHTML = '<p style="color:#667085">Đang tải giỏ hàng…</p>';
  try {
    const [c, me] = await Promise.all([api('/api/cart'), api('/api/me')]);
    setBadge(c.count);
    if (!c.items.length) { el.innerHTML = '<p>Giỏ hàng trống. <a href="index.html" style="color:#4f46e5;font-weight:600">Tiếp tục mua sắm →</a></p>'; return; }
    const pay = me.logged_in
      ? `<div class="okmsg" style="margin:16px 0 0">👤 Đang đăng nhập: <b>${me.name}</b> (${me.email})</div>
         <div style="text-align:right;margin-top:16px"><button class="btn" style="padding:13px 26px" onclick="checkout()">Thanh toán</button></div>`
      : `<div class="err" style="margin-top:16px">🔒 Bạn cần <b>đăng nhập</b> trước khi thanh toán.</div>
         <div style="text-align:right;margin-top:16px"><a class="btn" style="display:inline-block;padding:13px 26px" href="login.html?next=cart.html">Đăng nhập để thanh toán</a></div>`;
    el.innerHTML = `<table><tr><th>Sản phẩm</th><th>Đơn giá</th><th>SL</th><th>Thành tiền</th></tr>
      ${c.items.map((r) => `<tr><td>${r.icon} ${r.name}</td><td>${fmt(r.price)}</td><td>${r.qty}</td><td><b>${fmt(r.line)}</b></td></tr>`).join('')}</table>
      <div class="total">Tổng cộng: <span>${fmt(c.total)}</span></div>${pay}`;
  } catch (e) {
    el.innerHTML = '<div class="err">⚠️ Không tải được giỏ hàng: không kết nối được máy chủ.</div>';
  }
}
async function checkout() {
  try {
    const o = await api('/api/order', { method: 'POST', body: '{}' });
    setBadge(0);
    document.getElementById('cart').innerHTML = `<div class="success"><div class="big">✅</div><h2>Thanh toán thành công!</h2>
      <p style="color:#667085">Mã đơn <b>${o.order_id}</b> · ${o.count} sản phẩm · ${fmt(o.total)} · khách hàng ${o.customer}</p></div>`;
  } catch (e) {
    if (e.http === 401) { location.href = 'login.html?next=cart.html'; return; }
    toast('Thanh toán thất bại — ' + (e.http ? e.message : 'mất kết nối máy chủ'), true);
  }
}

// ---------- Dang nhap ----------
async function doLogin(ev) {
  ev.preventDefault();
  const box = document.getElementById('login-msg');
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  try {
    const r = await api('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    const next = new URLSearchParams(location.search).get('next');
    const safeNext = next && /^[a-z]+\.html$/.test(next) ? next : null;   // chi cho phep chuyen trong site (chong open redirect)
    box.innerHTML = `<div class="okmsg">✅ Xin chào ${r.name}! Đăng nhập thành công.${safeNext ? ' Đang quay lại giỏ hàng…' : ''}</div>`;
    if (safeNext) setTimeout(() => { location.href = safeNext; }, 900);
  } catch (e) {
    const msg = e.http === 429 ? '⛔ Địa chỉ của bạn tạm bị khóa do đăng nhập sai nhiều lần.'
      : e.http === 401 ? '❌ Sai email hoặc mật khẩu.'
      : e.http ? '⚠️ ' + e.message : '⚠️ Không kết nối được máy chủ.';
    box.innerHTML = `<div class="err">${msg}</div>`;
  }
}

// ---------- Khoi dong ----------
// Lien ket nhanh (dung cho demo/kiem thu): index.html?them=3 them san pham 3; cart.html?dathang=1 dat hang
document.addEventListener('DOMContentLoaded', async () => {
  startHealth();
  const q = new URLSearchParams(location.search);
  const id = parseInt(q.get('them') || '', 10);
  if (id) await addToCart(id); else refreshBadge();
  if (q.get('dathang') === '1' && document.getElementById('cart')) checkout();
});
