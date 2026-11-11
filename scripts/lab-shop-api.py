#!/usr/bin/env python3
"""
Lab Shop API - backend toi gian cho trang ban hang cua bai lab (chi dung thu vien chuan).
Chay sau Nginx: Nginx /api/ -> 127.0.0.1:8081. Gio hang luu tren may chu theo cookie phien `sid`.

  GET  /api/health      trang thai may chu
  GET  /api/products    danh sach san pham
  GET  /api/cart        gio hang cua phien
  POST /api/cart        {"id": 3}  them 1 san pham
  POST /api/order       dat hang gio hien tai -> ma don
  POST /api/login       {"email","password"} - khoa IP 5 phut sau 5 lan sai trong 5 phut
  POST /api/logout      dang xuat phien hien tai
  (POST /api/order      tra 401 neu phien CHUA dang nhap)
  GET  /api/me          tai khoan dang dang nhap cua phien

Log moi request ra stdout (journald): "<ip that> <METHOD> <path> <ma>".
Su kien xac thuc ghi JSON vao /var/log/lab-shop/auth.jsonl (analyzer doc de phat hien do mat khau).
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.environ.get("LOGS_DIRECTORY", "/var/log/lab-shop")
AUTH_LOG = os.path.join(LOG_DIR, "auth.jsonl")
FAIL_LIMIT, FAIL_WINDOW, LOCK_SECONDS = 5, 300, 300
_SALT = b"labshop-demo-salt"


def _hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), _SALT, 120_000).hex()


# Tai khoan khach hang THU NGHIEM cua lab (khong phai tai khoan that). Chi luu ban bam PBKDF2.
USERS = {"khach@labshop.vn": {"name": "Khách hàng C", "pw": _hash("Khach@2026")}}
FAILS: dict[str, list[float]] = {}
LOCKED: dict[str, float] = {}
SESS_USER: dict[str, str] = {}
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,64}$")


def auth_event(ip, kind, email):
    rec = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
           "src_ip": ip, "kind": kind, "email": re.sub(r"[^\x20-\x7e]", "?", str(email))[:80]}
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(AUTH_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass

PRODUCTS = [
    {"id": 1, "name": "Tai nghe không dây ANC", "price": 590000, "old": 790000, "icon": "🎧", "color": "#e0e7ff", "rate": 4.8, "n": 312, "tag": "-25%"},
    {"id": 2, "name": "Bàn phím cơ RGB", "price": 1250000, "icon": "⌨️", "color": "#ede9fe", "rate": 4.7, "n": 158, "tag": "Mới"},
    {"id": 3, "name": "Chuột gaming 26K DPI", "price": 450000, "old": 560000, "icon": "🖱️", "color": "#dcfce7", "rate": 4.6, "n": 421, "tag": "-20%"},
    {"id": 4, "name": "Màn hình 24\" 165Hz", "price": 2890000, "icon": "🖥️", "color": "#fef3c7", "rate": 4.9, "n": 97},
    {"id": 5, "name": "Loa bluetooth chống nước", "price": 720000, "icon": "🔊", "color": "#ffe4e6", "rate": 4.5, "n": 203},
    {"id": 6, "name": "Webcam Full HD", "price": 650000, "old": 750000, "icon": "📷", "color": "#e0f2fe", "rate": 4.4, "n": 88, "tag": "-13%"},
    {"id": 7, "name": "Ổ cứng SSD NVMe 1TB", "price": 1690000, "icon": "💾", "color": "#f3e8ff", "rate": 4.9, "n": 540, "tag": "Mới"},
    {"id": 8, "name": "Sạc dự phòng 20.000mAh", "price": 390000, "icon": "🔋", "color": "#ecfccb", "rate": 4.6, "n": 276},
]
BY_ID = {p["id"]: p for p in PRODUCTS}
CARTS: dict[str, dict[int, int]] = {}
ORDERS: list[dict] = []
LOCK = threading.Lock()
STARTED = time.time()
MAX_BODY = 4096
MAX_SESSIONS = 5000


class Handler(BaseHTTPRequestHandler):
    server_version = "LabShopAPI/1.0"
    sys_version = ""

    # ---------- tien ich ----------
    def client_ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def session(self):
        sid = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v.isalnum() and len(v) <= 64:
                sid = v
        new = sid is None
        if new:
            sid = secrets.token_hex(16)
        return sid, new

    def send_json(self, code, obj, sid=None, new=False):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if sid and new:
            self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def cart_view(self, sid):
        cart = CARTS.get(sid, {})
        items = [{**BY_ID[i], "qty": q, "line": BY_ID[i]["price"] * q} for i, q in cart.items() if i in BY_ID]
        return {"items": items, "count": sum(cart.values()), "total": sum(x["line"] for x in items)}

    # ---------- GET ----------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        sid, new = self.session()
        if path == "/api/health":
            self.send_json(200, {"status": "ok", "server": "B 10.77.0.20", "uptime_s": int(time.time() - STARTED),
                                 "time": time.strftime("%H:%M:%S")}, sid, new)
        elif path == "/api/products":
            self.send_json(200, {"products": PRODUCTS}, sid, new)
        elif path == "/api/cart":
            with LOCK:
                self.send_json(200, self.cart_view(sid), sid, new)
        elif path == "/api/me":
            email = SESS_USER.get(sid)
            self.send_json(200, {"logged_in": bool(email), "email": email,
                                 "name": USERS[email]["name"] if email else None}, sid, new)
        else:
            self.send_json(404, {"error": "not found"}, sid, new)

    # ---------- POST ----------
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        sid, new = self.session()
        if path == "/api/cart":
            data = self.read_json()
            pid = data.get("id") if isinstance(data, dict) else None
            if not isinstance(pid, int) or pid not in BY_ID:
                self.send_json(400, {"error": "san pham khong hop le"}, sid, new)
                return
            with LOCK:
                if sid not in CARTS and len(CARTS) >= MAX_SESSIONS:
                    CARTS.clear()
                cart = CARTS.setdefault(sid, {})
                cart[pid] = min(cart.get(pid, 0) + 1, 99)
                view = self.cart_view(sid)
            self.send_json(200, {"added": BY_ID[pid]["name"], **view}, sid, new)
        elif path == "/api/logout":
            with LOCK:
                SESS_USER.pop(sid, None)
            self.send_json(200, {"ok": True}, sid, new)
        elif path == "/api/order":
            # Bat buoc dang nhap moi duoc dat hang (kiem tra o MAY CHU, khong chi an nut tren giao dien)
            if sid not in SESS_USER:
                self.send_json(401, {"error": "can dang nhap truoc khi thanh toan", "login_required": True}, sid, new)
                return
            with LOCK:
                view = self.cart_view(sid)
                if not view["items"]:
                    self.send_json(400, {"error": "gio hang trong"}, sid, new)
                    return
                order = {"order_id": f"LS{int(time.time()) % 1000000:06d}{len(ORDERS) % 100:02d}",
                         "total": view["total"], "count": view["count"], "time": time.strftime("%H:%M:%S"),
                         "customer": SESS_USER[sid]}
                ORDERS.append(order)
                CARTS.pop(sid, None)
            self.send_json(201, order, sid, new)
        elif path == "/api/login":
            self.login(sid, new)
        else:
            self.send_json(404, {"error": "not found"}, sid, new)

    def login(self, sid, new):
        ip, now = self.client_ip(), time.time()
        data = self.read_json()
        email = data.get("email", "") if isinstance(data, dict) else ""
        pw = data.get("password", "") if isinstance(data, dict) else ""
        if not isinstance(email, str) or not isinstance(pw, str) or not EMAIL_RE.match(email) or not 0 < len(pw) <= 128:
            auth_event(ip, "login_invalid_input", email)
            self.send_json(400, {"error": "du lieu dang nhap khong hop le"}, sid, new)
            return
        with LOCK:
            if LOCKED.get(ip, 0) > now:
                auth_event(ip, "login_locked", email)
                self.send_json(429, {"error": "tam khoa do dang nhap sai nhieu lan",
                                     "retry_after_s": int(LOCKED[ip] - now)}, sid, new)
                return
            u = USERS.get(email.lower())
            ok = bool(u) and hmac.compare_digest(u["pw"], _hash(pw))
            if ok:
                FAILS.pop(ip, None)
                SESS_USER[sid] = email.lower()
            else:
                f = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW] + [now]
                FAILS[ip] = f
                if len(f) >= FAIL_LIMIT:
                    LOCKED[ip] = now + LOCK_SECONDS
        if ok:
            auth_event(ip, "login_ok", email)
            self.send_json(200, {"ok": True, "name": u["name"]}, sid, new)
        else:
            auth_event(ip, "login_fail", email)
            self.send_json(401, {"error": "sai email hoac mat khau"}, sid, new)

    def log_message(self, fmt, *args):  # gon, an toan cho journald
        print(f"{self.client_ip()} {self.command} {self.path[:120]} {args[1] if len(args) > 1 else '-'}", flush=True)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8081), Handler)
    print("LabShopAPI listening on 127.0.0.1:8081", flush=True)
    srv.serve_forever()
