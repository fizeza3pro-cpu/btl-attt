#!/usr/bin/env python3
"""
Lab Shop — backend FastAPI + SQLite cho trang bán hàng của bài lab.

Chạy sau Nginx: Nginx /api/ -> 127.0.0.1:8081. Giữ TƯƠNG THÍCH với bản cũ:
  - cùng các endpoint /api/*
  - vẫn ghi sự kiện xác thực JSON vào auth.jsonl (analyzer/dashboard đọc để phát hiện dò mật khẩu)
  - vẫn log mỗi request ra stdout: "<ip> <METHOD> <path> <mã>"

Biến môi trường:
  LAB_DB           đường dẫn lab.db      (mặc định: ./lab.db cạnh file này)
  LOGS_DIRECTORY   thư mục auth.jsonl    (mặc định trên B: /var/log/lab-shop; local: ./logs)
  LAB_VULN         0 (mặc định, AN TOÀN) | 1 (BẬT lỗ hổng SQLi có chủ đích cho P4 khai thác)
  LAB_HOST, LAB_PORT  địa chỉ nghe       (mặc định 127.0.0.1:8081)

CHỈ dùng trong mạng lab cô lập. LAB_VULN=1 cố tình để SQLi ở /api/login và /api/search
cho người tấn công (P4) khai thác và để P1/P2/P3 phát hiện — mặc định TẮT.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone

# Windows: ép stdout/stderr UTF-8 để log tiếng Việt không làm crash tiến trình.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("LAB_DB", os.path.join(HERE, "lab.db"))
LOG_DIR = os.environ.get("LOGS_DIRECTORY") or os.path.join(HERE, "logs")
AUTH_LOG = os.path.join(LOG_DIR, "auth.jsonl")
VULN = os.environ.get("LAB_VULN", "0") == "1"
WWW_DIR = os.environ.get("LAB_WWW", os.path.join(HERE, "..", "config", "www"))

FAIL_LIMIT, FAIL_WINDOW, LOCK_SECONDS = 5, 300, 300
MAX_BODY = 4096
_SALT = b"labshop-demo-salt"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,64}$")
STARTED = time.time()

# Trạng thái phiên trong bộ nhớ (sid -> email đã đăng nhập) + chống dò mật khẩu
SESS_USER: dict[str, str] = {}
FAILS: dict[str, list[float]] = {}
LOCKED: dict[str, float] = {}


def db():
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def pw_hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), _SALT, 120_000).hex()


def auth_event(ip, kind, email):
    rec = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
           "src_ip": ip, "kind": kind, "email": re.sub(r"[^\x20-\x7e]", "?", str(email))[:80]}
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(AUTH_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


app = FastAPI(title="Lab Shop API", version="2.0", docs_url="/api/docs", openapi_url="/api/openapi.json")


# ---------- tiện ích phiên / IP / cookie ----------
def client_ip(req: Request) -> str:
    return req.headers.get("X-Real-IP") or (req.client.host if req.client else "0.0.0.0")


def get_sid(req: Request):
    sid = req.cookies.get("sid")
    if sid and sid.isalnum() and len(sid) <= 64:
        return sid, False
    return secrets.token_hex(16), True


def reply(data, code=200, sid=None, new=False):
    r = JSONResponse(data, status_code=code)
    r.headers["Cache-Control"] = "no-store"
    if sid and new:
        r.set_cookie("sid", sid, path="/", httponly=True, samesite="lax")
    return r


async def read_json(req: Request):
    body = await req.body()
    if not body or len(body) > MAX_BODY:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def cart_view(con, sid):
    rows = con.execute(
        "SELECT p.*, c.qty FROM cart_items c JOIN products p ON p.id=c.pid WHERE c.sid=?",
        (sid,)).fetchall()
    items = [{**dict(r), "line": r["price"] * r["qty"]} for r in rows]
    return {"items": items, "count": sum(r["qty"] for r in rows), "total": sum(x["line"] for x in items)}


# ---------- log mỗi request (giữ định dạng cũ cho journald) ----------
@app.middleware("http")
async def access_log(req: Request, call_next):
    resp = await call_next(req)
    print(f"{client_ip(req)} {req.method} {req.url.path[:120]} {resp.status_code}", flush=True)
    return resp


# ---------- GET ----------
@app.get("/api/health")
async def health(req: Request):
    sid, new = get_sid(req)
    return reply({"status": "ok", "server": os.environ.get("LAB_SERVER", "B 10.77.0.20"),
                  "uptime_s": int(time.time() - STARTED), "time": time.strftime("%H:%M:%S"),
                  "vuln_mode": VULN}, sid=sid, new=new)


@app.get("/api/products")
async def products(req: Request):
    sid, new = get_sid(req)
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM products ORDER BY id").fetchall()]
    return reply({"products": rows}, sid=sid, new=new)


@app.get("/api/search")
async def search(req: Request, q: str = ""):
    """Tìm sản phẩm theo tên. LAB_VULN=1: dùng chuỗi nối -> SQLi (UNION) được."""
    sid, new = get_sid(req)
    q = q[:100]
    with db() as con:
        try:
            if VULN:
                sql = f"SELECT id,name,price FROM products WHERE name LIKE '%{q}%'"  # cố ý: SQLi
                rows = [dict(r) for r in con.execute(sql).fetchall()]
            else:
                rows = [dict(r) for r in con.execute(
                    "SELECT id,name,price FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()]
        except sqlite3.Error as e:
            return reply({"error": "truy vấn lỗi", "detail": str(e)[:200]}, code=400, sid=sid, new=new)
    return reply({"query": q, "results": rows}, sid=sid, new=new)


@app.get("/api/cart")
async def cart_get(req: Request):
    sid, new = get_sid(req)
    with db() as con:
        return reply(cart_view(con, sid), sid=sid, new=new)


@app.get("/api/me")
async def me(req: Request):
    sid, new = get_sid(req)
    email = SESS_USER.get(sid)
    name = None
    if email:
        with db() as con:
            r = con.execute("SELECT name FROM users WHERE email=?", (email,)).fetchone()
            name = r["name"] if r else None
    return reply({"logged_in": bool(email), "email": email, "name": name}, sid=sid, new=new)


# ---------- POST ----------
@app.post("/api/cart")
async def cart_add(req: Request):
    sid, new = get_sid(req)
    data = await read_json(req)
    pid = data.get("id") if isinstance(data, dict) else None
    if not isinstance(pid, int):
        return reply({"error": "sản phẩm không hợp lệ"}, code=400, sid=sid, new=new)
    with db() as con:
        if not con.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
            return reply({"error": "sản phẩm không hợp lệ"}, code=400, sid=sid, new=new)
        con.execute(
            "INSERT INTO cart_items(sid,pid,qty) VALUES(?,?,1) "
            "ON CONFLICT(sid,pid) DO UPDATE SET qty=min(qty+1,99)", (sid, pid))
        con.commit()
        view = cart_view(con, sid)
        name = con.execute("SELECT name FROM products WHERE id=?", (pid,)).fetchone()["name"]
    return reply({"added": name, **view}, sid=sid, new=new)


@app.post("/api/logout")
async def logout(req: Request):
    sid, new = get_sid(req)
    SESS_USER.pop(sid, None)
    return reply({"ok": True}, sid=sid, new=new)


@app.post("/api/order")
async def order(req: Request):
    sid, new = get_sid(req)
    if sid not in SESS_USER:  # kiểm tra ở MÁY CHỦ, không chỉ ẩn nút trên giao diện
        return reply({"error": "cần đăng nhập trước khi thanh toán", "login_required": True},
                     code=401, sid=sid, new=new)
    with db() as con:
        view = cart_view(con, sid)
        if not view["items"]:
            return reply({"error": "giỏ hàng trống"}, code=400, sid=sid, new=new)
        code = f"LS{int(time.time()) % 1000000:06d}"
        cur = con.execute(
            "INSERT INTO orders(order_code,email,total,count,created_at) VALUES(?,?,?,?,?)",
            (code, SESS_USER[sid], view["total"], view["count"],
             datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")))
        oid = cur.lastrowid
        con.executemany("INSERT INTO order_items(order_id,pid,qty,price) VALUES(?,?,?,?)",
                        [(oid, it["id"], it["qty"], it["price"]) for it in view["items"]])
        con.execute("DELETE FROM cart_items WHERE sid=?", (sid,))
        con.commit()
    return reply({"order_id": code, "total": view["total"], "count": view["count"],
                  "time": time.strftime("%H:%M:%S"), "customer": SESS_USER[sid]}, code=201, sid=sid, new=new)


@app.post("/api/login")
async def login(req: Request):
    sid, new = get_sid(req)
    ip, now = client_ip(req), time.time()
    data = await read_json(req)
    email = data.get("email", "") if isinstance(data, dict) else ""
    pw = data.get("password", "") if isinstance(data, dict) else ""

    # Chế độ AN TOÀN mới kiểm tra định dạng; chế độ VULN để lọt payload SQLi vào truy vấn.
    if not VULN and (not isinstance(email, str) or not isinstance(pw, str)
                     or not EMAIL_RE.match(email) or not 0 < len(pw) <= 128):
        auth_event(ip, "login_invalid_input", email)
        return reply({"error": "dữ liệu đăng nhập không hợp lệ"}, code=400, sid=sid, new=new)
    if not isinstance(email, str) or not isinstance(pw, str):
        return reply({"error": "dữ liệu đăng nhập không hợp lệ"}, code=400, sid=sid, new=new)

    if LOCKED.get(ip, 0) > now:
        auth_event(ip, "login_locked", email)
        return reply({"error": "tạm khóa do đăng nhập sai nhiều lần",
                      "retry_after_s": int(LOCKED[ip] - now)}, code=429, sid=sid, new=new)

    ok = False
    row = None
    with db() as con:
        try:
            if VULN:
                # CỐ Ý dễ tấn công: nối chuỗi -> ' OR 1=1 -- bỏ qua xác thực
                sql = (f"SELECT email,name,pw_hash FROM users "
                       f"WHERE email='{email}' AND pw_hash='{pw_hash(pw)}'")
                row = con.execute(sql).fetchone()
                ok = row is not None
            else:
                row = con.execute("SELECT email,name,pw_hash FROM users WHERE email=?",
                                  (email.lower(),)).fetchone()
                ok = bool(row) and hmac.compare_digest(row["pw_hash"], pw_hash(pw))
        except sqlite3.Error:
            ok, row = False, None

    if ok and row:
        FAILS.pop(ip, None)
        SESS_USER[sid] = row["email"]
        auth_event(ip, "login_ok", email)
        return reply({"ok": True, "name": row["name"]}, sid=sid, new=new)

    f = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW] + [now]
    FAILS[ip] = f
    if len(f) >= FAIL_LIMIT:
        LOCKED[ip] = now + LOCK_SECONDS
    auth_event(ip, "login_fail", email)
    return reply({"error": "sai email hoặc mật khẩu"}, code=401, sid=sid, new=new)


# ---------- Giao diện tĩnh (shop) — phục vụ ../config/www khi chạy local ----------
if os.path.isdir(WWW_DIR):
    app.mount("/", StaticFiles(directory=WWW_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("LAB_PORT", "8081"))
    print(f"Lab Shop API (FastAPI) nghe trên {host}:{port} | DB={DB_PATH} | VULN={VULN}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")
