#!/usr/bin/env python3
"""
Lab Honeypot - thanh phan danh lua cua bai lab (chi thu vien chuan). Khong chua chuc nang that nao.

1) HTTP 127.0.0.1:8082 (Nginx chuyen vao):
   /admin, /admin/*        trang quan tri GIA: dang nhap, "bang dieu khien" gia
   /api/admin/*            API quan tri GIA, doi header X-Api-Key
   /backup/*               file sao luu GIA (honeytoken file)
2) Cong bay TCP tren 10.77.0.20: 23 (telnet), 2222 (ssh), 3306 (mysql): gui banner, doc toi da 512 byte, dong.

Moi tuong tac ghi 1 dong JSON vao /var/log/lab-honeypot/events.jsonl:
  {"ts", "src_ip", "kind", "detail", ...}
kind: honeypot_admin_view | honeypot_admin_login | honeytoken_creds | honeytoken_api_key | honeytoken_file | honeyport_connect
"""
import html
import json
import os
import re
import socket
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.environ.get("LOGS_DIRECTORY", "/var/log/lab-honeypot")
EVENTS = os.path.join(LOG_DIR, "events.jsonl")
LAB_IP = "10.77.0.20"
# Honeytoken: chi xuat hien trong comment HTML / file JS / robots.txt. Nguoi dung that khong bao gio dung.
TOKEN_USER, TOKEN_PASS = "admin", "LabShop@2026!"
TOKEN_API_KEY = "ls_live_7f3a9c2e51b84d06a1e9"
HONEYPORTS = {23: b"\r\nUbuntu 24.04 LTS\r\nlabshop-db login: ", 2222: b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
              3306: b"J\x00\x00\x00\n8.0.36-0ubuntu0.24.04.1\x00"}
CTRL = re.compile(r"[^\x20-\x7e]")
LOCK = threading.Lock()


def clean(s, n=80):
    s = CTRL.sub("?", str(s if s is not None else ""))
    return s[:n]


def log_event(src_ip, kind, **detail):
    rec = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
           "src_ip": src_ip, "kind": kind, **{k: clean(v) for k, v in detail.items()}}
    line = json.dumps(rec, ensure_ascii=False)
    with LOCK, open(EVENTS, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


PAGE = """<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0}}
.box{{max-width:{w}px;margin:60px auto;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px}}
h1{{margin:0 0 6px;font-size:22px}} .m{{color:#94a3b8;font-size:14px}} input{{width:100%;padding:10px;margin:6px 0 14px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0}}
button{{width:100%;padding:11px;border:0;border-radius:8px;background:#6366f1;color:#fff;font-weight:700}} .err{{background:#7f1d1d;padding:10px;border-radius:8px;margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;font-size:14px}} td,th{{padding:8px;border-bottom:1px solid #334155;text-align:left}}</style></head><body><div class="box">{body}</div></body></html>"""


def login_page(err=""):
    e = f'<div class="err">{html.escape(err)}</div>' if err else ""
    return PAGE.format(title="Lab Shop — Quản trị", w=380, body=f"""<h1>⚡ Lab Shop Admin</h1><p class="m">Khu vực quản trị nội bộ</p>{e}
<form method="post" action="/admin/login"><label>Tài khoản</label><input name="user" autocomplete="off">
<label>Mật khẩu</label><input name="pass" type="password"><button>Đăng nhập</button></form>""")


def dashboard_page():
    rows = "".join(f"<tr><td>#LS{1040 + i}</td><td>khach{i}@labshop.vn</td><td>{(i * 371) % 2000 + 200}.000 ₫</td><td>Đang xử lý</td></tr>" for i in range(1, 9))
    return PAGE.format(title="Lab Shop Admin — Bảng điều khiển", w=820, body=f"""<h1>Bảng điều khiển</h1>
<p class="m">Xin chào, admin · Phiên làm việc nội bộ</p><h3>Đơn hàng gần đây</h3><table><tr><th>Mã</th><th>Khách</th><th>Giá trị</th><th>Trạng thái</th></tr>{rows}</table>
<p class="m">Xuất dữ liệu: <a style="color:#a5b4fc" href="/admin/export?table=customers">customers.csv</a> · <a style="color:#a5b4fc" href="/admin/export?table=orders">orders.csv</a></p>""")


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urllib.parse.urlsplit(self.path)
        ua = self.headers.get("User-Agent", "")
        if p.path.startswith("/backup/"):
            log_event(self.ip(), "honeytoken_file", path=p.path, ua=ua)
            return self.send(200, b"\x1f\x8b\x08\x00" + os.urandom(2048), "application/gzip")
        if p.path.startswith("/api/admin"):
            return self.api_admin(p.path)
        if p.path.startswith("/admin/export"):
            sess = "sid=hp" in (self.headers.get("Cookie") or "")
            log_event(self.ip(), "honeytoken_creds" if sess else "honeypot_admin_view", path=self.path, note="export")
            return self.send(302, "", extra={"Location": "/admin"})
        if p.path.startswith("/admin"):
            sess = "sid=hp" in (self.headers.get("Cookie") or "")
            log_event(self.ip(), "honeypot_admin_view", path=self.path, ua=ua)
            return self.send(200, dashboard_page() if sess else login_page())
        self.send(404, "Not Found", "text/plain")

    def do_POST(self):
        p = urllib.parse.urlsplit(self.path)
        n = min(int(self.headers.get("Content-Length") or 0), 2048)
        body = self.rfile.read(n).decode("utf-8", "replace") if n > 0 else ""
        if p.path.startswith("/api/admin"):
            return self.api_admin(p.path)
        if p.path == "/admin/login":
            f = urllib.parse.parse_qs(body)
            user, pw = (f.get("user") or [""])[0], (f.get("pass") or [""])[0]
            if user == TOKEN_USER and pw == TOKEN_PASS:
                log_event(self.ip(), "honeytoken_creds", user=user, note="dang nhap bang tai khoan bay")
                return self.send(302, "", extra={"Location": "/admin", "Set-Cookie": "sid=hp; Path=/admin; HttpOnly"})
            log_event(self.ip(), "honeypot_admin_login", user=user, password=pw)
            return self.send(200, login_page("Sai tài khoản hoặc mật khẩu."))
        self.send(404, "Not Found", "text/plain")

    def api_admin(self, path):
        key = self.headers.get("X-Api-Key", "")
        if key == TOKEN_API_KEY:
            log_event(self.ip(), "honeytoken_api_key", path=path)
            return self.send(200, json.dumps({"status": "ok", "items": []}), "application/json")
        log_event(self.ip(), "honeypot_admin_view", path=path, note="api khong co key")
        self.send(401, json.dumps({"error": "unauthorized"}), "application/json")

    def log_message(self, *a):
        pass


def honeyport(port, banner):
    """Cong bay. KHONG duoc chet am tham: luc may khoi dong nhanh (vd tu khoi dong lai sau kernel panic),
    card lab co the chua co IP 10.77.0.20 -> bind loi. Truoc day luong nay chet ngay ma dich vu van 'active'
    (phan web 8082 van chay) -> mat lop phat hien quet. Nay: IP_FREEBIND (bind duoc truoc khi IP xuat hien)
    + thu lai moi 3 giay neu van loi."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_FREEBIND", 15), 1)
            s.bind((LAB_IP, port))
            s.listen(16)
            print(f"LabHoneypot: cong bay {LAB_IP}:{port} san sang", flush=True)
            break
        except OSError as e:
            print(f"LabHoneypot: chua mo duoc cong bay {port} ({e}) -> thu lai sau 3 s", flush=True)
            time.sleep(3)
    while True:
        try:
            conn, (ip, _) = s.accept()
        except OSError:
            time.sleep(0.5)
            continue
        threading.Thread(target=serve_port, args=(conn, ip, port, banner), daemon=True).start()


def serve_port(conn, ip, port, banner):
    data = b""
    try:
        conn.settimeout(6)
        conn.sendall(banner)
        data = conn.recv(512)
    except OSError:
        pass
    finally:
        conn.close()
    log_event(ip, "honeyport_connect", port=port, data=data.decode("latin-1"))


if __name__ == "__main__":
    os.makedirs(LOG_DIR, exist_ok=True)
    for port, banner in HONEYPORTS.items():
        threading.Thread(target=honeyport, args=(port, banner), daemon=True).start()
    print("LabHoneypot: http 127.0.0.1:8082, ports", list(HONEYPORTS), flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8082), Handler).serve_forever()
