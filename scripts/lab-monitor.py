#!/usr/bin/env python3
"""
Man hinh giam sat B - DE DOC: moi su kien la 1-3 dong tieng Viet, noi ro AI lam GI va NGHIA LA GI.
Chay: ~/lab/monitor.sh  [--tat-ca]  [--health]      (Ctrl+C de thoat)
  --tat-ca  hien ca file tinh (.css .js .svg ...)   --health  hien ca /api/health (3 giay/lan)

Nguon (doc tu CUOI file, theo thoi gian thuc):
  Nginx (web that + ban GIA), Suricata eve.json, honeypot, dang nhap Lab Shop, analyzer, quyet dinh cua
  nguoi van hanh, lab-rulegen (rule tu sinh), trang thai firewall (sudo lab-block status, 2 giay/lan).
Bang diem lay truc tiep tu analyzer.py dang chay -> luon khop voi logic that.
"""
import importlib.util
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime

ARGS = set(sys.argv[1:])
SHOW_ALL = "--tat-ca" in ARGS or "--all" in ARGS
SHOW_HEALTH = "--health" in ARGS

FILES = {
    "web": "/var/log/nginx/access.log",
    "webfake": "/var/log/nginx/honeypot-access.log",
    "eve": "/var/log/suricata/eve.json",
    "hp": "/var/log/lab-honeypot/events.jsonl",
    "auth": "/var/log/lab-shop/auth.jsonl",
    "inc": "/var/lib/lab-analyzer/incidents.jsonl",
    "dec": "/var/lib/lab-analyzer/decisions.jsonl",
    "rule": "/var/lib/lab-rulegen/proposals.json",
}

# ---------- mau ----------
TTY = sys.stdout.isatty()
def c(code):
    return f"\033[{code}m" if TTY else ""
R, BOLD, DIM = c("0"), c("1"), c("2")
GRN, YEL, RED, MAG, CYN, BLU, GRY = c("1;32"), c("1;33"), c("1;31"), c("1;35"), c("1;36"), c("1;34"), c("37")
BG_RED, BG_GRN, BG_MAG, BG_YEL = c("1;97;41"), c("1;30;42"), c("1;97;45"), c("1;30;43")

# ---------- ten thiet bi ----------
NAMES = {"10.77.0.10": "A·Kali", "10.77.0.30": "C·Win10", "10.77.0.20": "B·máy chủ"}
def who(ip):
    n = NAMES.get(ip)
    return f"{BOLD}{ip}{R} ({n})" if n else f"{BOLD}{ip}{R} (máy lạ)"

# ---------- bang diem tu analyzer dang chay ----------
def load_analyzer():
    try:
        spec = importlib.util.spec_from_file_location("an", "/usr/local/lib/lab/analyzer.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.SIGNALS, m.INCIDENT_SCORE, m.BLOCK_SCORE
    except Exception:  # noqa: BLE001
        return {}, 50, 100
SIGNALS, INC_SCORE, BLOCK_SCORE = load_analyzer()

def pts(sid):
    try:
        s, unspoof, _, _ = SIGNALS[sid]
        return s, unspoof
    except Exception:  # noqa: BLE001
        return None, None

# ---------- y nghia rule ----------
RULE_VI = {
    1000001: "Quét cổng nhanh: mở ≥ 10 kết nối trong 10 giây",
    1000003: "Máy chủ phải từ chối ≥ 10 cổng đóng trong 10 giây → có người dò cổng",
    1000005: "Dò cổng CHẬM: ≥ 10 cổng đóng bị thử trong 60 giây",
    1000002: "Truy cập trang quản trị nhạy cảm (/admin)",
    1000007: "Trang nhạy cảm KHÔNG trả 403 → nguy hiểm",
    1000006: "Path traversal: cố đọc file ngoài thư mục web (../)",
    1000008: "Path traversal dạng mã hóa (%2e%2e)",
    1000013: "SQL injection trong đường dẫn",
    1000015: "SQL injection trong dữ liệu gửi lên",
    1000014: "XSS (chèn mã JavaScript) trong đường dẫn",
    1000016: "XSS trong dữ liệu gửi lên",
    1000017: "Đăng nhập sai ≥ 5 lần trong 60 giây → dò mật khẩu",
}
SUSPECT_IS_DEST = {1000003, 1000005, 1000007, 1000017}   # nghi pham la may NHAN goi tra loi tu B

PORT_SVC = {23: "telnet", 2222: "SSH", 3306: "MySQL"}
def hp_text(e):
    k = e.get("kind")
    if k == "honeyport_connect":
        p = e.get("port")
        try:
            svc = PORT_SVC.get(int(p), "?")
        except (TypeError, ValueError):
            svc = "?"
        return f"Kết nối vào CỔNG BẪY {p} ({svc}) — dịch vụ giả, người dùng thật không bao giờ chạm"
    if k == "honeypot_admin_view":
        return "Mở trang quản trị GIẢ (đang ở trong bẫy)"
    if k == "honeypot_admin_login":
        return f"Thử đăng nhập trang quản trị GIẢ: user={e.get('user', '?')} pass={e.get('password', '?')}"
    if k == "honeytoken_creds":
        return f"Đăng nhập bằng TÀI KHOẢN BẪY '{e.get('user', '')}' — mật khẩu chỉ có trong comment mã nguồn trang → chắc chắn là kẻ tấn công"
    if k == "honeytoken_api_key":
        return "Dùng API KEY BẪY (chỉ có trong comment của shop.js)"
    if k == "honeytoken_file":
        return f"Tải FILE SAO LƯU GIẢ {e.get('path', '')}"
    return k or "?"
HP_SID = {"honeyport_connect": 2000001, "honeypot_admin_view": 2000002, "honeypot_admin_login": 2000003,
          "honeytoken_creds": 2000004, "honeytoken_api_key": 2000005, "honeytoken_file": 2000006}
HP_NAME_VI = {2000001: "Chạm cổng bẫy", 2000002: "Mở trang quản trị GIẢ", 2000003: "Thử đăng nhập trang quản trị GIẢ",
              2000004: "Dùng tài khoản BẪY", 2000005: "Dùng API key BẪY", 2000006: "Tải file sao lưu GIẢ"}
DECEIVED = set()     # IP dang bi danh lua (watch_fw cap nhat) - de giai thich canh bao cua trang gia

AUTH_VI = {"login_ok": (GRN, "Đăng nhập Lab Shop THÀNH CÔNG"), "login_fail": (YEL, "Đăng nhập SAI mật khẩu"),
           "login_locked": (RED, "Bị KHÓA đăng nhập 5 phút (sai quá nhiều lần)"),
           "login_invalid_input": (YEL, "Gửi dữ liệu đăng nhập bất thường")}

HTTP_VI = {200: "OK", 201: "đã tạo", 204: "OK", 301: "chuyển trang", 302: "chuyển trang", 304: "dùng bản đã lưu",
           400: "dữ liệu sai", 401: "chưa/ sai đăng nhập", 403: "BỊ CẤM", 404: "không có", 405: "sai phương thức",
           429: "QUÁ NHIỀU LẦN – bị giới hạn", 500: "lỗi máy chủ", 502: "lỗi máy chủ", 503: "quá tải"}

DEC_VI = {
    "log": (GRY, None, "chỉ ghi nhận (dưới {inc} điểm)"),
    "incident_medium": (YEL, "SỰ CỐ", "đủ {inc} điểm nhưng chưa tới {blk} → báo người vận hành, chưa phản ứng"),
    "incident_high_spoof_suspect": (BG_GRN, "KHÔNG CHẶN", "đủ điểm nhưng TOÀN bằng chứng có thể bị giả IP (chưa có kết nối TCP thật nào) → không phản ứng để tránh vu oan"),
    "incident_high_protected": (BG_GRN, "KHÔNG CHẶN", "IP thuộc danh sách hạ tầng được bảo vệ → chỉ báo người vận hành"),
    "recommend_only_out_of_scope": (YEL, "CHỈ ĐỀ XUẤT", "IP nằm ngoài phạm vi được phép phản ứng"),
    "recommend_block_l1": (BG_YEL, "ĐỀ XUẤT CHẶN", "đủ điều kiện chặn web 60 giây nhưng đang ở chế độ CHỈ ĐỀ XUẤT"),
    "block_l1": (BG_RED, "CHẶN WEB 60 GIÂY", "đủ {blk} điểm + có bằng chứng thật → tự động chặn cổng 80 của IP này"),
    "already_blocked": (GRY, "ĐANG BỊ CHẶN", "không gia hạn thêm"),
    "recommend_deceive": (BG_YEL, "ĐỀ XUẤT ĐÁNH LỪA", "đủ điều kiện nhưng đang ở chế độ CHỈ ĐỀ XUẤT"),
    "deceive": (BG_MAG, "ĐÁNH LỪA 10 PHÚT", "đủ {blk} điểm + có bằng chứng thật → âm thầm chuyển IP này sang web GIẢ (honeypot)"),
    "attacker_engaged": (BG_RED, "CẮN CÂU – CHỜ DUYỆT", "đang bị đánh lừa mà vẫn tiếp tục tấn công → chờ người vận hành duyệt CHẶN TOÀN BỘ trên dashboard"),
}

OP_VI = {"approve_l2": "DUYỆT chặn toàn bộ 10 phút", "block_l2": "chặn toàn bộ 10 phút", "block_l1": "chặn web 60 giây",
         "deceive": "đưa vào honeypot", "unblock_all": "GỠ mọi phản ứng", "dismiss": "bỏ qua yêu cầu",
         "rule_approve": "DUYỆT & NẠP rule tự sinh", "rule_reject": "TỪ CHỐI rule tự sinh",
         "rule_revoke": "THU HỒI rule tự sinh", "rulegen_run": "yêu cầu phân tích rule tự sinh",
         "reset_lab": "ĐẶT LẠI hệ thống (reset-lab.sh)"}

LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[[^:]+:(\d\d:\d\d:\d\d)[^\]]*\] "(\S+) (\S+)[^"]*" (\d{3}) ')
STATIC = re.compile(r"\.(css|js|svg|png|jpg|ico|woff2?)(\?|$)", re.I)

# ---------- in ra ----------
OUT = queue.Queue()
def width():
    return max(80, min(shutil.get_terminal_size((120, 30)).columns, 160))

def emit(t, icon, label, color, body, extra=None):
    """Dong chinh: gio | nhan | noi dung. extra: cac dong giai thich thut le."""
    line = f"{DIM}{t}{R}  {color}{icon} {label:<9}{R} {body}"
    OUT.put("\n".join([line] + [f"{' ' * 23}{GRY}{x}{R}" for x in (extra or [])]))

def hhmmss(ts):
    return str(ts or "")[11:19] or datetime.now().strftime("%H:%M:%S")

# ---------- doc theo thoi gian thuc ----------
def follow(path, handler, from_end=True):
    """Nhu tail -F: doc dong moi, chiu duoc file chua ton tai / bi xoay vong; dong ghi do dang de lai cho lan sau."""
    f, ino, buf = None, None, b""
    while True:
        try:
            st = os.stat(path)
            if f is None or st.st_ino != ino or st.st_size < f.tell():
                if f:
                    f.close()
                f = open(path, "rb")
                ino, buf = st.st_ino, b""
                if from_end:
                    f.seek(0, 2)
                from_end = False        # file moi sau khi xoay vong: doc tu dau
            chunk = f.read(65536)
            if chunk:
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for ln in lines:
                    try:
                        handler(ln.decode("utf-8", "replace"))
                    except Exception:  # noqa: BLE001 - mot dong hong khong lam dung man hinh
                        pass
                continue
        except OSError:
            pass
        time.sleep(0.3)

# ---------- xu ly tung nguon ----------
def on_web(fake):
    def h(line):
        m = LOG_RE.match(line)
        if not m:
            return
        ip, t, meth, url, code = m.groups()
        code = int(code)
        if url.startswith("/api/health") and not SHOW_HEALTH:
            return
        if STATIC.search(url) and not SHOW_ALL and code < 400:
            return
        col = GRN if code < 400 else (RED if code in (403, 429) or code >= 500 else YEL)
        tag = f" {MAG}[web GIẢ – đang bị đánh lừa]{R}" if fake else ""
        emit(t, "🌐", "WEB", BLU, f"{who(ip)}  {meth} {url[:70]}  → {col}{code} {HTTP_VI.get(code, '')}{R}{tag}")
    return h

def on_eve(line):
    if '"event_type":"alert"' not in line:
        return
    e = json.loads(line)
    a = e.get("alert") or {}
    sid = a.get("signature_id", 0)
    if sid >= 9000000:
        return
    src, dst = e.get("src_ip"), e.get("dest_ip")
    suspect = dst if (sid in SUSPECT_IS_DEST and src == "10.77.0.20") else src
    if 5000000 <= sid <= 5999999:
        what = f"Rule TỰ SINH bắt được: {a.get('signature', '').replace('LAB AUTO ', '')}"
    else:
        what = RULE_VI.get(sid, a.get("signature", ""))
    url = (e.get("http") or {}).get("url")
    p, unspoof = pts(sid)
    if sid == 1000007 and suspect in DECEIVED:
        meta = [f"Suricata rule {sid}" + (f" · đường dẫn: {url[:60]}" if url else "")
                + " · KHÔNG tính điểm: IP này đang bị đánh lừa, trang GIẢ cố ý trả 200 để dụ"]
        emit(hhmmss(e.get("timestamp")), "⚠️", "CẢNH BÁO", GRY, f"{who(suspect)}  Trang quản trị (bản GIẢ) trả 200", meta)
        return
    meta = [f"Suricata rule {sid}" + (f" · đường dẫn: {url[:60]}" if url else "")
            + (f" · +{p} điểm · {'bằng chứng THẬT (cần kết nối TCP thật)' if unspoof else 'có thể bị giả IP'}" if p is not None else "")]
    emit(hhmmss(e.get("timestamp")), "⚠️", "CẢNH BÁO", YEL, f"{who(suspect)}  {what}", meta)

def on_hp(line):
    e = json.loads(line)
    p, _ = pts(HP_SID.get(e.get("kind"), 0))
    emit(hhmmss(e.get("ts")), "🍯", "HONEYPOT", MAG, f"{who(e.get('src_ip'))}  {hp_text(e)}",
         [f"bẫy · +{p} điểm · bằng chứng THẬT"] if p else None)

def on_auth(line):
    e = json.loads(line)
    col, txt = AUTH_VI.get(e.get("kind"), (YEL, e.get("kind")))
    emit(hhmmss(e.get("ts")), "🔑", "ĐĂNG NHẬP", col, f"{who(e.get('src_ip'))}  {col}{txt}{R}  ({e.get('email', '')})")

def on_inc(line):
    i = json.loads(line)
    dec = i.get("decision")
    col, title, why = DEC_VI.get(dec, (YEL, dec, i.get("reason", "")))
    if dec == "log":
        return
    why = why.format(inc=INC_SCORE, blk=BLOCK_SCORE)
    score = i.get("score", 0)
    bar_n = min(20, int(score / BLOCK_SCORE * 10)) if BLOCK_SCORE else 0
    bar = ("█" * bar_n).ljust(20, "░")
    sig_txt = []
    for s in i.get("signals") or []:
        sid = s.get("sid")
        p, unspoof = pts(sid)
        if 2000000 <= sid < 3000000:
            name = HP_NAME_VI.get(sid, "honeypot")
        elif 3000000 <= sid < 4000000:
            name = {3000001: "đăng nhập sai ≥ 5 lần", 3000002: "bị khóa đăng nhập"}.get(sid, "đăng nhập")
        elif 5000000 <= sid <= 5999999:
            name = f"rule tự sinh {sid}"
        else:
            name = RULE_VI.get(sid, str(sid))
        mark = f"{GRN}✓ thật{R}{GRY}" if unspoof else f"{YEL}? có thể bị giả IP{R}{GRY}"
        sig_txt.append(f"  • {name}: +{p if p is not None else '?'} điểm ({mark})")
    extra = ["Bằng chứng trong 120 giây gần nhất:"] + sig_txt + [f"{col} → {title} {R} {why}"]
    act = i.get("action")
    if act:
        ok = act.get("status") == "ok"
        extra.append(f"Đã thực hiện: {act.get('cmd')} → {'thành công' if ok else 'THẤT BẠI: ' + str((act.get('result') or {}).get('msg'))}")
    att = ", ".join(f"{a['id']} {a['name']}" for a in i.get("attack") or [])
    if att:
        extra.append(f"MITRE ATT&CK: {att}")
    emit(hhmmss(i.get("created_at")), "🧠", "PHÂN TÍCH", CYN,
         f"{who(i.get('suspect_ip'))}  {BOLD}{score}{R}/{BLOCK_SCORE} điểm [{bar}]", extra)

SET_VI = {"blocked_l1": "danh sách chặn web", "blocked_l2": "danh sách chặn toàn bộ", "deceive_v4": "danh sách đánh lừa"}
def vi_result(msg):
    """Dich ket qua tho cua lab-block / lab-rule sang tieng Viet."""
    out = []
    for part in (msg or "").split("; "):
        m = re.match(r"applied \(present in (\w+)\)", part)
        if m:
            out.append(f"đã thêm vào {SET_VI.get(m.group(1), m.group(1))}")
            continue
        m = re.match(r"removed from (\w+)", part)
        if m:
            out.append(f"đã gỡ khỏi {SET_VI.get(m.group(1), m.group(1))}")
            continue
        if "not in ALLOWED" in part:
            out.append("BỊ TỪ CHỐI: IP không thuộc diện được phản ứng")
            continue
        out.append(part)
    return "; ".join(x for x in out if x)

def on_dec(line):
    d = json.loads(line)
    a = d.get("action")
    target = ("cho mọi thiết bị" if d.get("ip") == "*" else d.get("ip")) or (f"rule {d.get('rule')}" if d.get("rule") else "")
    ok = d.get("ok")
    emit(hhmmss(d.get("at")), "👤", "VẬN HÀNH", GRN if ok else RED,
         f"Người vận hành: {BOLD}{OP_VI.get(a, a)}{R} {target}", [f"Kết quả: {vi_result(d.get('result', ''))}"])

# rulegen: proposals.json la file JSON (khong phai jsonl) -> theo doi thay doi
def watch_rules():
    seen = None
    while True:
        try:
            with open(FILES["rule"], encoding="utf-8") as f:
                props = json.load(f)
            cur = {p["id"]: p["status"] for p in props}
            if seen is not None:
                for p in props:
                    if p["id"] not in seen and p["status"] == "pending":
                        emit(datetime.now().strftime("%H:%M:%S"), "🧬", "RULE MỚI", MAG,
                             f"lab-rulegen đề xuất rule chặn {BOLD}{p['content']}{R} (học từ {p['support']} request của kẻ tấn công)",
                             [f"Qua đủ 5 cửa kiểm chứng · ví dụ: {', '.join(p.get('samples', [])[:3])} · chờ duyệt trên dashboard"])
            seen = cur
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)

# firewall: so sanh trang thai lab-block status
LV = {"blocked_l1": (BG_RED, "BỊ CHẶN WEB", "không vào được trang web (cổng 80)"),
      "blocked_l2": (BG_RED, "BỊ CHẶN TOÀN BỘ", "mọi kết nối TCP tới B đều bị bỏ"),
      "deceive": (BG_MAG, "BỊ ĐÁNH LỪA", "vào web sẽ thấy bản GIẢ, không hề biết")}
def fw_state():
    try:
        out = subprocess.run(["sudo", "-n", "/usr/local/sbin/lab-block", "status"], capture_output=True, text=True, timeout=5).stdout
        d = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return None, {}
    st = {}
    for key in LV:
        for ip, exp in re.findall(r"(\d+\.\d+\.\d+\.\d+) expires ([0-9hms]+)", d.get(key) or ""):
            st[(ip, key)] = exp
    return st, d

def vi_dur(s):
    m = re.match(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", s or "")
    h, mi, se = (int(x) if x else 0 for x in m.groups()) if m else (0, 0, 0)
    return (f"{h} giờ " if h else "") + (f"{mi} phút " if mi else "") + f"{se} giây"

def watch_fw():
    prev, prev_d = fw_state()
    last_drop_report = 0
    while True:
        time.sleep(2)
        cur, d = fw_state()
        if cur is None:
            continue
        DECEIVED.clear()
        DECEIVED.update(ip for ip, lv in cur if lv == "deceive")
        now = datetime.now().strftime("%H:%M:%S")
        for k in cur.keys() - prev.keys():
            col, title, mean = LV[k[1]]
            emit(now, "🛡", "TƯỜNG LỬA", RED, f"{who(k[0])}  {col} {title} {R} còn {vi_dur(cur[k])} — {mean}")
        for k in prev.keys() - cur.keys():
            still = [LV[lv][1].lower() for (ip, lv) in cur if ip == k[0]]
            if still:        # vd danh lua -> chan toan bo: khong phai "duoc tha"
                emit(now, "🛡", "TƯỜNG LỬA", RED, f"{who(k[0])}  chuyển từ {LV[k[1]][1].lower()} sang {', '.join(still)}")
            else:
                emit(now, "🛡", "TƯỜNG LỬA", GRN, f"{who(k[0])}  {GRN}hết {LV[k[1]][1].lower()}{R} — truy cập lại bình thường")
        drops = sum(int(d.get(x) or 0) for x in ("drop_packets", "drop_l2_packets"))
        pdrops = sum(int(prev_d.get(x) or 0) for x in ("drop_packets", "drop_l2_packets"))
        if drops > pdrops and time.time() - last_drop_report > 6:
            blocked = sorted({ip for ip, lv in cur if lv != "deceive"})
            emit(now, "🛡", "TƯỜNG LỬA", RED, f"đã bỏ thêm {drops - pdrops} gói tin của {', '.join(blocked) or 'IP bị chặn'} (họ đang thử kết nối lại)")
            last_drop_report = time.time()
        prev, prev_d = cur, d

# ---------- che do analyzer ----------
def mode_text():
    mode = {}
    try:
        for ln in open("/etc/default/lab-analyzer", encoding="utf-8"):
            k, _, v = ln.strip().partition("=")
            mode[k] = v
    except OSError:
        pass
    m = "TỰ ĐỘNG phản ứng" if mode.get("MODE") == "apply" else "CHỈ ĐỀ XUẤT (không tự chặn)"
    r = "đánh lừa trước" if mode.get("RESPONSE", "deceive") == "deceive" else "chặn web ngay"
    return m, r

def watch_mode():
    """Bao khi nguoi van hanh doi che do analyzer (/etc/default/lab-analyzer)."""
    last = mode_text()
    while True:
        time.sleep(2)
        cur = mode_text()
        if cur != last:
            col = RED if cur[0].startswith("TỰ") else GRN
            emit(datetime.now().strftime("%H:%M:%S"), "⚙️", "CHẾ ĐỘ", col, f"Analyzer chuyển sang: {BOLD}{cur[0]}{R} · {cur[1]}")
            last = cur

# ---------- chay ----------
def header():
    m, r = mode_text()
    w = width()
    print(f"{CYN}{'═' * w}{R}")
    print(f"{CYN}{BOLD}  MÁY CHỦ B 10.77.0.20 — MÀN HÌNH GIÁM SÁT{R}      Chế độ analyzer: {BOLD}{m}{R} · {r}")
    print(f"  {BLU}🌐 WEB{R} request vào Lab Shop   {YEL}⚠️ CẢNH BÁO{R} Suricata phát hiện   {MAG}🍯 HONEYPOT{R} có người chạm bẫy   "
          f"{GRN}🔑 ĐĂNG NHẬP{R}")
    print(f"  {CYN}🧠 PHÂN TÍCH{R} analyzer cộng điểm & quyết định   {RED}🛡 TƯỜNG LỬA{R} chặn/đánh lừa   {GRN}👤 VẬN HÀNH{R} người duyệt   "
          f"{MAG}🧬 RULE MỚI{R} hệ thống tự học")
    print(f"  {DIM}Quy tắc: ≥ {INC_SCORE} điểm = sự cố · ≥ {BLOCK_SCORE} điểm VÀ có ít nhất 1 bằng chứng THẬT (✓) mới phản ứng · "
          f"cộng điểm trong 120 giây{R}")
    print(f"  {DIM}Ẩn /api/health và file tĩnh (thêm --health / --tat-ca để hiện) · Ctrl+C để thoát{R}")
    print(f"{CYN}{'═' * w}{R}")

def main():
    header()
    jobs = [(FILES["web"], on_web(False)), (FILES["webfake"], on_web(True)), (FILES["eve"], on_eve),
            (FILES["hp"], on_hp), (FILES["auth"], on_auth), (FILES["inc"], on_inc), (FILES["dec"], on_dec)]
    for path, h in jobs:
        threading.Thread(target=follow, args=(path, h), daemon=True).start()
    threading.Thread(target=watch_rules, daemon=True).start()
    threading.Thread(target=watch_fw, daemon=True).start()
    threading.Thread(target=watch_mode, daemon=True).start()
    try:
        while True:
            print(OUT.get(), flush=True)
    except KeyboardInterrupt:
        print(f"\n{DIM}Đã thoát màn hình giám sát.{R}")


if __name__ == "__main__":
    main()
