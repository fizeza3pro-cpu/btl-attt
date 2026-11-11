#!/usr/bin/env python3
"""
Analyzer v2 cua bai lab: lien ket su kien tu NHIEU NGUON, cham diem theo chinh sach, gan MITRE ATT&CK,
tao incident va (chi khi duoc phep) yeu cau executor lab-block phan ung.

Nguon:  --eve       alert Suricata (EVE JSON)
        --honeypot  su kien honeypot / honeytoken / cong bay (lab-honeypot)
        --auth      nhat ky xac thuc cua Lab Shop API (dang nhap sai / bi khoa)

Chay KHONG can quyen root (user labresp). Quyen duy nhat: sudo /usr/local/sbin/lab-block.

Che do:   --mode recommend (mac dinh) chi de xuat | --mode apply duoc goi lab-block khi du MOI dieu kien
          --response block (mac dinh): du dieu kien -> chan web (l1)
          --response deceive: du dieu kien -> DANH LUA (chuyen vao honeypot); neu ke tan cong tiep tuc
                              "can cau" trong honeypot -> incident cho NGUOI VAN HANH DUYET chan hoan toan (l2)
          --offline  doc file tu dau (log cu/PCAP phat lai), gop theo thoi gian; LUON ep ve recommend
Chi dung thu vien chuan.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone

# ----------------------------- MITRE ATT&CK --------------------------------
ATTACK = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
}

# ----------------------------- Chinh sach ---------------------------------
# SID -> (diem, khong_gia_mao_duoc, nghi_pham_la, ATT&CK)
# Tin hieu yeu = 20 (mot minh khong bao gio du nguong); cung co = 50 (du tao incident); manh >= 70.
# Chan/danh lua luon can it nhat mot tin hieu KHONG gia mao duoc (den tu ket noi TCP that).
SIGNALS = {
    # Suricata - trinh sat
    1000001: (20, False, "src", "T1046"),
    1000003: (50, False, "dest", "T1046"),
    1000005: (50, False, "dest", "T1046"),
    # Suricata - web
    1000002: (70, True, "src", "T1595"),
    1000007: (100, True, "dest", "T1190"),
    1000006: (50, True, "src", "T1083"),
    1000008: (50, True, "src", "T1083"),
    1000013: (50, True, "src", "T1190"),
    1000015: (50, True, "src", "T1190"),
    1000014: (50, True, "src", "T1190"),
    1000016: (50, True, "src", "T1190"),
    1000017: (50, True, "dest", "T1110.001"),
    # Honeypot / honeytoken (ma noi bo 2000xxx) - deu can ket noi TCP that
    2000001: (40, True, "src", "T1046"),       # honeyport_connect
    2000002: (30, True, "src", "T1595"),       # honeypot_admin_view
    2000003: (60, True, "src", "T1110.001"),   # honeypot_admin_login
    2000004: (100, True, "src", "T1078"),      # honeytoken_creds (dung tai khoan bay)
    2000005: (100, True, "src", "T1552.001"),  # honeytoken_api_key
    2000006: (100, True, "src", "T1213"),      # honeytoken_file
    # Xac thuc Lab Shop (ma noi bo 3000xxx)
    3000001: (60, True, "src", "T1110.001"),   # >= 5 lan dang nhap sai trong 120 s
    3000002: (60, True, "src", "T1110.001"),   # bi khoa do dang nhap sai
}


class _Signals(dict):
    """Bang SIGNALS + dai SID cua rule TU SINH (lab-rulegen):
    5000000-5499999 = do duong dan (T1595.003), 5500000-5999999 = User-Agent cong cu quet (T1595.002).
    Diem 50, KHONG gia mao duoc (rule HTTP chi khop sau bat tay TCP that) - ngang cac rule web viet tay."""
    def __contains__(self, sid):
        return dict.__contains__(self, sid) or (isinstance(sid, int) and 5000000 <= sid <= 5999999)

    def __missing__(self, sid):
        if isinstance(sid, int) and 5000000 <= sid <= 5499999:
            return (50, True, "src", "T1595.003")
        if isinstance(sid, int) and 5500000 <= sid <= 5999999:
            return (50, True, "src", "T1595.002")
        raise KeyError(sid)


SIGNALS = _Signals(SIGNALS)
HONEYPOT_KIND = {"honeyport_connect": 2000001, "honeypot_admin_view": 2000002, "honeypot_admin_login": 2000003,
                 "honeytoken_creds": 2000004, "honeytoken_api_key": 2000005, "honeytoken_file": 2000006}
HONEYPOT_NAME = {v: k for k, v in HONEYPOT_KIND.items()}
AUTH_NAME = {3000001: "login_bruteforce", 3000002: "login_locked"}
ENGAGE_SIDS = {2000002, 2000003, 2000004, 2000005, 2000006}   # dau hieu "can cau" khi dang bi danh lua

PROTECTED_TARGET = "10.77.0.20"
LAB_NET = ipaddress.ip_network("10.77.0.0/24")
# Chi con MAY CHU duoc dac cach. C (10.77.0.30) da duoc bo khoi danh sach "khong bao gio chan" (11/11/2026):
# C la nguoi dung binh thuong, chi bi phan ung khi CHINH C tan cong qua ket noi TCP that. Lop chong vu oan chinh
# la yeu cau tin hieu KHONG gia mao duoc, khong phai danh sach khach hang.
NEVER_BLOCK = {"10.77.0.20"}
BLOCK_ALLOWED = {"10.77.0.10", "10.77.0.30"}
CORR_WINDOW = 120.0
INCIDENT_SCORE = 50
BLOCK_SCORE = 100
BLOCK_TTL = 60.0
DECEIVE_TTL = 600.0
MAX_EVENT_AGE = 15.0
FAIL_COUNT, FAIL_WINDOW = 5, 120.0
EXECUTOR = ["sudo", "-n", "/usr/local/sbin/lab-block"]

RANK = {
    "log": 0,
    "incident_medium": 1,
    "incident_high_spoof_suspect": 2,
    "incident_high_protected": 2,
    "recommend_only_out_of_scope": 2,
    "recommend_block_l1": 3,
    "block_l1": 3,
    "already_blocked": 3,
    "recommend_deceive": 3,
    "deceive": 3,
    "attacker_engaged": 4,
}

CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(s, n=120):
    if s is None:
        return None
    s = CTRL.sub("?", str(s))
    return s if len(s) <= n else s[:n] + "...(cat)"


def parse_ts(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt)
        except (TypeError, ValueError):
            pass
    try:
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


def attack_of(sids):
    out, seen = [], set()
    for s in sids:
        t = SIGNALS[s][3]
        if t not in seen:
            seen.add(t)
            out.append({"id": t, "name": ATTACK[t][0], "tactic": ATTACK[t][1]})
    return out


# ------------------------- Chuan hoa su kien -------------------------------
def from_eve(ev):
    if ev.get("event_type") != "alert":
        return None
    sid = (ev.get("alert") or {}).get("signature_id")
    if sid not in SIGNALS:
        return None
    return {"sid": sid, "ts": ev.get("timestamp"), "src": ev.get("src_ip"), "dst": ev.get("dest_ip"),
            "msg": (ev.get("alert") or {}).get("signature"), "source": "suricata",
            "community_id": ev.get("community_id"), "http_url": (ev.get("http") or {}).get("url")}


def from_honeypot(ev):
    sid = HONEYPOT_KIND.get(ev.get("kind"))
    if not sid:
        return None
    detail = {k: ev.get(k) for k in ("user", "password", "path", "port", "data", "note") if ev.get(k) not in (None, "")}
    return {"sid": sid, "ts": ev.get("ts"), "src": ev.get("src_ip"), "dst": PROTECTED_TARGET,
            "msg": f"honeypot: {ev.get('kind')}", "source": "honeypot", "detail": detail}


class Analyzer:
    def __init__(self, mode, response, offline, out_path, verbose, dry_run=False):
        # dry_run: chay logic nhu "apply" tren du lieu offline nhung executor la GIA (khong bao gio cham firewall)
        self.dry_run = dry_run
        self.mode = "apply" if dry_run else ("recommend" if offline else mode)
        self.response = response
        self.offline = offline
        self.out_path = out_path
        self.verbose = verbose
        self.window = {}
        self.last_rank = {}
        self.blocked_until = {}
        self.deceived_until = {}
        self._fw_cache = (0.0, set(), set())   # (thoi diem, IP bi danh lua, IP bi chan) THEO FIREWALL THAT
        self.fails = {}
        self.engaged_seen = {}
        self.seq = 0
        self.stats = {"lines": 0, "bad_json": 0, "alerts": 0, "ignored": 0, "stale": 0, "incidents": 0}

    def emit(self, rec):
        self.stats["incidents"] += 1
        line = json.dumps(rec, ensure_ascii=False)
        print(line, flush=True)
        if self.out_path:
            with open(self.out_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def fw_sets(self):
        """(IP dang bi danh lua, IP dang bi chan l1/l2) THEO FIREWALL THAT. Khi chay that, firewall la nguon su that
        duy nhat: nguoi van hanh co the danh lua / chan / GO bang tay (dashboard, lab-block). Truoc day analyzer tin
        tri nho cua minh -> go chan bang tay xong, analyzer van tuong IP con bi danh lua va bo qua moi tan cong moi.
        Offline / dry-run: tra None (dung tri nho, khong hoi firewall that). Luu dem 5 giay."""
        if self.offline or self.dry_run:
            return None
        t, dec, blk = self._fw_cache
        if time.time() - t > 5:
            res = self.run_executor(["status"])
            ips = lambda key: set(re.findall(r"(\d+\.\d+\.\d+\.\d+) expires", str(res.get(key) or "")))
            dec, blk = ips("deceive"), ips("blocked_l1") | ips("blocked_l2")
            self._fw_cache = (time.time(), dec, blk)
        return dec, blk

    def run_executor(self, args):
        if self.dry_run:
            return {"rc": 0, "exit_code": 0, "msg": "DRY-RUN: khong thay doi firewall", "args": args}
        try:
            p = subprocess.run(EXECUTOR + args, shell=False, capture_output=True, text=True, timeout=10)
            try:
                res = json.loads(p.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                res = {"rc": p.returncode, "msg": clean(p.stdout + p.stderr, 200)}
            res["exit_code"] = p.returncode
            return res
        except (OSError, subprocess.SubprocessError) as e:
            return {"rc": -1, "exit_code": -1, "msg": clean(repr(e), 200)}

    # ---------------- dau vao ----------------
    def handle_line(self, line, source):
        self.stats["lines"] += 1
        try:
            ev = json.loads(line)
        except ValueError:
            self.stats["bad_json"] += 1
            return
        if source == "eve":
            sig = from_eve(ev)
        elif source == "honeypot":
            sig = from_honeypot(ev)
        else:
            sig = self.from_auth(ev)
        if sig is None:
            if source == "eve" and ev.get("event_type") == "alert":
                self.stats["ignored"] += 1
            return
        self.handle(sig)

    def from_auth(self, ev):
        kind, ip = ev.get("kind"), ev.get("src_ip")
        ts = parse_ts(ev.get("ts"))
        if not ip or ts is None:
            return None
        if kind == "login_locked":
            return {"sid": 3000002, "ts": ev.get("ts"), "src": ip, "dst": PROTECTED_TARGET,
                    "msg": "Bị khóa đăng nhập do sai nhiều lần", "source": "auth", "detail": {"email": ev.get("email")}}
        if kind == "login_fail":
            q = self.fails.setdefault(ip, deque())
            t = ts.timestamp()
            q.append(t)
            while q and t - q[0] > FAIL_WINDOW:
                q.popleft()
            if len(q) >= FAIL_COUNT:
                q.clear()
                return {"sid": 3000001, "ts": ev.get("ts"), "src": ip, "dst": PROTECTED_TARGET,
                        "msg": f"Đăng nhập sai ≥ {FAIL_COUNT} lần trong {int(FAIL_WINDOW)} giây", "source": "auth",
                        "detail": {"email": ev.get("email")}}
        return None

    # ---------------- xu ly ----------------
    def handle(self, sig):
        sid = sig["sid"]
        self.stats["alerts"] += 1
        score, unspoofable, who, _ = SIGNALS[sid]
        src, dst = sig["src"], sig["dst"]
        if PROTECTED_TARGET not in (src, dst):
            self.stats["ignored"] += 1
            return
        suspect = src if who == "src" else dst
        try:
            sip = ipaddress.ip_address(suspect)
        except (TypeError, ValueError):
            self.stats["ignored"] += 1
            return
        if sip.version != 4 or sip not in LAB_NET or suspect == PROTECTED_TARGET:
            self.stats["ignored"] += 1
            return
        ts = parse_ts(sig["ts"])
        if ts is None:
            self.stats["ignored"] += 1
            return
        ev_epoch = ts.timestamp()
        age = time.time() - ev_epoch
        stale = (not self.offline) and age > MAX_EVENT_AGE
        if stale:
            self.stats["stale"] += 1
        now = ev_epoch

        fw = self.fw_sets()
        if fw is not None:
            # CHAY THAT: dong bo tri nho voi firewall (het han, hoac nguoi van hanh da go bang tay)
            for d, live in ((self.deceived_until, fw[0]), (self.blocked_until, fw[1])):
                if suspect in d and suspect not in live:
                    del d[suspect]
                    self.last_rank.pop(suspect, None)
                    self.engaged_seen.pop(suspect, None)
            deceived, blocked = suspect in fw[0], suspect in fw[1]
        else:
            # OFFLINE / dry-run: het han theo thoi gian cua su kien
            for d in (self.blocked_until, self.deceived_until):
                if suspect in d and now >= d[suspect]:
                    del d[suspect]
                    self.last_rank.pop(suspect, None)
                    self.engaged_seen.pop(suspect, None)
            deceived, blocked = suspect in self.deceived_until, suspect in self.blocked_until
        # Dang danh lua: honeypot tra 200 cho /admin la CO CHU DICH -> bo qua SID 1000007
        if deceived and sid == 1000007:
            return

        w = self.window.setdefault(suspect, {})
        for s in [s for s, (t, _) in w.items() if now - t > CORR_WINDOW]:
            del w[s]
        if not w:
            # IP da im lang > cua so tuong quan -> DOT TAN CONG MOI: quen muc da bao truoc do.
            # (Truoc day last_rank chi duoc xoa khi CHINH analyzer chan/danh lua xong; neu nguoi van hanh danh lua
            #  bang tay thi analyzer im lang vinh vien voi IP do, ke ca khi no tan cong lai.)
            self.last_rank.pop(suspect, None)
            self.engaged_seen.pop(suspect, None)
        if sid not in w:
            w[sid] = (ev_epoch, {
                "sid": sid, "ts": sig["ts"], "source": sig["source"], "msg": clean(sig["msg"]),
                "src": src, "dst": dst, "attack": SIGNALS[sid][3],
                "community_id": sig.get("community_id"), "http_url": clean(sig.get("http_url")),
                "detail": {k: clean(v, 60) for k, v in (sig.get("detail") or {}).items()} or None,
            })
        total = sum(SIGNALS[s][0] for s in w)
        has_unspoof = any(SIGNALS[s][1] for s in w)

        decision, reason = self.decide(suspect, total, has_unspoof, stale, sid, deceived, blocked)
        rank = RANK[decision]
        # Khi ke tan cong da "can cau": moi LOAI hanh vi moi van phat incident (de dashboard/bao cao du du kien)
        seen = self.engaged_seen.setdefault(suspect, set())
        new_engage = decision == "attacker_engaged" and sid not in seen
        if decision == "attacker_engaged":
            seen.add(sid)
        if rank == 0 or (rank <= self.last_rank.get(suspect, -1) and not new_engage):
            if self.verbose:
                print(f"# {suspect} sid={sid} score={total} -> {decision} (khong phat lai)", file=sys.stderr)
            return
        self.last_rank[suspect] = rank

        self.seq += 1
        sids = [info["sid"] for _, info in sorted(w.values(), key=lambda x: x[0])]
        rec = {
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{self.seq:03d}",
            "created_at": now_iso(),
            "mode": self.mode,
            "response": self.response,
            "offline": self.offline,
            "suspect_ip": suspect,
            "target_ip": PROTECTED_TARGET,
            "score": total,
            "has_unspoofable_signal": has_unspoof,
            "signals": [info for _, info in sorted(w.values(), key=lambda x: x[0])],
            "attack": attack_of(sids),
            "decision": decision,
            "reason": reason,
            "need_approval": decision == "attacker_engaged",
            "recommended_action": "block_l2" if decision == "attacker_engaged" else None,
            "event_age_s": round(age, 3),
            "action": None,
        }
        level = {"block_l1": "l1", "deceive": "dec"}.get(decision)
        if level:
            res = self.run_executor(["add", level, suspect])
            rec["action"] = {"cmd": f"lab-block add {level} {suspect}", "result": res,
                             "status": "ok" if res.get("rc") == 0 else "failed"}
            if res.get("rc") == 0:
                if level == "l1":
                    self.blocked_until[suspect] = now + BLOCK_TTL
                else:
                    self.deceived_until[suspect] = now + DECEIVE_TTL
                    # Cua so moi cho giai doan "trong honeypot": de nhan ra hanh vi can cau tiep theo
                    self.window[suspect] = {}
                self._fw_cache = (0.0, set(), set())   # vua doi firewall -> lan sau doc lai trang thai that
                rec["verification"] = {"executor_status": self.run_executor(["status"])}
            else:
                self.last_rank[suspect] = RANK["recommend_block_l1"] - 1
        self.emit(rec)

    def decide(self, suspect, score, has_unspoof, stale, sid, deceived, blocked=False):
        if deceived:
            if sid in ENGAGE_SIDS:
                return ("attacker_engaged",
                        "Kẻ tấn công đang bị đánh lừa mà vẫn tiếp tục tương tác với honeypot → chờ NGƯỜI VẬN HÀNH duyệt chặn toàn bộ (l2)")
            return "log", "Đang bị đánh lừa; chỉ ghi nhận"
        if score < INCIDENT_SCORE:
            return "log", "Điểm dưới ngưỡng sự cố; chỉ ghi nhận"
        if score < BLOCK_SCORE:
            return "incident_medium", "Đủ ngưỡng sự cố nhưng chưa đủ ngưỡng phản ứng; cần người điều tra"
        if not has_unspoof:
            return ("incident_high_spoof_suspect",
                    "Đủ điểm nhưng toàn bằng chứng có thể bị giả IP (không có kết nối TCP thật) → không phản ứng để tránh vu oan")
        if suspect in NEVER_BLOCK:
            return "incident_high_protected", "Nghi phạm thuộc danh sách hạ tầng được bảo vệ → chỉ báo người vận hành"
        if suspect not in BLOCK_ALLOWED:
            return "recommend_only_out_of_scope", "Ngoài phạm vi được phép phản ứng của lab → chỉ đề xuất"
        if blocked:
            return "already_blocked", "Đang bị chặn → không gia hạn thêm"
        rec_name, act_name = (("recommend_deceive", "deceive") if self.response == "deceive"
                              else ("recommend_block_l1", "block_l1"))
        if (self.offline and not self.dry_run) or self.mode != "apply" or stale:
            why = "chạy offline" if self.offline else ("sự kiện đã cũ" if stale else "đang ở chế độ chỉ đề xuất")
            return rec_name, f"Đủ điều kiện phản ứng nhưng {why} → chỉ đề xuất"
        if act_name == "deceive":
            return "deceive", "Đủ điểm, có bằng chứng thật, IP được phép phản ứng → ĐÁNH LỪA: chuyển vào honeypot 10 phút"
        return "block_l1", "Đủ điểm, có bằng chứng thật, IP được phép phản ứng, chế độ tự động → CHẶN WEB 60 giây"


# ------------------------------ doc file ----------------------------------
class Tail:
    """Doc file theo thoi gian thuc tu CUOI; chiu duoc xoay vong log va file chua ton tai."""

    def __init__(self, path, source):
        self.path, self.source, self.f, self.ino, self.buf = path, source, None, None, ""
        self.open(seek_end=True)

    def open(self, seek_end):
        try:
            self.f = open(self.path, "r", encoding="utf-8", errors="replace")
            if seek_end:
                self.f.seek(0, os.SEEK_END)
            self.ino = os.fstat(self.f.fileno()).st_ino
        except OSError:
            self.f = None

    def lines(self):
        if self.f is None:
            self.open(seek_end=False)
            if self.f is None:
                return
        while True:
            chunk = self.f.readline()
            if not chunk:
                break
            self.buf += chunk
            if self.buf.endswith("\n"):
                yield self.buf
                self.buf = ""
        try:
            if os.stat(self.path).st_ino != self.ino:
                self.f.close()
                self.open(seek_end=False)
        except FileNotFoundError:
            pass


def offline_events(paths):
    """Doc tat ca file, gop theo thoi gian de lien ket dung thu tu giua cac nguon."""
    items = []
    for path, source in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        items.append((0.0, i, line, source))
                        continue
                    ts = parse_ts(ev.get("timestamp") or ev.get("ts"))
                    items.append((ts.timestamp() if ts else 0.0, i, line, source))
        except OSError as e:
            print(f"# khong doc duoc {path}: {e}", file=sys.stderr)
    items.sort(key=lambda x: (x[0], x[1]))
    return items


def main():
    ap = argparse.ArgumentParser(description="Analyzer v2: lien ket da nguon, ATT&CK, danh lua co duyet")
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--honeypot", default=None, help="vd /var/log/lab-honeypot/events.jsonl")
    ap.add_argument("--auth", default=None, help="vd /var/log/lab-shop/auth.jsonl")
    ap.add_argument("--mode", choices=["recommend", "apply"], default="recommend")
    ap.add_argument("--response", choices=["block", "deceive"], default="block")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--dry-run-apply", action="store_true",
                    help="(kiem thu) cung --offline: chay logic apply voi executor GIA, khong cham firewall")
    ap.add_argument("--out")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    if a.dry_run_apply and not a.offline:
        ap.error("--dry-run-apply chi dung cung --offline")

    an = Analyzer(a.mode, a.response, a.offline, a.out, a.verbose, dry_run=a.dry_run_apply)
    sources = [(a.eve, "eve")] + ([(a.honeypot, "honeypot")] if a.honeypot else []) + ([(a.auth, "auth")] if a.auth else [])
    print(f"# analyzer v2 mode={an.mode} response={a.response} offline={a.offline} sources={[s for _, s in sources]}",
          file=sys.stderr, flush=True)
    try:
        if a.offline:
            for _, _, line, source in offline_events(sources):
                an.handle_line(line, source)
        else:
            tails = [Tail(p, s) for p, s in sources]
            while True:
                got = False
                for t in tails:
                    for line in t.lines():
                        got = True
                        an.handle_line(line, t.source)
                if not got:
                    time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"# stats {json.dumps(an.stats)}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
