#!/usr/bin/env python3
"""
lab-rulegen - TU SINH RULE SURICATA tu hanh vi cua ke tan cong da bi honeypot xac nhan.
Chi dung thu vien chuan. Chay bang user labresp (dich vu lab-rulegen). Cai dat: /usr/local/lib/lab/lab-rulegen.py

Quy trinh (moi vong, mac dinh 60 s hoac khi dashboard bam "Phan tich ngay"):
  1. Thu thap   : request HTTP (EVE event_type=http) cua cac IP da bi XAC NHAN la ke tan cong
                  (dung honeytoken / dang nhap trang admin gia / bi danh lua) trong LOOKBACK giay.
  2. Gan nhan   : do tin cay cao (honeytoken) / trung binh (bi danh lua, cham cong bay).
                  Request da co alert cua rule cu thi bo (rule cu da bat duoc).
  3. Chuan hoa  : giai ma URL 2 lan, chu thuong, tach duong dan / User-Agent.
  4. Trich dac trung: ung vien = doan dau duong dan ("/.env", "/wp-") va tu khoa User-Agent ("nikto").
                  Chon tham lam (set cover): ung vien phu nhieu request tan cong nhat, KHONG xuat hien
                  trong kho hop le, khong trung duong dan that cua site.
  5. Sinh rule  : khuon rule co dinh, SID 5000000-5499999 (duong dan) / 5500000-5999999 (User-Agent).
  6. Kiem chung : G1 cu phap (suricata -T) | G2 bat duoc (phat lai PCAP vong cua phien tan cong)
                  G3 khong bat nham (phat lai PCAP hop le) | G4 an toan | G5 khong trung.
     Dat ca 5 cua -> phieu de xuat "pending" cho NGUOI VAN HANH duyet tren dashboard.
     Nap rule do /usr/local/sbin/lab-rule (root) lam, KHONG phai chuong trinh nay.

Dung:
  lab-rulegen.py --daemon                 vong lap (dich vu)
  lab-rulegen.py --once [-v]              chay 1 vong, in ket qua
  sudo lab-rulegen.py --build-benign [pcap ...]   dung kho hop le (gop PCAP ca binh thuong + PCAP them)
"""
import argparse
import fcntl
import glob
import heapq
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone

STATE = os.environ.get("RULEGEN_STATE", "/var/lib/lab-rulegen")
EVE = "/var/log/suricata/eve.json"
HONEYPOT = "/var/log/lab-honeypot/events.jsonl"
INCIDENTS = "/var/lib/lab-analyzer/incidents.jsonl"
RING_DIR = "/var/lib/lab-pcap"
ACTIVE = "/var/lib/lab-rule/active.json"          # rule dang chay (root ghi, minh chi doc)
SURICATA = "/usr/bin/suricata"
YAML = "/etc/suricata/suricata.yaml"
WEBROOT = "/var/www/lab"
EVIDENCE = "/home/laamf-tung/lab/evidence"

PROPOSALS = os.path.join(STATE, "proposals.json")
LAST_RUN = os.path.join(STATE, "last_run.json")
TRIGGER = os.path.join(STATE, "trigger")
RESET_MARK = os.path.join(STATE, "since")         # epoch; rulegen-reset.sh ghi -> bo qua du lieu cu hon
BENIGN_PCAP = os.path.join(STATE, "benign.pcap")
BENIGN_HTTP = os.path.join(STATE, "benign_http.jsonl")

SERVER = "10.77.0.20"
TRUSTED = {"10.77.0.30"}               # khach hang that (never_block): traffic cua ho la HOP LE
LAB_PREFIX = "10.77.0."
LOOKBACK = 1800                        # chi xet 30 phut gan nhat
INTERVAL = 60
EVE_TAIL = 30_000_000                  # doc toi da 30 MB cuoi eve.json
MIN_SUPPORT_URI = 2                    # >= 2 request KHAC NHAU moi sinh rule duong dan (chong nhieu)
MIN_SUPPORT_UA = 3
MAX_NEW_PER_RUN = 8
SID_URI = (5000000, 5499999)
SID_UA = (5500000, 5999999)

HIGH_KINDS = {"honeytoken_creds", "honeytoken_api_key", "honeytoken_file"}
MED_KINDS = {"honeypot_admin_login", "honeypot_admin_view", "honeyport_connect"}
URI_OK = re.compile(r"^/[a-z0-9._~/-]{3,63}$")
UA_OK = re.compile(r"^[a-z0-9]{4,32}$")
SEP = "-._~"
# Tu pho bien trong User-Agent cua trinh duyet that -> khong bao gio lam dac trung
UA_COMMON = {"mozilla", "windows", "win64", "linux", "x86_64", "gecko", "firefox", "chrome", "safari", "applewebkit",
             "khtml", "like", "version", "compatible", "macintosh", "intel", "android", "mobile", "iphone", "edge",
             "edg", "opera", "trident", "curl", "wget", "python", "requests", "okhttp", "java", "ubuntu", "debian",
             # trinh duyet that it gap (kho hop le cua lab chi co Edge/Firefox -> phai liet ke de khong bat nham)
             "vivaldi", "brave", "yabrowser", "samsungbrowser", "ucbrowser", "crios", "fxios", "seamonkey",
             "palemoon", "waterfox", "librewolf", "thunderbird", "chromium", "silk", "qqbrowser", "maxthon",
             "konqueror", "epiphany", "midori", "falkon", "duckduckgo", "whale", "puffin", "coccoc", "ipad",
             "darwin", "cfnetwork", "dalvik", "build", "wv", "headlesschrome", "electron"}
MAX_PENDING = 6                        # toi da phieu cho duyet cung luc (cong cu quet co the sinh hang tram ung vien)
# API that cua Lab Shop (khong co file tuong ung trong webroot)
REAL_API = ["/api/health", "/api/products", "/api/cart", "/api/order", "/api/login", "/api/logout", "/api/me"]
# Duong dan BAY: honeypot da phat hien (va cham diem) roi -> khong dung lam mau sinh rule
TRAP_PREFIXES = ("/backup/", "/api/admin", "/admin", "/lab-admin")

VERBOSE = False


def log(*a):
    if VERBOSE:
        print(*a, file=sys.stderr, flush=True)


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def parse_epoch(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (TypeError, ValueError):
            pass
    try:
        return datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return None


def read_tail_jsonl(path, max_bytes):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return []
    out = []
    for ln in data.split(b"\n")[1 if size > max_bytes else 0:]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def fsync_dir(path):
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_json(path, obj):
    """Ghi nguyen tu + fsync: may ao bi tat dot ngot khong de lai file rong (da gap voi ext4)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(path)


def update_proposals(fn):
    """Doc-sua-ghi proposals.json duoi KHOA (dashboard cung ghi file nay khi nguoi van hanh duyet/tu choi)."""
    with open(os.path.join(STATE, ".proposals.lock"), "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        props = load_json(PROPOSALS, [])
        fn(props)
        save_json(PROPOSALS, props)


# ------------------------------- chuan hoa ---------------------------------
def norm_path(url):
    p = (url or "").split("?", 1)[0].split("#", 1)[0]
    for _ in range(2):                                  # chong ma hoa 2 lan (%252e)
        p = urllib.parse.unquote(p)
    p = re.sub(r"/{2,}", "/", p.lower())
    return p if p.startswith("/") else "/" + p


def ua_tokens(ua):
    return {t for t in re.split(r"[^a-z0-9]+", (ua or "").lower())
            if len(t) >= 4 and not t.isdigit() and t not in UA_COMMON and UA_OK.match(t)}


def path_candidates(path):
    """Ung vien = doan dau cua tung thanh phan duong dan, cat tai dau phan cach.
    /wp-login.php -> /wp-, /wp-login, /wp-login., /wp-login.php ; /.git/config -> /.git, /.git/, /config ..."""
    segs = [s for s in path.split("/") if s]
    out = set()
    for i, seg in enumerate(segs):
        full = "/" + seg
        out.add(full)
        if i < len(segs) - 1:
            out.add(full + "/")
        for j, ch in enumerate(seg):
            if ch in SEP:
                out.add("/" + seg[:j])
                out.add("/" + seg[:j + 1])
    return {c for c in out if URI_OK.match(c) and len(c) >= 4 and meaningful(c)}


def meaningful(c):
    """Loai manh vun: >= 2 chu cai va chu nhieu hon so (bo /77., /1077020., /10_77_0_20. - cong cu quet doan ten
    file sao luu tu IP may chu - chuoi nhu vay vo nghia lam dac trung)."""
    letters = sum(ch.isalpha() for ch in c)
    digits = sum(ch.isdigit() for ch in c)
    return letters >= 2 and letters > digits


def real_paths():
    paths = set(REAL_API) | {"/"}
    for root, _dirs, files in os.walk(WEBROOT):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), WEBROOT).replace(os.sep, "/")
            paths.add("/" + rel.lower())
    return paths


# ------------------------------- thu thap ----------------------------------
def reset_mark():
    try:
        with open(RESET_MARK, encoding="utf-8") as f:
            return float(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0.0


def confirmed_attackers(since):
    """IP -> (do tin cay, ly do). Nguon: honeypot + quyet dinh cua analyzer."""
    att = {}

    def put(ip, conf, why):
        if not (isinstance(ip, str) and ip.startswith(LAB_PREFIX)) or ip == SERVER or ip in TRUSTED:
            return
        old = att.get(ip)
        if old is None or (conf == "high" and old[0] != "high"):
            att[ip] = (conf, why)

    for ev in read_tail_jsonl(HONEYPOT, 2_000_000):
        t = parse_epoch(ev.get("ts"))
        if t is None or t < since:
            continue
        k = ev.get("kind")
        if k in HIGH_KINDS:
            put(ev.get("src_ip"), "high", k)
        elif k in MED_KINDS:
            put(ev.get("src_ip"), "medium", k)
    for inc in read_tail_jsonl(INCIDENTS, 2_000_000):
        t = parse_epoch(inc.get("created_at"))
        if t is None or t < since:
            continue
        if inc.get("decision") == "attacker_engaged":
            put(inc.get("suspect_ip"), "high", "attacker_engaged")
        elif inc.get("decision") in ("deceive", "block_l1"):
            put(inc.get("suspect_ip"), "medium", inc.get("decision"))
    return att


def collect(since, attackers):
    """Doc EVE: mau tan cong (http cua ke tan cong, CHUA bi rule nao bat) + mau hop le song (khach that)."""
    evs = read_tail_jsonl(EVE, EVE_TAIL)
    alerted = set()
    for ev in evs:
        if ev.get("event_type") == "alert":
            sid = (ev.get("alert") or {}).get("signature_id") or 0
            if not 9000000 <= sid < 10000000:
                alerted.add((ev.get("flow_id"), ev.get("tx_id")))
    attack, benign_live = [], []
    for ev in evs:
        if ev.get("event_type") != "http" or ev.get("dest_ip") != SERVER:
            continue
        h = ev.get("http") or {}
        t = parse_epoch(ev.get("timestamp"))
        rec = {"ip": ev.get("src_ip"), "url": h.get("url") or "", "ua": h.get("http_user_agent") or "",
               "status": h.get("status"), "t": t}
        if ev.get("src_ip") in attackers and t is not None and t >= since:
            rec["covered"] = (ev.get("flow_id"), ev.get("tx_id")) in alerted
            attack.append(rec)
        elif (ev.get("src_ip") in TRUSTED and isinstance(rec["status"], int) and rec["status"] < 400
              and not norm_path(rec["url"]).startswith(TRAP_PREFIXES)):
            # Traffic song cua khach chi duoc coi la HOP LE khi no trong hop le: thanh cong (< 400), khong cham bay.
            # (Loi 11/11/2026: C dung de thu do /.env, /.git/... (404) -> bi tinh la "hop le" -> G3 tu choi mai mai.)
            benign_live.append(rec)
    return attack, benign_live


# ------------------------------- sinh ung vien -----------------------------
def anchored(c, paths):
    """Ung vien la DAU cua moi duong dan no phu -> rule dung startswith (chinh xac hon, cung mot 'ho')."""
    return all(p.startswith(c) for p in paths)


def greedy(samples_by_cand, min_support, limit, prefer=None, covered=None):
    """Set cover tham lam: chon ung vien phu nhieu mau chua phu nhat; hoa thi uu tien ung vien 'dang tin' hon
    (prefer: duong dan NEO dau - cung mot ho, vd /.git/ thay vi /config gop /.git/config + /config.php.bak;
    User-Agent: TEN SAN PHAM 'Nikto/2.5' thay vi tu phu 'evasions'), roi den chuoi DAI hon (cu the hon).
    covered: mau DA duoc rule/phieu hien co phu (tu cac vong truoc) -> khong tinh lai."""
    chosen, covered = [], set(covered or ())
    pool = dict(samples_by_cand)
    while pool and len(chosen) < limit:
        best = max(pool, key=lambda c: (len(pool[c] - covered),
                                        bool(prefer and prefer(c, pool[c] - covered)), len(c)))
        gain = pool[best] - covered
        if len(gain) < min_support:
            break
        chosen.append((best, sorted(pool[best])))
        covered |= pool[best]
        del pool[best]
    return chosen


def build_candidates(attack, attackers, benign_uris, benign_uas, reals, existing, revoked=None):
    """revoked: {noi dung rule da THU HOI: thoi diem thu hoi}. Thu hoi = go bay gio, nhung neu ke tan cong DO LAI
    sau thoi diem do thi duoc de xuat lai (khac 'tu choi' = khong bao gio). Mau cu hon luc thu hoi khong tinh."""
    revoked = revoked or {}
    rejected = []                      # (ung vien, ly do) - de bao cao / dashboard

    def reject(c, why):
        rejected.append({"candidate": c, "reason": why})

    # ---- duong dan ----
    uri_samples = {}                   # ung vien -> tap duong dan tan cong (distinct)
    seen_paths = set()
    for s in attack:
        if s["covered"]:
            continue
        p = norm_path(s["url"])
        if p in reals:                 # ke tan cong cung duyet web binh thuong -> khong phai dac trung
            continue
        if p.startswith(TRAP_PREFIXES):  # bay cua honeypot: da bi phat hien bang kenh khac
            continue
        seen_paths.add(p)
        for c in path_candidates(p):
            if any((c in e or e in c) and (s["t"] or 0) <= when for e, when in revoked.items()):
                continue               # mau CU hon luc thu hoi rule tuong tu -> khong dung de de xuat lai
            uri_samples.setdefault(c, set()).add(p)
    ok_uri, dup = {}, 0
    for c, paths in uri_samples.items():
        bh = sum(1 for u in benign_uris if c in u)
        if bh:
            reject(c, f"G3: xuất hiện {bh} lần trong traffic hợp lệ")
            continue
        clash = next((r for r in reals if c in r), None)
        if clash:
            reject(c, f"G4: trùng đường dẫn thật của site ({clash})")
            continue
        if any(c in e or e in c for e in existing.get("uri", ())):
            dup += 1                   # G5: chi dem (liet ke het se che mat ly do quan trong)
            continue
        ok_uri[c] = paths
    pre_uri = {p for p in seen_paths if any(e in p for e in existing.get("uri", ()))}
    chosen_uri = greedy(ok_uri, MIN_SUPPORT_URI, MAX_NEW_PER_RUN, prefer=anchored, covered=pre_uri)

    # ---- User-Agent ----
    ua_samples = {}
    for i, s in enumerate(attack):
        if s["covered"]:
            continue
        for tok in ua_tokens(s["ua"]):
            ua_samples.setdefault(tok, set()).add(i)
    ok_ua = {}
    for tok, idx in ua_samples.items():
        bh = sum(1 for u in benign_uas if tok in u)
        if bh:
            reject(tok, f"G3: có trong User-Agent hợp lệ ({bh} lần)")
            continue
        if tok in existing.get("ua", ()):
            dup += 1
            continue
        ok_ua[tok] = idx
    pre_ua = {i for i, s in enumerate(attack) if any(e in (s["ua"] or "").lower() for e in existing.get("ua", ()))}
    # Chi nhan TEN SAN PHAM dang "Ten/phien-ban" (Nikto/2.5, sqlmap/1.8): chuoi ngau nhien hay tu phu thi khong
    products = {m.group(1) for s in attack for m in re.finditer(r"([a-z][a-z0-9]{3,31})/\d", (s["ua"] or "").lower())}
    for tok in [t for t in ok_ua if t not in products]:
        del ok_ua[tok]
    chosen_ua = greedy(ok_ua, MIN_SUPPORT_UA, 3, covered=pre_ua)

    cands = []
    for c, paths in chosen_uri:
        cands.append({"kind": "uri", "content": c, "samples": paths[:10], "support": len(paths),
                      "anchor": anchored(c, paths)})
    for tok, idx in chosen_ua:
        cands.append({"kind": "ua", "content": tok, "samples": sorted({attack[i]["ua"][:120] for i in idx})[:5],
                      "support": len(idx), "anchor": False})
    # duong dan la nhung chi xuat hien 1 lan va khong thuoc ho nao -> bao cao 1 dong / duong dan (khong liet ke moi tien to)
    covered_paths = {p for c in cands if c["kind"] == "uri" for p in ok_uri.get(c["content"], ())} | pre_uri
    for p in sorted(seen_paths - covered_paths):
        reject(p, f"ít mẫu: đường dẫn đơn lẻ, không thuộc họ nào (cần ≥ {MIN_SUPPORT_URI} đường dẫn khác nhau)")
    order = {"G3": 0, "G4": 1}
    rejected.sort(key=lambda r: order.get(r["reason"][:2], 3))
    return cands, rejected, len(seen_paths), dup


# ------------------------------- rule ---------------------------------------
def make_rule(kind, content, sid, anchor=False):
    """Khuon rule CO DINH. lab-rule (root) dung lai dung ham tuong duong de dung rule, khong tin van ban rule.
    anchor=True: duong dan PHAI BAT DAU bang content (startswith) -> it bat nham hon."""
    if kind == "uri":
        assert URI_OK.match(content)
        return (f'alert http any any -> $HOME_NET any (msg:"LAB AUTO uri probe {content}"; '
                f'flow:established,to_server; http.uri; content:"{content}"; nocase; {"startswith; " if anchor else ""}'
                f'classtype:web-application-attack; priority:2; '
                f'metadata:generated_by lab-rulegen, kind uri; sid:{sid}; rev:1;)')
    assert kind == "ua" and UA_OK.match(content)
    return (f'alert http any any -> $HOME_NET any (msg:"LAB AUTO scanner user-agent {content}"; '
            f'flow:established,to_server; http.user_agent; content:"{content}"; nocase; '
            f'classtype:web-application-attack; priority:2; '
            f'metadata:generated_by lab-rulegen, kind ua; sid:{sid}; rev:1;)')


def next_sid(kind, used):
    lo, hi = SID_URI if kind == "uri" else SID_UA
    s = max([u for u in used if lo <= u <= hi] + [lo - 1]) + 1
    if s > hi:
        raise RuntimeError("het dai SID")
    used.add(s)
    return s


def suricata_replay(rules_path, pcap_path, workdir):
    """Phat lai PCAP (file hoac thu muc) voi DUY NHAT bo rule ung vien. Tra ve danh sach alert."""
    os.makedirs(workdir, exist_ok=True)
    cmd = [SURICATA, "-c", YAML, "-S", rules_path, "-r", pcap_path, "-k", "none", "-l", workdir,
           "--runmode", "single", "--set", "unix-command.enabled=no"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    alerts = []
    for ev in read_tail_jsonl(os.path.join(workdir, "eve.json"), 200_000_000):
        if ev.get("event_type") == "alert":
            alerts.append({"sid": ev["alert"]["signature_id"], "src": ev.get("src_ip"),
                           "url": (ev.get("http") or {}).get("url"), "ua": (ev.get("http") or {}).get("http_user_agent")})
    return p.returncode, alerts, (p.stderr or p.stdout)[-400:]


def gate_syntax(rules, tmp):
    path = os.path.join(tmp, "g1.rules")
    with open(path, "w") as f:
        f.write("\n".join(rules) + "\n")
    p = subprocess.run([SURICATA, "-T", "-c", YAML, "-S", path, "-l", tmp, "--set", "unix-command.enabled=no"],
                       capture_output=True, text=True, timeout=120)
    return p.returncode == 0, (p.stderr or p.stdout)[-300:]


def ring_pcaps():
    """Vong hien tai + vong truoc lan khoi dong lai gan nhat (prev/); bo file chi co header (24 byte)."""
    files = glob.glob(os.path.join(RING_DIR, "ring.pcap*")) + glob.glob(os.path.join(RING_DIR, "prev", "ring.pcap*"))
    return sorted((f for f in files if os.path.getsize(f) > 24), key=os.path.getmtime)


def validate(cands, attackers, tmp):
    """Chay G1-G3 cho tat ca ung vien (moi cua 1 lan Suricata cho ca lo)."""
    rules = [c["rule"] for c in cands]
    ok, detail = gate_syntax(rules, tmp)
    if not ok and len(cands) > 1:                      # loi o 1 rule -> thu tung rule
        for c in cands:
            ok1, d1 = gate_syntax([c["rule"]], tmp)
            c["gates"]["G1"] = {"ok": ok1, "detail": "suricata -T đạt" if ok1 else d1}
    else:
        for c in cands:
            c["gates"]["G1"] = {"ok": ok, "detail": "suricata -T đạt" if ok else detail}
    good = [c for c in cands if c["gates"]["G1"]["ok"]]
    if not good:
        return
    rpath = os.path.join(tmp, "cand.rules")
    with open(rpath, "w") as f:
        f.write("\n".join(c["rule"] for c in good) + "\n")

    # G2: phat lai PCAP vong (chua phien tan cong that) -> rule phai bat duoc chinh cac mau da sinh ra no
    ring = ring_pcaps()
    if ring:
        rdir = os.path.join(tmp, "ring")
        os.makedirs(rdir)
        for i, f in enumerate(ring):                    # chep ra de file dang ghi khong bi doc do dang
            shutil.copy(f, os.path.join(rdir, f"r{i:02d}.pcap"))
        rc, alerts, err = suricata_replay(rpath, rdir, os.path.join(tmp, "g2"))
    else:
        rc, alerts, err = 1, [], "không có PCAP vòng (dịch vụ lab-pcap-ring?)"
    for c in good:
        mine = [a for a in alerts if a["sid"] == c["sid"] and a["src"] in attackers]
        if c["kind"] == "uri":
            got = {norm_path(a["url"]) for a in mine if a["url"]}
            hit = len(got & set(c["samples"]))
            need = min(len(c["samples"]), c["support"])
        else:
            hit, need = len(mine), c["support"]
        c["gates"]["G2"] = {"ok": rc == 0 and hit >= need and need > 0,
                            "detail": f"bắt {hit}/{need} mẫu tấn công khi phát lại PCAP vòng" if rc == 0 else f"lỗi phát lại: {err}"}

    # G3: phat lai kho HOP LE -> khong duoc co alert nao
    try:
        with open(BENIGN_HTTP, encoding="utf-8") as f:
            BENIGN_REQS = sum(1 for _ in f)
    except OSError:
        BENIGN_REQS = 0
    if os.path.exists(BENIGN_PCAP) and os.path.getsize(BENIGN_PCAP) > 24:
        rc, alerts, err = suricata_replay(rpath, BENIGN_PCAP, os.path.join(tmp, "g3"))
        for c in good:
            n = sum(1 for a in alerts if a["sid"] == c["sid"])
            c["gates"]["G3"] = {"ok": rc == 0 and n == 0,
                                "detail": f"{n} alert trên kho hợp lệ ({BENIGN_REQS} request)" if rc == 0 else f"lỗi phát lại: {err}"}
    else:
        for c in good:
            c["gates"]["G3"] = {"ok": False, "detail": "chưa có kho hợp lệ (chạy --build-benign)"}


# ------------------------------- mot vong ------------------------------------
def run_once():
    now = time.time()
    os.makedirs(STATE, exist_ok=True)
    proposals = load_json(PROPOSALS, [])
    active = load_json(ACTIVE, {"rules": []}).get("rules", [])
    since = max(now - LOOKBACK, reset_mark())          # chi xet du lieu SAU lan reset gan nhat (demo lai)
    attackers = confirmed_attackers(since)
    report = {"run_at": now_iso(), "attackers": {ip: {"confidence": c, "why": w} for ip, (c, w) in attackers.items()},
              "attack_samples": 0, "uncovered_samples": 0, "distinct_paths": 0, "candidates": 0, "new_proposals": [],
              "rejected": [], "benign_uris": 0, "note": ""}
    if not any(c == "high" for c, _ in attackers.values()):
        report["note"] = "Chưa có kẻ tấn công độ tin cậy CAO (honeytoken) trong 30 phút → không sinh rule"
        save_json(LAST_RUN, report)
        return report
    attack, benign_live = collect(since, attackers)
    benign = read_tail_jsonl(BENIGN_HTTP, 50_000_000) + benign_live
    benign_uris = {norm_path(b.get("url")) for b in benign}
    benign_uas = {(b.get("ua") or "").lower() for b in benign}
    reals = real_paths()
    report.update(attack_samples=len(attack), uncovered_samples=sum(1 for s in attack if not s["covered"]),
                  benign_uris=len(benign_uris))
    # noi dung da co (dang chay hoac dang cho duyet / da tu choi) -> G5
    existing = {"uri": set(), "ua": set()}
    recent_fail = [p for p in proposals if p.get("status") == "failed_gate"
                   and now - (parse_epoch(p.get("created_at")) or 0) < 600]   # truot cua: 10 phut moi thu lai
    for r in active + recent_fail + [p for p in proposals if p.get("status") in ("pending", "approved", "rejected")]:
        existing.setdefault(r.get("kind"), set()).add(r.get("content"))
    # Thu hoi (khac tu choi): duoc de xuat lai neu bi do LAI sau luc thu hoi -> khong dua vao G5, ghi thoi diem
    revoked = {}
    for p in proposals:
        if p.get("status") == "revoked" and p.get("kind") == "uri" and p.get("content") not in existing.get("uri", ()):
            t_rev = parse_epoch(p.get("decided_at")) or now
            revoked[p["content"]] = max(revoked.get(p["content"], 0), t_rev)
    n_pending = sum(1 for p in proposals if p.get("status") == "pending")
    if n_pending >= MAX_PENDING:
        report["note"] = f"Đã có {n_pending} phiếu chờ duyệt (tối đa {MAX_PENDING}) → tạm dừng sinh thêm, chờ người vận hành xử lý"
        save_json(LAST_RUN, report)
        return report
    cands, rejected, npaths, dup = build_candidates(attack, attackers, benign_uris, benign_uas, reals, existing, revoked)
    cands = cands[:MAX_PENDING - n_pending]
    report.update(distinct_paths=npaths, candidates=len(cands), rejected=rejected[:60], duplicates=dup)
    if not cands:
        report["note"] = "Không có ứng viên mới đạt điều kiện" + (f" ({dup} ứng viên trùng rule/phiếu đã có)" if dup else "")
        save_json(LAST_RUN, report)
        return report
    used = {p["sid"] for p in proposals} | {r["sid"] for r in active}
    for c in cands:
        c["sid"] = next_sid(c["kind"], used)
        c["rule"] = make_rule(c["kind"], c["content"], c["sid"], c["anchor"])
        c["gates"] = {"G4": {"ok": True, "detail": "không trùng đường dẫn thật, ký tự an toàn, đủ dài"},
                      "G5": {"ok": True, "detail": "chưa có rule tương tự"}}
    tmp = tempfile.mkdtemp(prefix="rulegen-", dir=STATE)
    try:
        validate(cands, attackers, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    new_recs = []
    for c in cands:
        ok = all(g.get("ok") for g in c["gates"].values()) and len(c["gates"]) == 5
        rec = {"id": f"R{c['sid']}", "sid": c["sid"], "kind": c["kind"], "content": c["content"], "anchor": c["anchor"],
               "rule": c["rule"],
               "samples": c["samples"], "support": c["support"],
               "attackers": sorted(ip for ip in attackers), "confidence": "high",
               "gates": c["gates"], "status": "pending" if ok else "failed_gate", "created_at": now_iso()}
        new_recs.append(rec)
        report["new_proposals"].append({"id": rec["id"], "content": rec["content"], "status": rec["status"]})
        if not ok:
            failed = [k for k, g in c["gates"].items() if not g.get("ok")]
            report["rejected"].insert(0, {"candidate": c["content"], "reason": "không qua cửa " + ",".join(failed)})
    # chi NOI THEM phieu moi (khong ghi de thay doi cua dashboard trong luc dang kiem chung)
    update_proposals(lambda props: props.extend(r for r in new_recs if r["sid"] not in {p.get("sid") for p in props}))
    save_json(LAST_RUN, report)
    return report


def daemon():
    for d in glob.glob(os.path.join(STATE, "rulegen-*")):   # thu muc tam cua vong bi ngat (dung dich vu giua chung)
        shutil.rmtree(d, ignore_errors=True)
    last_sig = None
    while True:
        forced = os.path.exists(TRIGGER)
        if forced:
            try:
                os.unlink(TRIGGER)
            except OSError:
                pass
        try:
            # chi chay lai khi co du lieu moi (kich thuoc eve / honeypot thay doi) hoac bi yeu cau
            sig = tuple(os.path.getsize(p) if os.path.exists(p) else 0 for p in (EVE, HONEYPOT, INCIDENTS))
            if forced or sig != last_sig:
                r = run_once()
                last_sig = sig
                if r.get("new_proposals"):
                    print(f"rulegen: {len(r['new_proposals'])} de xuat moi: "
                          + ", ".join(f"{p['content']}({p['status']})" for p in r["new_proposals"]), flush=True)
        except Exception as e:                       # khong de dich vu chet vi 1 vong loi
            print(f"rulegen: loi vong: {e!r}", flush=True)
        for _ in range(INTERVAL):
            if os.path.exists(TRIGGER):
                break
            time.sleep(1)


# ------------------------------- kho hop le -----------------------------------
def read_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return None, []
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == 0xA1B2C3D4:
            end = "<"
        elif magic == 0xD4C3B2A1:
            end = ">"
        else:
            raise ValueError(f"{path}: khong phai pcap co dien")
        linktype = struct.unpack(end + "I", hdr[20:24])[0]
        recs = []
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, us, incl, orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            recs.append((ts, us, incl, orig, data))
        return (end, linktype, hdr), recs


def build_benign(extra):
    """Gop PCAP cac ca BINH THUONG (metadata 'nhan: normal') + PCAP them thanh benign.pcap (sap theo thoi gian),
    roi phat lai khong rule de lay danh sach request HTTP hop le (benign_http.jsonl)."""
    files = []
    for d in sorted(glob.glob(os.path.join(EVIDENCE, "run-*"))):
        try:
            with open(os.path.join(d, "metadata.txt"), encoding="utf-8") as f:
                if not re.search(r"^nhan:\s*normal\s*$", f.read(), re.M):
                    continue
        except OSError:
            continue
        if os.path.getsize(os.path.join(d, "traffic.pcap")) > 24:
            files.append(os.path.join(d, "traffic.pcap"))
    files += extra
    streams, link = [], None
    for fp in files:
        meta, recs = read_pcap(fp)
        if meta is None:
            continue
        if link is None:
            link = meta
        elif meta[1] != link[1]:
            print(f"bo qua {fp}: linktype khac", file=sys.stderr)
            continue
        streams.append([(r[0], r[1], r[2], r[3], r[4]) for r in recs])
    os.makedirs(STATE, exist_ok=True)
    n = 0
    with open(BENIGN_PCAP, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link[1]))
        for ts, us, incl, orig, data in heapq.merge(*streams, key=lambda r: (r[0], r[1])):
            out.write(struct.pack("<IIII", ts, us, incl, orig) + data)
            n += 1
        out.flush()
        os.fsync(out.fileno())
    empty = os.path.join(STATE, "empty.rules")
    open(empty, "w").close()
    tmp = tempfile.mkdtemp(prefix="benign-", dir=STATE)
    try:
        suricata_replay(empty, BENIGN_PCAP, tmp)
        rows = []
        for ev in read_tail_jsonl(os.path.join(tmp, "eve.json"), 500_000_000):
            if ev.get("event_type") == "http":
                h = ev.get("http") or {}
                rows.append({"src": ev.get("src_ip"), "url": h.get("url"), "ua": h.get("http_user_agent"),
                             "status": h.get("status")})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    with open(BENIGN_HTTP, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(BENIGN_HTTP)
    if not rows:
        print("CANH BAO: kho hop le KHONG co request HTTP nao", file=sys.stderr)
    print(json.dumps({"pcap_files": len(files), "packets": n, "http_requests": len(rows),
                      "distinct_paths": len({norm_path(r['url']) for r in rows})}, ensure_ascii=False))


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description="Tu sinh rule Suricata tu hanh vi ke tan cong da xac nhan")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--daemon", action="store_true")
    g.add_argument("--once", action="store_true")
    g.add_argument("--build-benign", nargs="*", metavar="PCAP")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    VERBOSE = a.verbose
    if a.build_benign is not None:
        build_benign(a.build_benign)
    elif a.once:
        print(json.dumps(run_once(), ensure_ascii=False, indent=1))
    else:
        daemon()


if __name__ == "__main__":
    main()
