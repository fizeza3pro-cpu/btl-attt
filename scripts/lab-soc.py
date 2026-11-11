#!/usr/bin/env python3
"""
Lab SOC Dashboard v2 - bang dieu khien cho nguoi van hanh (chi thu vien chuan, khong tai tai nguyen ngoai).

- Chi nghe tren mang QUAN TRI 192.168.56.101:9000, chi chap nhan may that 192.168.56.1 (va 127.0.0.1).
- THIET BI DONG: khong co danh sach may co dinh. Mot IP chi xuat hien khi co hoat dong (truy cap web,
  alert, honeypot, dang nhap, incident) trong 30 phut gan nhat, hoac dang bi chan / danh lua.
- Nguon: nginx access log (web that + ban sao honeypot), eve.json (Suricata), events.jsonl (honeypot),
  auth.jsonl (Lab Shop), incidents.jsonl + decisions.jsonl (analyzer / nguoi van hanh), lab-block status.
- Hanh dong: danh lua / chan web 60 s / chan toan bo / go chan / duyet / bo qua. Goi lab-block qua sudo
  (quyen duy nhat cua labresp; lab-block tu choi IP ngoai danh sach cho phep). Moi quyet dinh ghi decisions.jsonl.
- Bao cao su co: /report/<incident_id>. Moi du lieu tu ke tan cong deu duoc escape truoc khi hien thi.
"""
import fcntl
import html
import json
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = ("192.168.56.101", 9000)
ALLOWED_CLIENTS = {"192.168.56.1", "192.168.56.101", "127.0.0.1"}   # may that + chinh B (Firefox tren B)
INC = "/var/lib/lab-analyzer/incidents.jsonl"
DEC = "/var/lib/lab-analyzer/decisions.jsonl"
EVE = "/var/log/suricata/eve.json"
HP = "/var/log/lab-honeypot/events.jsonl"
AUTH = "/var/log/lab-shop/auth.jsonl"
ACC = "/var/log/nginx/access.log"
HACC = "/var/log/nginx/honeypot-access.log"
EXECUTOR = ["sudo", "-n", "/usr/local/sbin/lab-block"]
RULE_EXEC = ["sudo", "-n", "/usr/local/sbin/lab-rule"]        # nap / thu hoi rule tu sinh (root)
RG_DIR = "/var/lib/lab-rulegen"
RG_PROPOSALS = RG_DIR + "/proposals.json"
RG_LAST = RG_DIR + "/last_run.json"
RG_TRIGGER = RG_DIR + "/trigger"
RG_LOCK = RG_DIR + "/.proposals.lock"
RULES_ACTIVE = "/var/lib/lab-rule/active.json"
SERVICES = ["suricata", "nginx", "lab-shop-api", "lab-honeypot", "lab-analyzer", "lab-response", "lab-rulegen",
            "lab-pcap-ring", "lab-soc"]
SERVER_IP = "10.77.0.20"
LAB_PREFIX = "10.77.0."
ACTIVE_WINDOW = 1800          # IP hien tren dashboard neu co hoat dong trong 30 phut
RISK_WINDOW = 120             # diem rui ro = incident moi nhat trong 120 s (= cua so tuong quan cua analyzer)
CLEAR_ACTIONS = {"unblock_all", "dismiss", "reset_lab"}   # nguoi van hanh go / bo qua / reset -> xoa nhan rui ro
BUCKETS = 30                  # bieu do 30 phut, moi cot 1 phut
TOKEN = secrets.token_hex(16)
IP_RE = re.compile(r"^10\.77\.0\.\d{1,3}$")
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')


# ------------------------------ doc du lieu ------------------------------
def tail_lines(path, max_bytes=600_000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = data.splitlines()
    return lines[1:] if size > max_bytes else lines


def jsonl(path, max_bytes=600_000):
    out = []
    for line in tail_lines(path, max_bytes):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def epoch(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def nginx_events(path, kind, max_bytes=400_000):
    out = []
    for line in tail_lines(path, max_bytes):
        m = LOG_RE.match(line)
        if not m:
            continue
        ip, ts, method, url, status, _, ua = m.groups()
        try:
            t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            continue
        out.append({"t": t, "ip": ip, "method": method, "path": url[:200], "status": int(status), "ua": ua[:160], "kind": kind})
    return out


def lab_block(*args):
    try:
        p = subprocess.run(EXECUTOR + list(args), shell=False, capture_output=True, text=True, timeout=10)
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "msg": str(e)[:160]}


def fw_map(fw):
    """{ip: [{"level","label","expires"}]} tu chuoi elements cua lab-block status."""
    out = {}
    for key, level, label in (("deceive", "dec", "Đánh lừa"), ("blocked_l2", "l2", "Chặn toàn bộ"), ("blocked_l1", "l1", "Chặn web")):
        for ip, exp in re.findall(r"(\d+\.\d+\.\d+\.\d+) expires ([0-9hms]+)", fw.get(key, "") or ""):
            out.setdefault(ip, []).append({"level": level, "label": label, "expires": exp})
    return out


def services():
    try:
        p = subprocess.run(["systemctl", "is-active", *SERVICES], capture_output=True, text=True, timeout=5)
        states = p.stdout.split()
    except Exception:  # noqa: BLE001
        states = []
    return [{"name": n, "active": (states[i] == "active") if i < len(states) else False} for i, n in enumerate(SERVICES)]


def mode_info():
    d = {"MODE": "recommend", "RESPONSE": "deceive"}
    try:
        for line in open("/etc/default/lab-analyzer", encoding="utf-8"):
            k, _, v = line.strip().partition("=")
            if k in d and v:
                d[k] = v
    except OSError:
        pass
    return d


def collect():
    """Doc tat ca nguon, chuan hoa thoi gian (epoch)."""
    alerts = []
    for e in jsonl(EVE, 2_000_000):
        if e.get("event_type") == "alert" and (e.get("alert") or {}).get("signature_id", 0) < 9000000:
            alerts.append({"t": epoch(e.get("timestamp")), "sid": e["alert"]["signature_id"], "msg": e["alert"]["signature"],
                           "src": e.get("src_ip"), "dst": e.get("dest_ip")})
    hp = [{**h, "t": epoch(h.get("ts"))} for h in jsonl(HP)]
    auth = [{**a, "t": epoch(a.get("ts"))} for a in jsonl(AUTH)]
    incidents = [{**i, "t": epoch(i.get("created_at"))} for i in jsonl(INC, 1_500_000)]
    decisions = [{**d, "t": epoch(d.get("at"))} for d in jsonl(DEC)]
    web = nginx_events(ACC, "web") + nginx_events(HACC, "honeypot")
    return alerts, hp, auth, incidents, decisions, web


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def update_proposals(fn):
    """Doc-sua-ghi proposals.json duoi khoa chung voi lab-rulegen."""
    with open(RG_LOCK, "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        props = read_json(RG_PROPOSALS, [])
        res = fn(props)
        tmp = RG_PROPOSALS + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(props, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, RG_PROPOSALS)
        return res


def lab_rule(*args):
    try:
        p = subprocess.run(RULE_EXEC + list(args), shell=False, capture_output=True, text=True, timeout=180)
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "msg": str(e)[:160]}


def rulegen_state(alerts):
    """Phieu de xuat, rule tu sinh dang chay (+ so lan khop), ket qua lan phan tich gan nhat."""
    props = read_json(RG_PROPOSALS, [])
    active = read_json(RULES_ACTIVE, {"rules": []}).get("rules", [])
    hits = {}
    for a in alerts:
        if 5000000 <= a["sid"] <= 5999999:
            h = hits.setdefault(a["sid"], {"n": 0, "last": None, "ips": set()})
            h["n"] += 1
            h["last"] = max(h["last"] or 0, a["t"] or 0)
            h["ips"].add(a["src"])
    by_sid = {p.get("sid"): p for p in props}
    act = []
    for r in active:
        h = hits.get(r["sid"], {"n": 0, "last": None, "ips": set()})
        p = by_sid.get(r["sid"], {})
        act.append({**r, "hits": h["n"], "last_hit": h["last"], "hit_ips": sorted(x for x in h["ips"] if x),
                    "support": p.get("support"), "samples": (p.get("samples") or [])[:4]})
    keep = ("id", "sid", "kind", "content", "rule", "samples", "support", "attackers", "gates", "status", "created_at",
            "decided_at", "decided_by")
    pending = [{k: p.get(k) for k in keep} for p in props if p.get("status") == "pending"]
    history = [{k: p.get(k) for k in keep} for p in props if p.get("status") != "pending"][-12:][::-1]
    last = read_json(RG_LAST, {})
    if isinstance(last.get("rejected"), list):
        last["rejected"] = last["rejected"][:14]
    return {"pending": pending, "active": act, "history": history, "last_run": last,
            "triggered": os.path.exists(RG_TRIGGER)}


def lab_ip(ip):
    return isinstance(ip, str) and ip.startswith(LAB_PREFIX) and ip != SERVER_IP


def suspect_of_alert(a):
    return a["dst"] if a.get("src") == SERVER_IP else a.get("src")


# ------------------------------ tong hop ---------------------------------
def state():
    now = time.time()
    alerts, hp, auth, incidents, decisions, web = collect()
    fw = lab_block("status")
    fwm = fw_map(fw)
    devices = {}

    def dev(ip):
        if not lab_ip(ip):
            return None
        return devices.setdefault(ip, {"ip": ip, "first": None, "last": None, "requests": 0, "errors": 0, "alerts": 0,
                                       "honeypot": 0, "honeypot_web": 0, "auth_fail": 0, "auth_ok": 0, "incidents": 0,
                                       "risk": 0, "decision": None, "attack": [], "ua": "", "last_path": ""})

    since = now - ACTIVE_WINDOW   # moi bo dem cua thiet bi tinh trong 30 phut gan nhat

    def touch(d, t):
        if d is None or t is None:
            return
        d["first"] = t if d["first"] is None else min(d["first"], t)
        d["last"] = t if d["last"] is None else max(d["last"], t)

    for w in web:
        if w["t"] < since:
            continue
        d = dev(w["ip"])
        if d is None:
            continue
        if w["path"].startswith("/api/health"):
            touch(d, w["t"])
            continue
        touch(d, w["t"])
        if w["kind"] == "honeypot":
            d["honeypot_web"] += 1
        d["requests"] += 1
        d["errors"] += 1 if w["status"] >= 400 else 0
        d["ua"], d["last_path"] = w["ua"], w["path"]
    for a in alerts:
        d = dev(suspect_of_alert(a)) if (a["t"] or 0) >= since else None
        if d:
            d["alerts"] += 1
            touch(d, a["t"])
    for h in hp:
        d = dev(h.get("src_ip")) if (h["t"] or 0) >= since else None
        if d:
            d["honeypot"] += 1
            touch(d, h["t"])
    for u in auth:
        d = dev(u.get("src_ip")) if (u["t"] or 0) >= since else None
        if d:
            if u.get("kind") == "login_ok":
                d["auth_ok"] += 1
            elif u.get("kind") in ("login_fail", "login_locked"):
                d["auth_fail"] += 1
            touch(d, u["t"])
    # Moc "da xu ly" cua tung IP: sau khi nguoi van hanh go chan / bo qua / chay reset-lab.sh (ip "*" = moi IP),
    # cac incident CU HON moc do khong con tinh vao rui ro hien tai.
    cleared, cleared_all = {}, 0.0
    for dd in decisions:
        if dd.get("action") in CLEAR_ACTIONS and dd.get("t"):
            if dd.get("ip") == "*":
                cleared_all = max(cleared_all, dd["t"])
            elif dd.get("ip"):
                cleared[dd["ip"]] = max(cleared.get(dd["ip"], 0.0), dd["t"])
    for i in incidents:
        d = dev(i.get("suspect_ip")) if (i["t"] or 0) >= since else None
        if d:
            d["incidents"] += 1
            if i["t"] and now - i["t"] < RISK_WINDOW and i["t"] > max(cleared_all, cleared.get(d["ip"], 0.0)):
                d["risk"], d["decision"] = i.get("score", 0), i.get("decision")
                d["attack"] = [a["id"] for a in i.get("attack") or []]
    for ip in fwm:
        d = dev(ip)
        if d and d["last"] is None:
            d["last"] = now
    for d in devices.values():
        d["responses"] = fwm.get(d["ip"], [])
        d["level"] = "high" if d["risk"] >= 100 else "medium" if d["risk"] >= 50 else "low" if d["risk"] > 0 else "none"
    active = [d for d in devices.values() if (d["last"] and now - d["last"] <= ACTIVE_WINDOW) or d["responses"]]
    active.sort(key=lambda d: (-(d["risk"] or 0), -(d["last"] or 0)))

    # Chuoi thoi gian: 30 cot x 1 phut
    start = int(now // 60) * 60 - (BUCKETS - 1) * 60
    series = {"web": [0] * BUCKETS, "threat": [0] * BUCKETS, "deceived": [0] * BUCKETS}

    def add(key, t):
        if t is None or t < start:
            return
        k = int((t - start) // 60)
        if 0 <= k < BUCKETS:
            series[key][k] += 1
    for w in web:
        if lab_ip(w["ip"]) and not w["path"].startswith("/api/health"):
            add("deceived" if w["kind"] == "honeypot" else "web", w["t"])
    for a in alerts:
        add("threat", a["t"])
    for h in hp:
        add("threat", h["t"])
    for u in auth:
        if u.get("kind") != "login_ok":
            add("threat", u["t"])
    labels = [datetime.fromtimestamp(start + 60 * k).strftime("%H:%M") for k in range(BUCKETS)]

    hour = now - 3600
    decided = {d.get("incident_id") for d in decisions}
    last_dec = {}
    for d in decisions:
        last_dec[d.get("ip")] = max(last_dec.get(d.get("ip"), ""), d.get("at", ""))
    latest = {}
    for i in incidents:
        if i.get("need_approval") and i.get("incident_id") not in decided and i.get("created_at", "") > last_dec.get(i.get("suspect_ip"), ""):
            latest[i["suspect_ip"]] = i
    pending = list(latest.values())

    techniques = {}
    for i in incidents:
        for a in i.get("attack") or []:
            techniques.setdefault(a["id"], {**a, "count": 0})["count"] += 1

    # Luong su kien gop (moi nhat truoc)
    feed = []
    for a in alerts[-80:]:
        feed.append({"t": a["t"], "type": "alert", "ip": suspect_of_alert(a), "title": f"SID {a['sid']}", "text": a["msg"], "meta": f"{a['src']} → {a['dst']}"})
    for h in hp[-60:]:
        meta = " · ".join(x for x in [h.get("user") and "user=" + h["user"], h.get("password") and "pass=" + h["password"],
                                      h.get("path"), h.get("port") and "cổng " + str(h["port"])] if x)
        feed.append({"t": h["t"], "type": "honeypot", "ip": h.get("src_ip"), "title": h.get("kind"), "text": meta, "meta": ""})
    for u in auth[-60:]:
        feed.append({"t": u["t"], "type": "auth", "ip": u.get("src_ip"), "title": u.get("kind"), "text": u.get("email", ""), "meta": ""})
    for i in incidents[-60:]:
        feed.append({"t": i["t"], "type": "incident", "ip": i.get("suspect_ip"), "title": i.get("decision"),
                     "text": f"điểm {i.get('score')}", "meta": ",".join(a["id"] for a in i.get("attack") or []), "id": i.get("incident_id")})
    for d in decisions[-30:]:
        feed.append({"t": d["t"], "type": "decision", "ip": d.get("ip"), "title": d.get("action"),
                     "text": (f"rule {d['rule']} · " if d.get("rule") else "") + d.get("result", ""), "meta": d.get("by", "")})
    for w in [w for w in web if lab_ip(w["ip"]) and not w["path"].startswith("/api/health")][-60:]:
        feed.append({"t": w["t"], "type": "web" if w["kind"] == "web" else "honeyweb", "ip": w["ip"],
                     "title": f"{w['method']} {w['status']}", "text": w["path"], "meta": w["ua"][:60]})
    feed = sorted([f for f in feed if f["t"]], key=lambda f: -f["t"])[:150]

    kpi = {
        "devices": len(active),
        "devices_5m": sum(1 for d in active if d["last"] and now - d["last"] <= 300),
        "alerts_1h": sum(1 for a in alerts if a["t"] and a["t"] >= hour),
        "incidents_1h": sum(1 for i in incidents if i["t"] and i["t"] >= hour),
        "pending": len(pending),
        "responses": sum(len(v) for v in fwm.values()),
        "honeypot_1h": sum(1 for h in hp if h["t"] and h["t"] >= hour),
        "auth_fail_1h": sum(1 for u in auth if u["t"] and u["t"] >= hour and u.get("kind") != "login_ok"),
        "web_1m": sum(1 for w in web if w["t"] >= now - 60 and lab_ip(w["ip"]) and not w["path"].startswith("/api/health")),
    }
    rules = rulegen_state(alerts)
    kpi["rules_pending"] = len(rules["pending"])
    kpi["rules_active"] = len(rules["active"])
    return {"now": now, "mode": mode_info(), "firewall": fw, "kpi": kpi, "devices": active, "pending": pending, "rules": rules,
            "series": series, "labels": labels, "feed": feed, "attack": list(techniques.values()),
            "honeypot": [h for h in hp[-30:]][::-1], "services": services(),
            "incidents": [{k: i.get(k) for k in ("incident_id", "created_at", "suspect_ip", "score", "decision", "attack", "need_approval")}
                          for i in incidents[-40:]][::-1]}


def ip_detail(ip):
    now = time.time()
    alerts, hp, auth, incidents, decisions, web = collect()
    st = fw_map(lab_block("status")).get(ip, [])
    events = []
    for a in alerts:
        if suspect_of_alert(a) == ip:
            events.append({"t": a["t"], "type": "alert", "title": f"SID {a['sid']}", "text": a["msg"]})
    for h in hp:
        if h.get("src_ip") == ip:
            events.append({"t": h["t"], "type": "honeypot", "title": h.get("kind"),
                           "text": " · ".join(str(h[k]) for k in ("user", "password", "path", "port", "data") if h.get(k))})
    for u in auth:
        if u.get("src_ip") == ip:
            events.append({"t": u["t"], "type": "auth", "title": u.get("kind"), "text": u.get("email", "")})
    for i in incidents:
        if i.get("suspect_ip") == ip:
            events.append({"t": i["t"], "type": "incident", "title": i.get("decision"), "text": f"điểm {i.get('score')}", "id": i.get("incident_id")})
    for d in decisions:
        if d.get("ip") == ip:
            events.append({"t": d["t"], "type": "decision", "title": d.get("action"), "text": d.get("result", "")})
    reqs = [w for w in web if w["ip"] == ip and not w["path"].startswith("/api/health")]
    for w in reqs[-60:]:
        events.append({"t": w["t"], "type": "web" if w["kind"] == "web" else "honeyweb", "title": f"{w['method']} {w['status']}", "text": w["path"]})
    events = sorted([e for e in events if e["t"]], key=lambda e: -e["t"])[:200]
    paths = {}
    for w in reqs:
        paths[w["path"].split("?")[0]] = paths.get(w["path"].split("?")[0], 0) + 1
    attack = {}
    for i in incidents:
        if i.get("suspect_ip") == ip:
            for a in i.get("attack") or []:
                attack[a["id"]] = a
    return {"ip": ip, "now": now, "responses": st, "events": events, "top_paths": sorted(paths.items(), key=lambda x: -x[1])[:8],
            "ua": reqs[-1]["ua"] if reqs else "", "attack": list(attack.values()),
            "counts": {"web": len(reqs), "alerts": sum(1 for e in events if e["type"] == "alert"),
                       "honeypot": sum(1 for e in events if e["type"] == "honeypot"), "auth": sum(1 for e in events if e["type"] == "auth")}}


def report(incident_id):
    incs = [i for i in jsonl(INC, 3_000_000) if i.get("incident_id") == incident_id]
    if not incs:
        return None
    i = incs[-1]
    e = html.escape
    decs = [d for d in jsonl(DEC) if d.get("incident_id") == incident_id or (d.get("ip") == i.get("suspect_ip") and d.get("at", "") >= i.get("created_at", ""))]
    rows = "".join(
        f"<tr><td>{e(str(s.get('ts', ''))[11:23])}</td><td>{e(str(s.get('source', '')))}</td><td>{e(str(s.get('sid')))}</td>"
        f"<td>{e(str(s.get('msg', '')))}</td><td>{e(str(s.get('attack', '')))}</td>"
        f"<td>{e(json.dumps(s.get('detail') or {}, ensure_ascii=False)) if s.get('detail') else e(str(s.get('http_url') or ''))}</td></tr>"
        for s in i.get("signals", []))
    att = "".join(f"<tr><td>{e(a['tactic'])}</td><td>{e(a['id'])}</td><td>{e(a['name'])}</td></tr>" for a in i.get("attack") or [])
    dec = "".join(f"<li>{e(d.get('at', ''))}: <b>{e(d.get('action', ''))}</b> bởi {e(d.get('by', ''))} — {e(d.get('result', ''))}</li>" for d in decs) or "<li>Chưa có quyết định của người vận hành.</li>"
    act = i.get("action") or {}
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Báo cáo sự cố {e(incident_id)}</title>
<style>body{{font-family:"Segoe UI",system-ui,Arial,sans-serif;max-width:960px;margin:30px auto;color:#111827;padding:0 20px}}
h1{{margin-bottom:4px}} .m{{color:#6b7280}} table{{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}}
td,th{{border:1px solid #e5e7eb;padding:7px;text-align:left;vertical-align:top}} th{{background:#f3f4f6}}
.k{{display:grid;grid-template-columns:220px 1fr;gap:6px 14px;margin:14px 0}} .k b{{color:#374151}}
.tag{{display:inline-block;padding:2px 10px;border-radius:999px;background:#ede9fe;color:#5b21b6;font-weight:700}}
@media print{{a{{display:none}}}}</style></head><body>
<a href="/">← Về dashboard</a>
<h1>Báo cáo sự cố {e(incident_id)}</h1><p class="m">Sinh tự động bởi Lab SOC · {e(datetime.now().strftime('%d/%m/%Y %H:%M:%S'))}</p>
<div class="k"><b>Thời điểm</b><span>{e(i.get('created_at', ''))}</span>
<b>Nghi phạm</b><span>{e(i.get('suspect_ip', ''))}</span>
<b>Mục tiêu</b><span>{e(i.get('target_ip', ''))} (Lab Shop)</span>
<b>Điểm rủi ro</b><span>{e(str(i.get('score')))} · tín hiệu không giả mạo được: {'có' if i.get('has_unspoofable_signal') else 'không'}</span>
<b>Quyết định của analyzer</b><span><span class="tag">{e(i.get('decision', ''))}</span> — {e(i.get('reason', ''))}</span>
<b>Hành động tự động</b><span>{e(act.get('cmd', 'không'))} {('→ ' + e(act.get('status', ''))) if act else ''}</span>
<b>Chế độ</b><span>{e(i.get('mode', ''))} / {e(i.get('response', ''))}</span></div>
<h2>MITRE ATT&amp;CK</h2><table><tr><th>Chiến thuật</th><th>Kỹ thuật</th><th>Tên</th></tr>{att}</table>
<h2>Dòng thời gian bằng chứng</h2><table><tr><th>Giờ</th><th>Nguồn</th><th>SID</th><th>Mô tả</th><th>ATT&amp;CK</th><th>Chi tiết</th></tr>{rows}</table>
<h2>Quyết định của người vận hành</h2><ul>{dec}</ul>
<h2>Đối chiếu bằng chứng gốc</h2><ul><li>Alert Suricata: <code>/var/log/suricata/eve.json</code> (community_id để tra PCAP)</li>
<li>Honeypot: <code>/var/log/lab-honeypot/events.jsonl</code> · truy cập bị đánh lừa: <code>/var/log/nginx/honeypot-access.log</code></li>
<li>Xác thực: <code>/var/log/lab-shop/auth.jsonl</code> · Web: <code>/var/log/nginx/access.log</code> · Firewall: <code>lab-block status</code></li></ul>
<p class="m">Dữ liệu do kẻ tấn công nhập được hiển thị nguyên văn sau khi escape; đây là dữ liệu trong lab cô lập.</p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LabSOC"
    sys_version = ""

    def allowed(self):
        if self.client_address[0] not in ALLOWED_CLIENTS:
            self.send_error(403)
            return False
        return True

    def send(self, code, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.allowed():
            return
        if self.path == "/":
            return self.send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if self.path == "/api/state":
            return self.send(200, json.dumps(state(), ensure_ascii=False), "application/json; charset=utf-8")
        if self.path.startswith("/api/ip/"):
            ip = self.path[len("/api/ip/"):]
            if not IP_RE.match(ip):
                return self.send(400, json.dumps({"error": "ip"}), "application/json")
            return self.send(200, json.dumps(ip_detail(ip), ensure_ascii=False), "application/json; charset=utf-8")
        if self.path.startswith("/report/"):
            r = report(self.path[len("/report/"):][:64])
            return self.send(200 if r else 404, r or "Không tìm thấy incident", "text/html; charset=utf-8")
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if not self.allowed():
            return
        if self.path != "/api/action" or self.headers.get("X-SOC-Token") != TOKEN:
            return self.send(403, json.dumps({"error": "forbidden"}), "application/json")
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 2048)
            req = json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self.send(400, json.dumps({"error": "bad request"}), "application/json")
        action, ip, inc = req.get("action"), str(req.get("ip", "")), str(req.get("incident_id", ""))[:64]
        if action in ("rule_approve", "rule_reject", "rule_revoke", "rulegen_run"):
            return self.rule_action(action, str(req.get("rule", ""))[:16])
        if not IP_RE.match(ip):
            return self.send(400, json.dumps({"error": "ip khong hop le"}), "application/json")
        mapping = {"approve_l2": [("add", "l2"), ("del", "dec")], "deceive": [("add", "dec")], "block_l1": [("add", "l1")],
                   "block_l2": [("add", "l2"), ("del", "dec")],
                   "unblock_all": [("del", "l1"), ("del", "l2"), ("del", "dec")], "dismiss": []}
        if action not in mapping:
            return self.send(400, json.dumps({"error": "hanh dong khong hop le"}), "application/json")
        results = [lab_block(op, lvl, ip) for op, lvl in mapping[action]]
        ok_msgs = [r.get("msg", "") for r in results if r.get("rc") == 0]
        err_msgs = [r.get("msg", "") for r in results if r.get("rc") not in (0, 1)]
        summary = "; ".join(ok_msgs or err_msgs or [r.get("msg", "") for r in results]) or "chi ghi nhan"
        ok = action == "dismiss" or bool(ok_msgs)
        rec = {"at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"), "incident_id": inc,
               "ip": ip, "action": action, "by": f"nguoi van hanh ({self.client_address[0]})", "result": summary, "ok": ok}
        with open(DEC, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send(200, json.dumps(rec, ensure_ascii=False), "application/json; charset=utf-8")

    def rule_action(self, action, rule):
        """Duyet / tu choi / thu hoi rule tu sinh. Nap that su do lab-rule (root) lam, sau khi tu kiem tra lai."""
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        by = f"nguoi van hanh ({self.client_address[0]})"
        ok, summary = False, ""
        if action == "rulegen_run":
            try:
                open(RG_TRIGGER, "w").close()
                ok, summary = True, "đã yêu cầu lab-rulegen phân tích ngay"
            except OSError as e:
                summary = f"khong tao duoc trigger: {e}"
        elif action in ("rule_approve", "rule_reject"):
            if not re.fullmatch(r"R5\d{6}", rule):
                return self.send(400, json.dumps({"error": "ma phieu khong hop le"}), "application/json")
            if action == "rule_approve":
                res = lab_rule("apply", rule)
                ok, summary = res.get("rc") == 0, res.get("msg", "")
                new_status = "approved" if ok else None
            else:
                ok, summary, new_status = True, "đã từ chối phiếu", "rejected"

            def mark(props):
                for p in props:
                    if p.get("id") == rule and p.get("status") == "pending" and new_status:
                        p.update(status=new_status, decided_at=now, decided_by=by)
                        return True
                return False
            if new_status and not update_proposals(mark) and action == "rule_reject":
                ok, summary = False, "phiếu không ở trạng thái chờ duyệt"
        else:  # rule_revoke
            if not re.fullmatch(r"5\d{6}", rule):
                return self.send(400, json.dumps({"error": "sid khong hop le"}), "application/json")
            res = lab_rule("revoke", rule)
            ok, summary = res.get("rc") == 0, res.get("msg", "")
            if ok:
                def mark(props):
                    for p in props:
                        if p.get("sid") == int(rule) and p.get("status") == "approved":
                            p.update(status="revoked", decided_at=now, decided_by=by)
                update_proposals(mark)
        rec = {"at": now, "incident_id": "", "ip": "", "rule": rule, "action": action, "by": by, "result": summary, "ok": ok}
        with open(DEC, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send(200, json.dumps(rec, ensure_ascii=False), "application/json; charset=utf-8")

    def log_message(self, *a):
        pass


PAGE = r"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Lab SOC</title>
<style>
:root{--bg:#0b0a1f;--bg2:#120f2e;--panel:#1a1640;--panel2:#221d52;--line:#2e2866;--text:#ecebff;--mute:#9b97c9;--dim:#6e6aa3;
--brand:#6d5df6;--brand2:#8b5cf6;--cyan:#22d3ee;--green:#34d399;--amber:#fbbf24;--red:#fb7185;--pink:#e879f9;--orange:#fb923c;
--r:16px;--sh:0 10px 30px rgba(0,0,0,.35)}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#2a1f6e 0%,transparent 60%),var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
a{color:#b6abff}button{font:inherit}
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
/* Sidebar */
.side{position:sticky;top:0;height:100vh;padding:22px 16px;background:linear-gradient(180deg,#151235,#100d29);border-right:1px solid var(--line);display:flex;flex-direction:column;gap:18px}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:19px;letter-spacing:.3px;padding:0 6px}
.logo .mk{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,var(--brand),var(--pink));box-shadow:0 6px 18px rgba(109,93,246,.45)}
.navt{font-size:11px;letter-spacing:1.4px;text-transform:uppercase;color:var(--dim);padding:0 10px;margin-top:6px}
.nav{display:flex;flex-direction:column;gap:4px}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:12px;color:var(--mute);text-decoration:none;font-weight:600}
.nav a:hover{background:var(--panel);color:var(--text)}
.nav a.on{background:linear-gradient(90deg,var(--brand),var(--brand2));color:#fff;box-shadow:0 8px 20px rgba(109,93,246,.35)}
.nav .cnt{margin-left:auto;font-size:11px;padding:1px 8px;border-radius:999px;background:var(--panel2);color:var(--text)}
.nav a.on .cnt{background:rgba(255,255,255,.22)}
.svc{margin-top:auto;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px}
.svc h4{margin:0 0 10px;font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:1px}
.svc .it{display:flex;align-items:center;gap:8px;font-size:12.5px;padding:3px 0}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px rgba(52,211,153,.15)}
.dot.off{background:var(--red);box-shadow:0 0 0 3px rgba(251,113,133,.15)}
/* Main */
.main{padding:20px 26px 40px;min-width:0}
.top{display:flex;align-items:center;gap:12px;background:rgba(26,22,64,.75);backdrop-filter:blur(8px);border:1px solid var(--line);border-radius:var(--r);padding:10px 14px;position:sticky;top:12px;z-index:20}
.search{flex:1;max-width:420px;display:flex;align-items:center;gap:8px;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:8px 12px;color:var(--mute)}
.search input{flex:1;background:none;border:0;outline:0;color:var(--text);font:inherit}
.chip{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:999px;border:1px solid var(--line);background:var(--bg2);font-size:12px;font-weight:700;white-space:nowrap}
.live{color:var(--green)}.live i{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 1.6s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.6)}70%{box-shadow:0 0 0 8px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
.chip.warn{color:var(--amber);border-color:#5a4a1a}.chip.ok{color:var(--green)}
h1{font-size:26px;margin:22px 4px 14px}
.sub{color:var(--mute);margin:-8px 4px 18px}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}
.c3{grid-column:span 3}.c4{grid-column:span 4}.c5{grid-column:span 5}.c7{grid-column:span 7}.c8{grid-column:span 8}.c12{grid-column:span 12}
@media(max-width:1280px){.c3{grid-column:span 6}.c4,.c5,.c7,.c8{grid-column:span 12}}
@media(max-width:860px){.app{grid-template-columns:1fr}.side{display:none}.c3{grid-column:span 12}}
.card{background:linear-gradient(180deg,var(--panel),#161238);border:1px solid var(--line);border-radius:var(--r);padding:18px;box-shadow:var(--sh);min-width:0}
.card h3{margin:0;font-size:16px}.card .hd{display:flex;align-items:center;gap:10px;margin-bottom:14px}.card .hd .sp{flex:1}
.muted{color:var(--mute)}.dim{color:var(--dim)}
/* KPI */
.kpi{border-radius:var(--r);padding:16px 18px;color:#fff;position:relative;overflow:hidden;box-shadow:var(--sh);min-height:132px}
.kpi::after{content:"";position:absolute;right:-30px;top:-30px;width:130px;height:130px;border-radius:50%;background:rgba(255,255,255,.08)}
.k1{background:linear-gradient(135deg,#5b4cf0,#7c5cf6)}.k2{background:linear-gradient(135deg,#1aa0e8,#3fc7f0)}
.k3{background:linear-gradient(135deg,#8b3cf0,#c040e8)}.k4{background:linear-gradient(135deg,#d946ef,#f472b6)}
.kpi .t{display:flex;align-items:center;gap:9px;font-weight:600;opacity:.95}.kpi .ic{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:rgba(255,255,255,.18)}
.kpi .v{font-size:34px;font-weight:800;margin-top:10px;line-height:1}.kpi .s{opacity:.85;font-size:12.5px;margin-top:4px}
.kpi svg.spark{position:absolute;right:16px;top:52px;width:96px;height:36px;opacity:.95}
.kpi .s{position:relative;z-index:1}
/* chart */
.legend{display:flex;gap:14px;font-size:12px;color:var(--mute)}.legend b{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
#chart{position:relative}#chart svg{width:100%;height:260px;display:block}
.tip{position:absolute;pointer-events:none;background:#0f0c26;border:1px solid var(--line);border-radius:10px;padding:8px 10px;font-size:12px;white-space:nowrap;box-shadow:var(--sh);display:none}
/* action panel */
.pend{border:1px solid #6b2a4a;background:linear-gradient(180deg,#3a1630,#2a1230);border-radius:14px;padding:12px;margin-bottom:10px}
.btn{border:0;border-radius:10px;padding:8px 12px;font-weight:700;cursor:pointer;transition:transform .1s, filter .1s}
.btn:hover{filter:brightness(1.1)}.btn:active{transform:scale(.97)}.btn:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.b-red{background:var(--red);color:#2a0710}.b-vio{background:var(--brand2);color:#fff}.b-ghost{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
.b-amber{background:var(--amber);color:#2a1d00}
.resp{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--line)}.resp:last-child{border:0}
/* table */
table{width:100%;border-collapse:collapse}th{font-size:11.5px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);text-align:left;font-weight:700;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:11px 10px;border-bottom:1px solid rgba(46,40,102,.55);vertical-align:middle}
tr.row{cursor:pointer}tr.row:hover td{background:rgba(109,93,246,.08)}
.ipb{display:flex;align-items:center;gap:10px}.av{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;font-weight:800;font-size:12px;background:var(--panel2);border:1px solid var(--line)}
.risk{width:110px;height:7px;border-radius:5px;background:var(--panel2);overflow:hidden}.risk i{display:block;height:100%;border-radius:5px}
.st{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700}
.st.none{background:rgba(52,211,153,.12);color:var(--green)}.st.low{background:rgba(34,211,238,.12);color:var(--cyan)}
.st.medium{background:rgba(251,191,36,.14);color:var(--amber)}.st.high{background:rgba(251,113,133,.15);color:var(--red)}
.st.dec{background:rgba(232,121,249,.15);color:var(--pink)}.st.blk{background:rgba(251,113,133,.2);color:#fecdd3}
.n{font-variant-numeric:tabular-nums}
.empty{padding:28px;text-align:center;color:var(--mute)}
/* feed */
.tabs{display:flex;gap:6px;flex-wrap:wrap}.tab{padding:6px 11px;border-radius:999px;background:var(--bg2);border:1px solid var(--line);color:var(--mute);cursor:pointer;font-size:12.5px;font-weight:600}
.tab.on{background:var(--brand);border-color:var(--brand);color:#fff}
.feed{max-height:470px;overflow:auto;margin-top:12px;padding-right:4px}
.ev{display:grid;grid-template-columns:62px 26px 1fr;gap:10px;padding:9px 4px;border-bottom:1px solid rgba(46,40,102,.55);align-items:start}
.ev .ti{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums;padding-top:2px}
.ev .ico{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;font-size:13px}
.ev .bd{min-width:0}.ev .bd b{font-weight:700}.ev .bd .tx{color:var(--mute);word-break:break-word;font-size:13px}
.ty-alert .ico{background:rgba(251,191,36,.15)}.ty-honeypot .ico,.ty-honeyweb .ico{background:rgba(232,121,249,.15)}
.ty-auth .ico{background:rgba(251,146,60,.15)}.ty-incident .ico{background:rgba(109,93,246,.2)}.ty-decision .ico{background:rgba(52,211,153,.15)}.ty-web .ico{background:rgba(34,211,238,.12)}
.ipl{color:#c4bcff;font-weight:700;cursor:pointer}
/* attack */
.mx{display:flex;flex-direction:column;gap:10px}
.mx .col{display:grid;grid-template-columns:150px 1fr;gap:10px;align-items:start;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.mx .col b{font-size:12px;letter-spacing:.4px;color:var(--mute);padding-top:5px}
.mx .tes{display:flex;flex-wrap:wrap;gap:6px}
.mx .te{font-size:12.5px;padding:5px 9px;border-radius:8px;background:linear-gradient(90deg,rgba(251,113,133,.25),rgba(232,121,249,.15));border:1px solid rgba(251,113,133,.35)}
.mx .te.zero{background:none;border:1px dashed var(--line);color:var(--dim)}
/* drawer */
.ov{position:fixed;inset:0;background:rgba(5,4,15,.55);backdrop-filter:blur(2px);display:none;z-index:40}
.dr{position:fixed;top:0;right:0;height:100vh;width:min(560px,100vw);background:#120f2e;border-left:1px solid var(--line);z-index:41;transform:translateX(100%);transition:transform .25s ease;display:flex;flex-direction:column}
.dr.open{transform:none}.ov.open{display:block}
.dr .dh{padding:20px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}
.dr .db{padding:18px 20px;overflow:auto;flex:1}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}.stats div{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center}
.stats b{display:block;font-size:20px}.stats span{font-size:11.5px;color:var(--mute)}
.acts{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 16px}
/* toast */
.toasts{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;z-index:60}
.toast{background:#1d1848;border:1px solid var(--line);border-left:4px solid var(--brand2);border-radius:12px;padding:12px 14px;box-shadow:var(--sh);min-width:280px;animation:in .25s ease}
.toast.red{border-left-color:var(--red)}.toast.pink{border-left-color:var(--pink)}
@keyframes in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
::-webkit-scrollbar{width:8px}::-webkit-scrollbar-thumb{background:var(--line);border-radius:8px}
.rgrid{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}@media(max-width:1100px){.rgrid{grid-template-columns:1fr}}
.rgrid h4{margin:0 0 8px;display:flex;align-items:center;gap:8px}
.gt{display:inline-flex;gap:4px;align-items:center;padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:700;margin:2px 4px 2px 0;cursor:help}
.gt.ok{background:rgba(52,211,153,.14);color:#6ee7b7}.gt.no{background:rgba(251,113,133,.15);color:#fda4af}
code.rc{display:block;white-space:pre-wrap;word-break:break-all;background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:8px 10px;font-size:11.5px;color:#c4bcff;margin-top:8px}
</style></head><body>
<div class="app">
<aside class="side" aria-label="Điều hướng">
  <div class="logo"><span class="mk">🛡️</span>Lab SOC</div>
  <div class="navt">Giám sát</div>
  <nav class="nav">
    <a href="#overview" class="on">▦ Tổng quan</a>
    <a href="#devices">🖥 Thiết bị <span class="cnt" id="nav-dev">0</span></a>
    <a href="#events">⚡ Sự kiện</a>
    <a href="#honeypot">🍯 Honeypot</a>
    <a href="#attack">🎯 MITRE ATT&amp;CK</a>
  </nav>
  <div class="navt">Phản ứng</div>
  <nav class="nav">
    <a href="#actions">🛑 Cần xử lý <span class="cnt" id="nav-pend">0</span></a>
    <a href="#rules">🧬 Rule tự sinh <span class="cnt" id="nav-rule">0</span></a>
    <a href="#incidents">📄 Sự cố &amp; báo cáo</a>
  </nav>
  <div class="svc"><h4>Dịch vụ trên B</h4><div id="svc"></div></div>
</aside>
<main class="main">
  <div class="top">
    <label class="search">🔍<input id="q" placeholder="Lọc theo IP, đường dẫn, SID, kiểu sự kiện…" aria-label="Tìm kiếm"></label>
    <span style="flex:1"></span>
    <span class="chip live"><i></i>Thời gian thực</span>
    <span class="chip" id="mode"></span>
    <span class="chip" id="clock">--:--:--</span>
  </div>

  <h1 id="overview">Tổng quan an ninh</h1>
  <p class="sub">Máy chủ Lab Shop <b>10.77.0.20</b> · thiết bị chỉ hiện khi có hoạt động trong 30 phút gần nhất · cập nhật mỗi 2 giây</p>

  <div class="grid">
    <div class="kpi k1 c3"><div class="t"><span class="ic">🖥</span>Thiết bị hoạt động</div><div class="v n" id="k-dev">0</div><div class="s" id="k-dev-s"></div><svg class="spark" id="sp-web"></svg></div>
    <div class="kpi k2 c3"><div class="t"><span class="ic">⚠</span>Cảnh báo (1 giờ)</div><div class="v n" id="k-al">0</div><div class="s" id="k-al-s"></div><svg class="spark" id="sp-th"></svg></div>
    <div class="kpi k3 c3"><div class="t"><span class="ic">🍯</span>Tương tác honeypot (1 giờ)</div><div class="v n" id="k-hp">0</div><div class="s" id="k-hp-s"></div><svg class="spark" id="sp-dc"></svg></div>
    <div class="kpi k4 c3"><div class="t"><span class="ic">🛑</span>Đang phản ứng</div><div class="v n" id="k-rs">0</div><div class="s" id="k-rs-s"></div></div>

    <section class="card c8"><div class="hd"><h3>Hoạt động 30 phút gần nhất</h3><span class="sp"></span>
      <div class="legend"><span><b style="background:var(--cyan)"></b>Truy cập web</span><span><b style="background:var(--red)"></b>Dấu hiệu tấn công</span><span><b style="background:var(--pink)"></b>Bị đánh lừa</span></div></div>
      <div id="chart"><svg viewBox="0 0 800 260" preserveAspectRatio="none" aria-label="Biểu đồ hoạt động"></svg><div class="tip" id="tip"></div></div>
    </section>

    <section class="card c4" id="actions"><div class="hd"><h3>Cần xử lý</h3><span class="sp"></span><span class="chip" id="pend-c">0</span></div>
      <div id="pending"></div>
      <div class="hd" style="margin:14px 0 6px"><h3>Phản ứng đang hiệu lực</h3></div><div id="active"></div>
    </section>

    <section class="card c12" id="devices"><div class="hd"><h3>Thiết bị đang hoạt động</h3><span class="dim">· số liệu trong 30 phút gần nhất · bấm vào thiết bị để xem chi tiết</span><span class="sp"></span><span class="muted" id="dev-c"></span></div>
      <div style="overflow:auto"><table><thead><tr><th>Thiết bị</th><th>Hoạt động</th><th>Web</th><th>Cảnh báo</th><th>Honeypot</th><th>Đăng nhập lỗi</th><th>Rủi ro</th><th>Trạng thái</th></tr></thead><tbody id="dev"></tbody></table></div>
    </section>

    <section class="card c12" id="rules"><div class="hd"><h3>🧬 Rule tự sinh (lab-rulegen)</h3><span class="dim">· học từ hành vi của kẻ tấn công đã bị honeypot xác nhận · chỉ nạp khi người vận hành duyệt</span><span class="sp"></span><button class="btn b-vio" data-ract="rulegen_run">Phân tích ngay</button></div>
      <div class="rgrid"><div><h4>Đề xuất chờ duyệt <span class="chip" id="rp-c">0</span></h4><div id="rp"></div>
        <h4 style="margin-top:16px">Lần phân tích gần nhất</h4><div id="rlast"></div></div>
      <div><h4>Rule đang chạy <span class="chip" id="ra-c">0</span></h4><div id="ra"></div>
        <h4 style="margin-top:16px">Lịch sử phiếu</h4><div id="rh"></div></div></div>
    </section>

    <section class="card c7" id="events"><div class="hd"><h3>Luồng sự kiện</h3><span class="sp"></span></div>
      <div class="tabs" id="tabs"></div><div class="feed" id="feed" aria-live="polite"></div>
    </section>

    <section class="card c5" id="attack"><div class="hd"><h3>MITRE ATT&amp;CK đã quan sát</h3></div><div class="mx" id="mx"></div></section>

    <section class="card c7" id="honeypot"><div class="hd"><h3>Kẻ tấn công làm gì trong honeypot</h3></div>
      <div style="overflow:auto;max-height:340px"><table><thead><tr><th>Giờ</th><th>IP</th><th>Hành vi</th><th>Chi tiết</th></tr></thead><tbody id="hp"></tbody></table></div></section>

    <section class="card c5" id="incidents"><div class="hd"><h3>Sự cố gần đây</h3><span class="sp"></span><span class="dim">bấm để mở báo cáo</span></div>
      <div style="overflow:auto;max-height:340px"><table><tbody id="incs"></tbody></table></div></section>
  </div>
</main>
</div>
<div class="ov" id="ov"></div>
<aside class="dr" id="dr" aria-label="Chi tiết thiết bị"><div class="dh"><div class="av" id="dr-av"></div><div><div style="font-size:18px;font-weight:800" id="dr-ip"></div><div class="muted" id="dr-ua"></div></div><span style="flex:1"></span><button class="btn b-ghost" id="dr-x" aria-label="Đóng">✕</button></div><div class="db" id="dr-b"></div></aside>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<script>
const TOKEN="__TOKEN__";
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtT=t=>t?new Date(t*1000).toLocaleTimeString("vi-VN",{hour12:false}):"";
const ago=(t,now)=>{if(!t)return"—";const s=Math.max(0,Math.round(now-t));return s<60?s+" giây trước":s<3600?Math.round(s/60)+" phút trước":Math.round(s/3600)+" giờ trước"};
const DEC={log:"ghi nhận",incident_medium:"Sự cố",incident_high_spoof_suspect:"Nghi giả mạo · không chặn",incident_high_protected:"Được bảo vệ",
 recommend_only_out_of_scope:"Ngoài phạm vi",recommend_block_l1:"Đề xuất chặn",block_l1:"Chặn web 60s",already_blocked:"Đang chặn",
 recommend_deceive:"Đề xuất đánh lừa",deceive:"Đánh lừa → honeypot",attacker_engaged:"Cắn câu · chờ duyệt"};
const KIND={honeyport_connect:"Kết nối cổng bẫy",honeypot_admin_view:"Xem trang admin giả",honeypot_admin_login:"Thử đăng nhập admin giả",
 honeytoken_creds:"Dùng tài khoản bẫy",honeytoken_api_key:"Dùng API key bẫy",honeytoken_file:"Tải file sao lưu bẫy",
 login_fail:"Đăng nhập sai",login_ok:"Đăng nhập thành công",login_locked:"Bị khóa do sai nhiều lần",login_invalid_input:"Dữ liệu đăng nhập bất thường",
 approve_l2:"Duyệt chặn toàn bộ",block_l2:"Chặn toàn bộ",block_l1:"Chặn web",deceive:"Đánh lừa",unblock_all:"Gỡ chặn",dismiss:"Bỏ qua",
 reset_lab:"Đặt lại hệ thống (reset-lab)",rule_approve:"Duyệt & nạp rule tự sinh",rule_reject:"Từ chối rule tự sinh",rule_revoke:"Thu hồi rule tự sinh",rulegen_run:"Yêu cầu phân tích rule"};
const GATES=[["G1","Cú pháp"],["G2","Bắt được"],["G3","Không bắt nhầm"],["G4","An toàn"],["G5","Không trùng"]];
const RST={approved:["none","Đã nạp"],rejected:["medium","Từ chối"],revoked:["low","Thu hồi"],failed_gate:["high","Trượt kiểm chứng"]};
const TYPE={alert:["⚠","Cảnh báo"],honeypot:["🍯","Honeypot"],honeyweb:["🎭","Web bị đánh lừa"],auth:["🔑","Xác thực"],incident:["🧠","Analyzer"],decision:["✅","Người vận hành"],web:["🌐","Web"]};
const TACTICS=["Reconnaissance","Discovery","Initial Access","Credential Access","Collection"];
const TACT_VI={"Reconnaissance":"Trinh sát","Discovery":"Khám phá","Initial Access":"Xâm nhập ban đầu","Credential Access":"Đánh cắp thông tin xác thực","Collection":"Thu thập"};
let S=null,tab="all",seenInc=null,openIp=null,seenRule=null;

function toast(msg,cls=""){const d=document.createElement("div");d.className="toast "+cls;d.innerHTML=msg;$("toasts").appendChild(d);setTimeout(()=>d.remove(),6000)}
async function act(action,ip,inc){
  const L={approve_l2:"chặn TOÀN BỘ kết nối của "+ip+" trong 10 phút",block_l2:"chặn TOÀN BỘ kết nối của "+ip+" trong 10 phút",block_l1:"chặn web của "+ip+" trong 60 giây",deceive:"đưa "+ip+" vào honeypot 10 phút",unblock_all:"gỡ mọi phản ứng với "+ip,dismiss:"bỏ qua yêu cầu này"};
  if(action!=="dismiss"&&!confirm("Xác nhận: "+L[action]+"?"))return;
  try{const r=await fetch("/api/action",{method:"POST",headers:{"Content-Type":"application/json","X-SOC-Token":TOKEN},body:JSON.stringify({action,ip,incident_id:inc||""})});
    const j=await r.json();toast(`<b>${esc(KIND[action]||action)}</b> · ${esc(ip)}<div class="muted">${esc(j.result||j.error)}</div>`,j.ok?"":"red");}
  catch(e){toast("Không gửi được lệnh","red")}
  load();if(openIp)openDetail(openIp);
}
async function ruleAct(action,rule){
  const L={rule_approve:"NẠP rule "+rule+" vào Suricata (nạp nóng, không dừng giám sát)",rule_reject:"TỪ CHỐI phiếu "+rule+" — sẽ KHÔNG bao giờ được đề xuất lại",rule_revoke:"THU HỒI rule "+rule+" — gỡ ngay; nếu kẻ tấn công dò lại sau đó thì hệ thống sẽ đề xuất lại"};
  if(L[action]&&!confirm("Xác nhận: "+L[action]+"?"))return;
  if(action==="rule_approve")toast(`<b>Đang kiểm tra lại và nạp ${esc(rule)}…</b><div class="muted">suricata -T rồi reload-rules</div>`);
  try{const r=await fetch("/api/action",{method:"POST",headers:{"Content-Type":"application/json","X-SOC-Token":TOKEN},body:JSON.stringify({action,rule:rule||""})});
    const j=await r.json();toast(`<b>${esc(KIND[action]||action)}</b>${rule?" · "+esc(rule):""}<div class="muted">${esc(j.result||j.error)}</div>`,j.ok?"":"red")}
  catch(e){toast("Không gửi được lệnh","red")}
  load();
}
function renderRules(d){
  const R=d.rules||{pending:[],active:[],history:[],last_run:{}},now=d.now;
  $("nav-rule").textContent=R.pending.length;$("rp-c").textContent=R.pending.length+" chờ duyệt";$("ra-c").textContent=R.active.length+" rule";
  const gates=g=>GATES.map(([k,n])=>{const x=(g||{})[k]||{};return `<span class="gt ${x.ok?"ok":"no"}" title="${esc(x.detail||"")}">${x.ok?"✓":"✗"} ${k} ${n}</span>`}).join("");
  const kindL=k=>k==="ua"?"User-Agent công cụ quét":"Đường dẫn dò quét";
  $("rp").innerHTML=R.pending.length?R.pending.map(p=>`<div class="pend"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b class="n">#${p.sid}</b><span class="st dec">${kindL(p.kind)}</span><code style="color:#fff;font-weight:700;font-size:14px">${esc(p.content)}</code><span class="dim" style="margin-left:auto">${esc(String(p.created_at).slice(11,19))}</span></div>
     <div class="muted" style="margin:6px 0;font-size:13px">Học từ <b>${p.support}</b> mẫu của ${(p.attackers||[]).map(ip=>`<b class="ipl" data-ip="${esc(ip)}">${esc(ip)}</b>`).join(", ")}: ${(p.samples||[]).slice(0,4).map(s=>`<code>${esc(s)}</code>`).join(" · ")}</div>
     <div>${gates(p.gates)}</div>
     <details><summary class="dim" style="cursor:pointer;margin-top:6px">Xem rule Suricata</summary><code class="rc">${esc(p.rule)}</code></details>
     <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn b-vio" data-ract="rule_approve" data-rule="${esc(p.id)}">Duyệt &amp; nạp</button><button class="btn b-ghost" data-ract="rule_reject" data-rule="${esc(p.id)}">Từ chối</button></div></div>`).join("")
     :`<div class="empty">✓ Không có rule nào chờ duyệt</div>`;
  $("ra").innerHTML=R.active.length?`<table><thead><tr><th>SID</th><th>Đặc trưng</th><th>Khớp gần đây</th><th></th></tr></thead><tbody>${R.active.map(r=>`<tr><td class="n">${r.sid}</td><td><span class="dim" style="font-size:11px">${r.kind==="ua"?"UA":"URI"}</span> <code style="color:#c4bcff">${esc(r.content)}</code></td><td class="n">${r.hits}${r.last_hit?` <span class="dim">· ${ago(r.last_hit,now)}</span>`:""}</td><td style="text-align:right"><button class="btn b-ghost" data-ract="rule_revoke" data-rule="${r.sid}">Thu hồi</button></td></tr>`).join("")}</tbody></table>`
     :`<div class="empty">Chưa có rule tự sinh nào đang chạy</div>`;
  const L=R.last_run||{},atk=Object.entries(L.attackers||{});
  $("rlast").innerHTML=L.run_at?`<div class="muted" style="font-size:13px;line-height:1.75">Lúc <b>${esc(String(L.run_at).slice(11,19))}</b> · kẻ tấn công đã xác nhận: ${atk.length?atk.map(([ip,v])=>`<b class="ipl" data-ip="${esc(ip)}">${esc(ip)}</b> <span class="dim">(${v.confidence==="high"?"tin cậy cao":"trung bình"} · ${esc(v.why)})</span>`).join(", "):"không có"}<br>
     <b>${L.attack_samples||0}</b> request tấn công · <b>${L.uncovered_samples||0}</b> chưa rule nào bắt · <b>${L.distinct_paths||0}</b> đường dẫn lạ · so với <b>${L.benign_uris||0}</b> đường dẫn hợp lệ${L.note?`<br><span class="dim">${esc(L.note)}</span>`:""}</div>
     ${(L.rejected||[]).length?`<div class="dim" style="font-size:12px;margin:8px 0 4px">Ứng viên bị loại (chống báo nhầm / đầu độc luật):</div>${L.rejected.map(r=>`<div style="display:flex;gap:10px;font-size:12.5px;padding:2px 0"><code style="color:#fda4af;min-width:110px">${esc(r.candidate)}</code><span class="muted">${esc(r.reason)}</span></div>`).join("")}`:""}`
     :`<div class="empty">lab-rulegen chưa chạy lần nào</div>`;
  $("rh").innerHTML=R.history.length?R.history.map(p=>{const[c,t]=RST[p.status]||["none",p.status];return `<div style="display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);font-size:13px"><span class="st ${c}">${t}</span><span class="dim n">#${p.sid}</span><code style="color:#c4bcff">${esc(p.content)}</code><span class="dim" style="margin-left:auto">${esc(String(p.decided_at||p.created_at).slice(11,19))}</span></div>`}).join("")
     :`<div class="empty" style="padding:12px">Chưa có</div>`;
  if(seenRule===null)seenRule=new Set(R.pending.map(p=>p.id));
  else for(const p of R.pending)if(!seenRule.has(p.id)){seenRule.add(p.id);toast(`<b>🧬 Rule mới chờ duyệt · #${p.sid}</b><div class="muted">${esc(p.content)} · học từ ${p.support} mẫu</div>`,"pink")}
}
function spark(id,arr,color){const el=$(id);if(!el)return;const w=120,h=40,m=Math.max(1,...arr);const pts=arr.map((v,i)=>[i*(w/(arr.length-1)),h-3-(v/m)*(h-8)]);
  const d="M"+pts.map(p=>p.join(",")).join(" L");el.setAttribute("viewBox",`0 0 ${w} ${h}`);
  el.innerHTML=`<path d="${d} L${w},${h} L0,${h}Z" fill="rgba(255,255,255,.18)"/><path d="${d}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>`}
function smooth(pts){if(pts.length<2)return"";let d=`M${pts[0][0]},${pts[0][1]}`;for(let i=1;i<pts.length;i++){const[x0,y0]=pts[i-1],[x1,y1]=pts[i],cx=(x0+x1)/2;d+=` C${cx},${y0} ${cx},${y1} ${x1},${y1}`}return d}
function chart(){
  const svg=document.querySelector("#chart svg"),W=800,H=260,P={l:34,r:10,t:14,b:26},s=S.series,L=S.labels,n=L.length;
  const max=Math.max(4,...s.web,...s.threat,...s.deceived),sc=v=>H-P.b-(v/max)*(H-P.t-P.b),x=i=>P.l+i*((W-P.l-P.r)/(n-1));
  let g="";for(let k=0;k<=4;k++){const v=Math.round(max*k/4),y=sc(v);g+=`<line x1="${P.l}" x2="${W-P.r}" y1="${y}" y2="${y}" stroke="#2e2866" stroke-dasharray="3 5"/><text x="${P.l-8}" y="${y+4}" fill="#6e6aa3" font-size="10" text-anchor="end">${v}</text>`}
  for(let i=0;i<n;i+=5)g+=`<text x="${x(i)}" y="${H-6}" fill="#6e6aa3" font-size="10" text-anchor="middle">${esc(L[i])}</text>`;
  const area=(arr,c,id)=>{const p=arr.map((v,i)=>[x(i),sc(v)]),d=smooth(p);return `<defs><linearGradient id="${id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${c}" stop-opacity=".45"/><stop offset="1" stop-color="${c}" stop-opacity="0"/></linearGradient></defs><path d="${d} L${x(n-1)},${H-P.b} L${x(0)},${H-P.b}Z" fill="url(#${id})"/><path d="${d}" fill="none" stroke="${c}" stroke-width="2.4"/>`};
  g+=area(s.web,"#22d3ee","gw")+area(s.deceived,"#e879f9","gd")+area(s.threat,"#fb7185","gt");
  g+=`<line id="hl" y1="${P.t}" y2="${H-P.b}" stroke="#9b97c9" stroke-width="1" opacity="0"/>`;
  for(let i=0;i<n;i++)g+=`<rect x="${x(i)-(W/n)/2}" y="0" width="${W/n}" height="${H}" fill="transparent" data-i="${i}"/>`;
  svg.innerHTML=g;
  svg.querySelectorAll("rect").forEach(r=>{r.onmouseenter=e=>{const i=+r.dataset.i,t=$("tip"),hl=svg.querySelector("#hl");hl.setAttribute("x1",x(i));hl.setAttribute("x2",x(i));hl.setAttribute("opacity",".5");
    t.style.display="block";t.innerHTML=`<b>${esc(L[i])}</b><br><span style="color:#22d3ee">● Web: ${s.web[i]}</span><br><span style="color:#fb7185">● Tấn công: ${s.threat[i]}</span><br><span style="color:#e879f9">● Đánh lừa: ${s.deceived[i]}</span>`;
    const box=$("chart").getBoundingClientRect(),px=(x(i)/W)*box.width;t.style.left=Math.min(px+12,box.width-150)+"px";t.style.top="10px"}});
  svg.onmouseleave=()=>{$("tip").style.display="none";const hl=svg.querySelector("#hl");if(hl)hl.setAttribute("opacity","0")};
}
function stChip(d){if(d.responses&&d.responses.length)return d.responses.map(r=>`<span class="st ${r.level==="dec"?"dec":"blk"}">● ${esc(r.label)} · ${esc(r.expires)}</span>`).join(" ");
  const t={none:"Bình thường",low:"Theo dõi",medium:"Đáng ngờ",high:"Nguy cơ cao"}[d.level];return `<span class="st ${d.level}">● ${t}</span>`}
const riskCol=v=>v>=100?"var(--red)":v>=50?"var(--amber)":v>0?"var(--cyan)":"var(--green)";
function q(){return $("q").value.trim().toLowerCase()}
function render(){
  const d=S,k=d.kpi,now=d.now,f=q();
  $("clock").textContent=new Date(now*1000).toLocaleTimeString("vi-VN",{hour12:false});
  const m=$("mode");m.textContent=`${d.mode.MODE==="apply"?"Tự động":"Chỉ đề xuất"} · ${d.mode.RESPONSE==="deceive"?"đánh lừa trước":"chặn ngay"}`;m.className="chip "+(d.mode.MODE==="apply"?"warn":"ok");
  $("svc").innerHTML=d.services.map(s=>`<div class="it"><span class="dot ${s.active?"":"off"}"></span>${esc(s.name)}<span style="margin-left:auto" class="${s.active?"muted":""}">${s.active?"chạy":"DỪNG"}</span></div>`).join("");
  $("k-dev").textContent=k.devices;$("k-dev-s").textContent=`${k.devices_5m} hoạt động trong 5 phút · ${k.web_1m} request/phút`;
  $("k-al").textContent=k.alerts_1h;$("k-al-s").textContent=`${k.incidents_1h} sự cố · ${k.auth_fail_1h} đăng nhập lỗi`;
  $("k-hp").textContent=k.honeypot_1h;$("k-hp-s").textContent=`${d.firewall.redirect_packets||0} gói đã chuyển vào honeypot`;
  $("k-rs").textContent=k.responses;$("k-rs-s").textContent=`${k.pending} chờ duyệt · IPv6 chặn ${d.firewall.ipv6_drop_packets||0} gói`;
  spark("sp-web",d.series.web,"#fff");spark("sp-th",d.series.threat,"#fff");spark("sp-dc",d.series.deceived,"#fff");
  $("nav-dev").textContent=k.devices;$("nav-pend").textContent=k.pending;$("pend-c").textContent=k.pending+" chờ duyệt";
  chart();
  $("pending").innerHTML=d.pending.length?d.pending.map(i=>`<div class="pend"><div style="display:flex;gap:8px;align-items:center"><b class="ipl" data-ip="${esc(i.suspect_ip)}">${esc(i.suspect_ip)}</b><span class="st high">điểm ${i.score}</span><span class="dim" style="margin-left:auto">${esc(String(i.created_at).slice(11,19))}</span></div>
     <div class="muted" style="margin:6px 0">Đang bị đánh lừa nhưng tiếp tục tương tác với honeypot.</div><div>${(i.attack||[]).map(a=>`<span class="chip" style="margin:2px 4px 2px 0;padding:3px 8px">${esc(a.id)}</span>`).join("")}</div>
     <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn b-red" data-act="approve_l2" data-ip="${esc(i.suspect_ip)}" data-inc="${esc(i.incident_id)}">Duyệt chặn toàn bộ</button>
     <button class="btn b-ghost" data-act="dismiss" data-ip="${esc(i.suspect_ip)}" data-inc="${esc(i.incident_id)}">Bỏ qua</button><a href="/report/${encodeURIComponent(i.incident_id)}" target="_blank" style="align-self:center">Báo cáo ↗</a></div></div>`).join("")
     :`<div class="empty">✓ Không có yêu cầu nào chờ duyệt</div>`;
  const ar=[];for(const dv of d.devices)for(const r of dv.responses)ar.push(`<div class="resp"><span class="st ${r.level==="dec"?"dec":"blk"}">${esc(r.label)}</span><b class="ipl" data-ip="${esc(dv.ip)}">${esc(dv.ip)}</b><span class="muted">còn ${esc(r.expires)}</span><span style="flex:1"></span><button class="btn b-ghost" data-act="unblock_all" data-ip="${esc(dv.ip)}">Gỡ</button></div>`);
  $("active").innerHTML=ar.join("")||`<div class="empty" style="padding:14px">Không có phản ứng nào</div>`;
  const devs=d.devices.filter(x=>!f||JSON.stringify(x).toLowerCase().includes(f));
  $("dev-c").textContent=`${devs.length} thiết bị`;
  $("dev").innerHTML=devs.length?devs.map(x=>`<tr class="row" data-ip="${esc(x.ip)}"><td><div class="ipb"><span class="av" style="color:${riskCol(x.risk)}">${esc(x.ip.split(".").pop())}</span><div><b>${esc(x.ip)}</b><div class="dim" style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.ua||"—")}</div></div></div></td>
     <td><div>${ago(x.last,now)}</div><div class="dim" style="font-size:12px">từ ${fmtT(x.first)}</div></td><td class="n">${x.requests}${x.honeypot_web?` <span class="st dec" style="padding:1px 7px">${x.honeypot_web} giả</span>`:""}</td>
     <td class="n">${x.alerts}</td><td class="n">${x.honeypot}</td><td class="n">${x.auth_fail}</td>
     <td><div style="display:flex;align-items:center;gap:8px"><div class="risk"><i style="width:${Math.min(100,x.risk/2)}%;background:${riskCol(x.risk)}"></i></div><b class="n">${x.risk}</b></div></td><td>${stChip(x)}</td></tr>`).join("")
     :`<tr><td colspan="8"><div class="empty">Chưa có thiết bị nào hoạt động trong 30 phút gần nhất.<br><span class="dim">Thiết bị sẽ tự xuất hiện khi có truy cập hoặc sự kiện.</span></div></td></tr>`;
  const cnt={all:d.feed.length};d.feed.forEach(e=>{const t=e.type==="honeyweb"?"honeypot":e.type;cnt[t]=(cnt[t]||0)+1});
  $("tabs").innerHTML=[["all","Tất cả"],["alert","Cảnh báo"],["honeypot","Honeypot"],["auth","Xác thực"],["incident","Analyzer"],["decision","Người vận hành"],["web","Web"]].map(([k2,t])=>`<span class="tab ${tab===k2?"on":""}" data-tab="${k2}">${t} ${cnt[k2]||0}</span>`).join("");
  const fe=d.feed.filter(e=>(tab==="all"||e.type===tab||(tab==="honeypot"&&e.type==="honeyweb"))&&(!f||JSON.stringify(e).toLowerCase().includes(f))).slice(0,120);
  $("feed").innerHTML=fe.length?fe.map(e=>{const[ic,lb]=TYPE[e.type]||["•",e.type];const title=e.type==="incident"?(DEC[e.title]||e.title):(KIND[e.title]||e.title);
    return `<div class="ev ty-${e.type}"><span class="ti">${fmtT(e.t)}</span><span class="ico" title="${lb}">${ic}</span><div class="bd"><span class="ipl" data-ip="${esc(e.ip)}">${esc(e.ip||"")}</span> · <b>${esc(title)}</b>${e.id?` <a href="/report/${encodeURIComponent(e.id)}" target="_blank">↗</a>`:""}<div class="tx">${esc(e.text)}${e.meta?` <span class="dim">· ${esc(e.meta)}</span>`:""}</div></div></div>`}).join("")
    :`<div class="empty">Không có sự kiện phù hợp</div>`;
  $("mx").innerHTML=TACTICS.map(t=>{const te=d.attack.filter(a=>a.tactic===t);return `<div class="col"><b>${TACT_VI[t]}</b><div class="tes">${te.length?te.map(a=>`<span class="te"><b style="color:#fff;padding:0;font-size:12.5px;letter-spacing:0">${esc(a.id)}</b> ${esc(a.name)} <span class="dim">×${a.count}</span></span>`).join(""):`<span class="te zero">chưa quan sát</span>`}</div></div>`}).join("");
  $("hp").innerHTML=d.honeypot.length?d.honeypot.map(h=>`<tr><td class="n">${esc(String(h.ts).slice(11,19))}</td><td><b class="ipl" data-ip="${esc(h.src_ip)}">${esc(h.src_ip)}</b></td><td><span class="st dec">${esc(KIND[h.kind]||h.kind)}</span></td><td class="muted">${esc([h.user&&"user="+h.user,h.password&&"pass="+h.password,h.path,h.port&&"cổng "+h.port,h.data&&"data="+h.data].filter(Boolean).join(" · "))}</td></tr>`).join(""):`<tr><td colspan="4"><div class="empty">Chưa có tương tác với honeypot</div></td></tr>`;
  $("incs").innerHTML=d.incidents.length?d.incidents.slice(0,25).map(i=>`<tr class="row" onclick="window.open('/report/'+encodeURIComponent('${esc(i.incident_id)}'),'_blank')"><td class="dim n">${esc(String(i.created_at).slice(11,19))}</td><td><b>${esc(i.suspect_ip)}</b></td><td class="n">${i.score}</td><td><span class="st ${i.decision==="deceive"||i.decision==="attacker_engaged"?"dec":(i.score>=100?"high":"medium")}">${esc(DEC[i.decision]||i.decision)}</span></td></tr>`).join(""):`<tr><td><div class="empty">Chưa có sự cố</div></td></tr>`;
  renderRules(d);
  if(seenInc===null)seenInc=new Set(d.incidents.map(i=>i.incident_id));
  else for(const i of d.incidents.slice().reverse())if(!seenInc.has(i.incident_id)){seenInc.add(i.incident_id);
    toast(`<b>Sự cố mới · ${esc(i.suspect_ip)}</b><div class="muted">${esc(DEC[i.decision]||i.decision)} · điểm ${i.score}</div>`,i.decision==="attacker_engaged"?"red":i.decision==="deceive"?"pink":"")}
}
async function openDetail(ip){openIp=ip;$("ov").classList.add("open");$("dr").classList.add("open");
  let x;try{x=await (await fetch("/api/ip/"+encodeURIComponent(ip),{cache:"no-store"})).json()}catch(e){return}
  $("dr-av").textContent=ip.split(".").pop();$("dr-ip").textContent=ip;$("dr-ua").textContent=x.ua||"Chưa có truy cập web";
  const resp=x.responses.length?x.responses.map(r=>`<span class="st ${r.level==="dec"?"dec":"blk"}">● ${esc(r.label)} · còn ${esc(r.expires)}</span>`).join(" "):`<span class="st none">● Không bị hạn chế</span>`;
  $("dr-b").innerHTML=`<div>${resp}</div>
   <div class="dim" style="font-size:12px;margin-top:12px">Thống kê trên toàn bộ nhật ký hiện có của thiết bị này</div>
   <div class="stats" style="margin-top:6px"><div><b>${x.counts.web}</b><span>Request web</span></div><div><b>${x.counts.alerts}</b><span>Cảnh báo</span></div><div><b>${x.counts.honeypot}</b><span>Honeypot</span></div><div><b>${x.counts.auth}</b><span>Xác thực</span></div></div>
   <div class="acts"><button class="btn b-vio" data-act="deceive" data-ip="${esc(ip)}">🎭 Đánh lừa</button><button class="btn b-amber" data-act="block_l1" data-ip="${esc(ip)}">Chặn web 60s</button><button class="btn b-red" data-act="block_l2" data-ip="${esc(ip)}">Chặn toàn bộ</button><button class="btn b-ghost" data-act="unblock_all" data-ip="${esc(ip)}">Gỡ tất cả</button></div>
   <div class="dim" style="font-size:12px;margin:-6px 0 14px">Chỉ phản ứng với IP trong danh sách được phép (A, C); máy chủ luôn được bảo vệ. Tự động chỉ phản ứng khi có bằng chứng không giả mạo được.</div>
   ${x.attack.length?`<h4 style="margin:6px 0">MITRE ATT&CK</h4><div>${x.attack.map(a=>`<span class="chip" style="margin:3px 4px 3px 0">${esc(a.id)} · ${esc(a.name)}</span>`).join("")}</div>`:""}
   ${x.top_paths.length?`<h4 style="margin:16px 0 6px">Đường dẫn truy cập nhiều nhất</h4>${x.top_paths.map(([p,c])=>`<div style="display:flex;gap:8px;padding:4px 0"><code style="color:#c4bcff;overflow:hidden;text-overflow:ellipsis">${esc(p)}</code><span style="margin-left:auto" class="n">${c}</span></div>`).join("")}`:""}
   <h4 style="margin:16px 0 6px">Dòng thời gian</h4>${x.events.map(e=>{const[ic]=TYPE[e.type]||["•"];const title=e.type==="incident"?(DEC[e.title]||e.title):(KIND[e.title]||e.title);
     return `<div class="ev ty-${e.type}"><span class="ti">${fmtT(e.t)}</span><span class="ico">${ic}</span><div class="bd"><b>${esc(title)}</b>${e.id?` <a href="/report/${encodeURIComponent(e.id)}" target="_blank">↗</a>`:""}<div class="tx">${esc(e.text)}</div></div></div>`}).join("")||`<div class="empty">Chưa có sự kiện</div>`}`;
}
function closeDetail(){openIp=null;$("ov").classList.remove("open");$("dr").classList.remove("open")}
document.addEventListener("click",e=>{const ra=e.target.closest("[data-ract]");if(ra){e.stopPropagation();return ruleAct(ra.dataset.ract,ra.dataset.rule)}
  const a=e.target.closest("[data-act]");if(a){e.stopPropagation();return act(a.dataset.act,a.dataset.ip,a.dataset.inc)}
  const t=e.target.closest("[data-tab]");if(t){tab=t.dataset.tab;return render()}
  const ip=e.target.closest("[data-ip]");if(ip&&ip.dataset.ip&&!e.target.closest(".dr"))openDetail(ip.dataset.ip)});
$("ov").onclick=closeDetail;$("dr-x").onclick=closeDetail;document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDetail()});
$("q").addEventListener("input",()=>S&&render());
document.querySelectorAll(".nav a").forEach(a=>a.addEventListener("click",()=>{document.querySelectorAll(".nav a").forEach(b=>b.classList.remove("on"));a.classList.add("on")}));
let tick=0;
async function load(){try{S=await (await fetch("/api/state",{cache:"no-store"})).json();render();
  if(openIp&&(++tick%3===0)){const b=$("dr-b"),y=b.scrollTop;await openDetail(openIp);b.scrollTop=y}}catch(e){$("clock").textContent="mất kết nối"}}
load();setInterval(load,2000);
</script></body></html>"""

if __name__ == "__main__":
    print(f"Lab SOC dashboard v2: http://{BIND[0]}:{BIND[1]}/", flush=True)
    ThreadingHTTPServer(BIND, Handler).serve_forever()
