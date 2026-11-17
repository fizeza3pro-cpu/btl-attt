#!/usr/bin/env python3
"""Shared event store, log collector and CLI for the Ubuntu lab. Standard library only."""
import argparse
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import threading
import time

DB = os.environ.get("LAB_SOC_DB", "/var/lib/lab-soc/soc.db")
SOURCES = {
    "web": "/var/log/nginx/access.log", "webfake": "/var/log/nginx/honeypot-access.log",
    "eve": "/var/log/suricata/eve.json", "hp": "/var/log/lab-honeypot/events.jsonl",
    "auth": "/var/log/lab-shop/auth.jsonl", "inc": "/var/lib/lab-analyzer/incidents.jsonl",
    "dec": "/var/lib/lab-analyzer/decisions.jsonl", "score": "/var/lib/lab-analyzer/signals.jsonl",
}
UNITS = ("lab-shop-api", "lab-analyzer", "lab-honeypot", "lab-rulegen", "lab-soc", "suricata", "nginx")
LABELS = {"web":"WEB", "webfake":"WEB GIẢ", "eve":"SURICATA THÔ", "score":"ĐIỂM", "hp":"HONEYPOT", "auth":"ĐĂNG NHẬP", "inc":"PHÂN TÍCH", "dec":"VẬN HÀNH", "rule":"RULE MỚI", "firewall":"TƯỜNG LỬA", "journal":"DỊCH VỤ"}
AUTH_VI = {"login_ok":"Đăng nhập thành công", "login_fail":"Sai email hoặc mật khẩu", "login_locked":"Tạm khóa đăng nhập", "login_invalid_input":"Dữ liệu đăng nhập bất thường"}
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')
SECRET = re.compile(r"password|passwd|pw_hash|pw_salt|authorization|cookie|token|api.?key", re.I)
STOP = threading.Event()


def redact(value):
    if isinstance(value, dict):
        return {str(k): "[đã che]" if SECRET.search(str(k)) or k == "data" else redact(v) for k,v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value[:100]]
    if isinstance(value, str):
        return re.sub(r"(?i)((?:password|passwd|api_key|token)\s*[=:]\s*)[^\s&,;]+", r"\1[đã che]", value[:16000])
    return value


def timestamp(value):
    if isinstance(value,(float,int)): return float(value)
    if not value: return time.time()
    return datetime.fromisoformat(str(value).replace("Z","+00:00")).timestamp()


def normalize(source, raw):
    """The source record is preserved after secret redaction; both UIs share summary."""
    if source in ("web","webfake"):
        m = LOG_RE.match(raw)
        if not m: raise ValueError("unrecognized nginx line")
        ip,ts,method,path,status,size,ua = m.groups()
        t=datetime.strptime(ts,"%d/%b/%Y:%H:%M:%S %z").timestamp()
        p={"t":t,"ip":ip,"method":method,"path":path[:1000],"status":int(status),"ua":ua,"kind":"web" if source=="web" else "honeypot"}
        kind="request"; severity="warning" if int(status)>=400 else "info"
        summary=f"{method} {path[:160]} → {status}" + (" · web giả" if source=="webfake" else "")
    else:
        p=json.loads(raw) if isinstance(raw,str) else raw
        # EVE contains high-volume flow/statistics records; do not walk their trees.
        if source=="eve" and p.get("event_type")!="alert": return None
        p=redact(p)
        t=timestamp(p.get("timestamp") or p.get("ts") or p.get("created_at") or p.get("at"))
        ip=p.get("src_ip") or p.get("suspect_ip") or p.get("ip") or ""
        kind=p.get("kind",source); severity="info"
        if source=="eve":
            if p.get("event_type")!="alert": return None
            a=p.get("alert") or {}; sid=a.get("signature_id",0)
            if sid>=9000000: return None
            if sid in (1000003,1000005,1000007,1000017) and ip=="10.77.0.20": ip=p.get("dest_ip","")
            kind="alert";severity="critical" if a.get("severity")==1 else "warning"
            summary=f"SID {sid} · {a.get('signature','Suricata alert')}"
        elif source=="auth":
            severity="info" if kind=="login_ok" else "warning"
            summary=f"{AUTH_VI.get(kind,kind)} · {p.get('authenticated_email') or p.get('email','')}"
        elif source=="hp":
            severity="warning";summary=f"{kind} · {p.get('path') or p.get('user') or p.get('port') or ''}"
        elif source=="inc":
            kind=p.get("decision","incident");severity="critical" if p.get("score",0)>=100 else "warning"
            summary=f"{kind} · {p.get('score',0)} điểm · {p.get('reason','')}"
        elif source=="score":
            kind="score_added";severity="critical" if p.get("score",0)>=100 else "warning"
            summary=f"SID {p.get('sid')} · +{p.get('delta',0)} điểm → hiện tại {p.get('score',0)} · {p.get('message','')}"
        elif source=="dec":
            kind=p.get("action","decision");summary=f"{kind} · {p.get('result','')}"
            severity="info" if p.get("ok",True) else "error"
        else: summary=p.get("summary",str(kind))
    p=redact(p)
    return {"ts":t,"source":source,"kind":str(kind),"ip":str(ip),"severity":severity,"summary":redact(summary),"payload":p}


class Store:
    def __init__(self,path=DB,initialize=False):
        self.path=str(path)
        if initialize:
            Path(path).parent.mkdir(parents=True,exist_ok=True)
            with self.connect(write=True) as c:
                c.execute("PRAGMA journal_mode=WAL")
                c.executescript("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts REAL NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,ip TEXT NOT NULL,severity TEXT NOT NULL,summary TEXT NOT NULL,payload TEXT NOT NULL,ref TEXT UNIQUE NOT NULL);
                CREATE INDEX IF NOT EXISTS events_time ON events(ts);
                CREATE INDEX IF NOT EXISTS events_source_time ON events(source,ts);
                CREATE INDEX IF NOT EXISTS events_ip_time ON events(ip,ts);
                CREATE TABLE IF NOT EXISTS checkpoints(source TEXT PRIMARY KEY,identity TEXT,offset INTEGER,cursor TEXT);
                CREATE TABLE IF NOT EXISTS health(source TEXT PRIMARY KEY,updated REAL,error TEXT,detail TEXT);
                """)

    @contextmanager
    def connect(self,write=False):
        c=sqlite3.connect(self.path if write else Path(self.path).resolve().as_uri()+"?mode=ro",uri=not write,timeout=5)
        c.row_factory=sqlite3.Row
        try:
            with c: yield c
        finally:c.close()

    def insert(self,c,event,ref):
        if not event:return
        c.execute("INSERT OR IGNORE INTO events(ts,source,kind,ip,severity,summary,payload,ref) VALUES(?,?,?,?,?,?,?,?)",
                  tuple(event[k] for k in ("ts","source","kind","ip","severity","summary"))+(json.dumps(event["payload"],ensure_ascii=False),ref))

    def health(self,source,error="",detail=""):
        with self.connect(True) as c:
            c.execute("INSERT OR REPLACE INTO health VALUES(?,?,?,?)",(source,time.time(),str(error)[:300],str(detail)[:500]))

    def status(self):
        with self.connect() as c:
            rows=[dict(r) for r in c.execute("SELECT * FROM health")]
            low,high=c.execute("SELECT min(id),max(id) FROM events").fetchone()
        return {"sources":rows,"oldest_id":low or 0,"latest_id":high or 0,"retention_days":7,
                "active":any(r["source"]=="collector" and time.time()-r["updated"]<10 for r in rows)}

    def history(self,after=None,before=None,limit=200,source="",ip="",q="",severity="",since=None):
        clauses=[];args=[]
        for field,value,op in (("id",after,">"),("id",before,"<"),("source",source,"="),("ip",ip,"="),("severity",severity,"="),("ts",since,">=")):
            if value is not None and value!="":clauses.append(f"{field}{op}?");args.append(value)
        if q:clauses.append("(summary LIKE ? OR payload LIKE ?)");args += ['%'+q+'%']*2
        sql="SELECT * FROM events"+(" WHERE "+" AND ".join(clauses) if clauses else "")
        sql+=" ORDER BY id "+("ASC" if after is not None else "DESC")+" LIMIT ?";args.append(max(1,min(1000,int(limit))))
        with self.connect() as c:
            # Same read transaction for history and stream watermark.
            c.execute("BEGIN")
            cursor=c.execute("SELECT coalesce(max(id),0) FROM events").fetchone()[0]
            rows=[dict(r) for r in c.execute(sql,args)]
        for r in rows:r["payload"]=json.loads(r["payload"])
        return {"events":rows,"cursor":cursor,"next_before":min((r["id"] for r in rows),default=0)}

    def records(self,source,since=0):
        with self.connect() as c:
            rows=c.execute("SELECT ts,payload FROM events WHERE source=? AND ts>=? ORDER BY id",(source,since)).fetchall()
        return [{**json.loads(r["payload"]),"t":r["ts"]} for r in rows]

    def checkpoint(self,source):
        with self.connect() as c:
            r=c.execute("SELECT * FROM checkpoints WHERE source=?",(source,)).fetchone()
        return dict(r) if r else {}

    def ingest_file(self,source,path,chunk_size=1024*1024):
        try:
            st=os.stat(path);base_identity=f"{st.st_dev}:{st.st_ino}"
            cp=self.checkpoint(source);offset=cp.get("offset",0)
            old_base=':'.join(cp.get('identity','').split(':')[:2])
            # Drain an inode renamed by logrotate before opening the new active log.
            if old_base and old_base!=base_identity:
                for candidate in Path(path).parent.glob(Path(path).name+'*'):
                    try:
                        s=candidate.stat()
                        if f'{s.st_dev}:{s.st_ino}'==old_base and s.st_size>offset:
                            return self.ingest_file(source,str(candidate),chunk_size)
                    except OSError:pass
            fingerprint=json.loads(cp.get('cursor') or '{}')
            with open(path,'rb') as f:head=f.read(fingerprint.get('length',64))
            changed=bool(fingerprint.get('hash') and hashlib.sha256(head).hexdigest()!=fingerprint['hash'])
            if fingerprint.get('tail_hash') and st.st_size>=offset:
                with open(path,'rb') as f:
                    f.seek(max(0,offset-64));tail=f.read(min(64,offset))
                changed=changed or hashlib.sha256(tail).hexdigest()!=fingerprint['tail_hash']
            if old_base!=base_identity or st.st_size<offset or changed:
                offset=0;identity=base_identity+':'+str(time.time_ns())
            else:identity=cp.get('identity') or base_identity+':'+str(time.time_ns())
            with open(path,"rb") as f:
                f.seek(offset);chunk=f.read(chunk_size)
            # Do not checkpoint a partial record. Oversized line is explicitly skipped.
            cut=chunk.rfind(b"\n")+1
            if not cut:
                if len(chunk)==chunk_size:
                    raise ValueError("record exceeds 1 MiB; source needs inspection")
                self.health(source,detail=f"offset={offset}; bytes={st.st_size}; waiting for newline")
                return 0
            count=0;bad=0;end=offset
            with self.connect(True) as c:
                for line in chunk[:cut].splitlines(keepends=True):
                    ref=f"{source}:{identity}:{end}:"+hashlib.sha256(line).hexdigest()[:16]
                    try:
                        event=normalize(source,line.decode('utf-8','replace').rstrip())
                        if event:self.insert(c,event,ref);count+=1
                    except (ValueError,TypeError,KeyError):bad+=1
                    end+=len(line)
                with open(path,'rb') as f:head=f.read(min(64,end))
                with open(path,'rb') as f:
                    f.seek(max(0,end-64));tail=f.read(min(64,end))
                fingerprint=json.dumps({'length':len(head),'hash':hashlib.sha256(head).hexdigest(),'tail_hash':hashlib.sha256(tail).hexdigest()})
                c.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?)",(source,identity,end,fingerprint))
                c.execute("INSERT OR REPLACE INTO health VALUES(?,?,?,?)",(source,time.time(),f"{bad} malformed records" if bad else "",f"offset={end}; bytes={st.st_size}"))
            return count
        except OSError as e:self.health(source,error=e);return 0

    def prune(self,now=None):
        with self.connect(True) as c:c.execute("DELETE FROM events WHERE ts<?",((now or time.time())-7*86400,))


def format_event(e):
    stamp=datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S %d/%m")
    return f"{stamp}  {LABELS.get(e['source'],e['source']):<11} {e['ip']:<14} {e['summary']}"


def journal_worker(store):
    while not STOP.is_set():
        cp=store.checkpoint('journal')
        cmd=['journalctl','--follow','--output=json','--no-pager']
        for unit in UNITS:cmd+=['-u',unit]
        cmd+=['--after-cursor',cp['cursor']] if cp.get('cursor') else ['--since','5 minutes ago']
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def end():
            while proc.poll() is None and not STOP.wait(1):pass
            if proc.poll() is None:proc.terminate()
        threading.Thread(target=end,daemon=True).start()
        try:
            for line in proc.stdout:
                try:
                    j=json.loads(line);cursor=j['__CURSOR']
                    if j.get('_SYSTEMD_UNIT','').removesuffix('.service') not in UNITS:continue
                    event=normalize('journal',{'ts':int(j['__REALTIME_TIMESTAMP'])/1e6,'kind':j.get('_SYSTEMD_UNIT'),
                        'summary':j.get('MESSAGE',''),'priority':j.get('PRIORITY'),'unit':j.get('_SYSTEMD_UNIT')})
                    with store.connect(True) as c:
                        store.insert(c,event,'journal:'+cursor)
                        c.execute("INSERT OR REPLACE INTO checkpoints VALUES('journal','',0,?)",(cursor,))
                    store.health('journal',detail='following allowlisted service units')
                except (ValueError,KeyError,TypeError) as e:store.health('journal',error=e)
            err=proc.stderr.read()[:300]
            store.health('journal',error=err or 'journal stream ended')
            if proc.returncode and cp.get('cursor') and re.search('cursor|seek',err,re.I):
                # A reclaimed journal cannot be replayed. Report the gap explicitly,
                # then resume recent records (journal cursor refs still deduplicate).
                with store.connect(True) as c:
                    store.insert(c,normalize('journal',{'ts':time.time(),'kind':'journal_gap','summary':'Journal cursor hết hạn; tiếp tục từ 5 phút gần nhất'}),'journal-gap:'+hashlib.sha256(cp['cursor'].encode()).hexdigest())
                    c.execute("DELETE FROM checkpoints WHERE source='journal'")
        except OSError as e:store.health('journal',error=e)
        finally:
            if proc.poll() is None:proc.terminate()
            proc.wait(timeout=5)
        STOP.wait(3)


def collect(store):
    threading.Thread(target=journal_worker,args=(store,),daemon=True).start()
    last_poll=0;last_prune=0;fw_previous=None;rule_previous={}
    while not STOP.is_set():
        for source,path in SOURCES.items():
            try:store.ingest_file(source,path)
            except Exception as e:store.health(source,error=e)
        now=time.time()
        if now-last_poll>=2:
            try:
                p=subprocess.run(['sudo','-n','/usr/local/sbin/lab-block','status'],capture_output=True,text=True,timeout=5)
                if p.returncode:raise RuntimeError(p.stderr or p.stdout)
                fw=json.loads(p.stdout.strip().splitlines()[-1])
                current={(ip,level) for level in ('deceive','blocked_l1','blocked_l2') for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+) expires',fw.get(level,'') or '')}
                if fw_previous is not None:
                    for ip,level in current.symmetric_difference(fw_previous):
                        event=normalize('firewall',{'ts':now,'ip':ip,'kind':level,'summary':('Bắt đầu ' if (ip,level) in current else 'Kết thúc ')+level})
                        with store.connect(True) as c:store.insert(c,event,f'fw:{now}:{ip}:{level}')
                fw_previous=current;store.health('firewall',detail=f'{len(current)} active memberships')
            except Exception as e:store.health('firewall',error=e)
            try:
                props=json.loads(Path('/var/lib/lab-rulegen/proposals.json').read_text())
                for prop in props:
                    key=prop['id']+':'+prop['status']
                    if rule_previous.get(prop['id'])!=prop['status']:
                        ev=normalize('rule',{'ts':now,'kind':prop['status'],'summary':f"Rule {prop['id']}: {prop['status']}",'proposal':prop})
                        with store.connect(True) as c:store.insert(c,ev,'rule:'+key)
                    rule_previous[prop['id']]=prop['status']
                store.health('rule',detail=f'{len(props)} proposals')
            except Exception as e:store.health('rule',error=e)
            last_poll=now
        if now-last_prune>3600:store.prune();last_prune=now
        store.health('collector',detail='running');STOP.wait(.3)


def follow(store,after=None,show_all=False,show_health=False):
    def visible(e):
        p=e['payload'];path=p.get('path','')
        if e['source']=='journal':return False
        if e['source'] in ('web','webfake'):
            if not show_health and path.startswith('/api/health'):return False
            if not show_all and re.search(r'\.(css|js|svg|ico|png)(\?|$)',path):return False
        return True
    if after is None:
        result=store.history(limit=30)
        for e in reversed(result['events']):
            if visible(e):print(format_event(e),flush=True)
        after=result['cursor']
    while not STOP.is_set():
        rows=store.history(after=after,limit=500)['events']
        for e in rows:
            after=e['id']
            if visible(e):print(format_event(e),flush=True)
        STOP.wait(.3)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--collect',action='store_true');ap.add_argument('--follow',action='store_true');ap.add_argument('--db',default=DB)
    a=ap.parse_args()
    signal.signal(signal.SIGTERM,lambda *_:STOP.set());signal.signal(signal.SIGINT,lambda *_:STOP.set())
    store=Store(a.db,initialize=a.collect)
    collect(store) if a.collect else follow(store)
