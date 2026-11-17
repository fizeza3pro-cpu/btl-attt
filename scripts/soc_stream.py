"""Bounded, read-only event history and SSE endpoints for the existing SOC server."""
import json
from pathlib import Path
import socket
import sqlite3
import threading
import time
from urllib.parse import parse_qs,urlsplit
from lab_events import Store, DB, SOURCES

ASSETS=Path(__file__).with_name('soc-assets')
STREAMS=threading.BoundedSemaphore(16)


class StreamMixin:
    def event_endpoint(self):
        url=urlsplit(self.path)
        if url.path.startswith('/assets/'):
            name=url.path.removeprefix('/assets/')
            if name not in ('logs.js','logs.css','dashboard.js','dashboard.css'):self.send(404,'not found','text/plain');return True
            self.send(200,(ASSETS/name).read_bytes(),'text/javascript; charset=utf-8' if name.endswith('.js') else 'text/css; charset=utf-8');return True
        if url.path not in ('/api/events','/api/events/stream','/api/events/status'):return False
        store=Store()
        try:
            if not Path(DB).exists():
                self.send(503,json.dumps({'error':'Bộ thu thập sự kiện chưa sẵn sàng'}),'application/json');return True
            q={k:v[0] for k,v in parse_qs(url.query).items()}
            if url.path=='/api/events/status':
                self.send(200,json.dumps(store.status()),'application/json');return True
            if url.path=='/api/events':
                kwargs={k:q[k][:120] for k in ('source','ip','q','severity') if k in q}
                for k in ('after','before','limit'):
                    if k in q:kwargs[k]=max(0,int(q[k]))
                if 'since' in q:kwargs['since']=float(q['since'])
                data=store.history(**kwargs)
                self.send(200,json.dumps(data,ensure_ascii=False),'application/json; charset=utf-8');return True
            after=max(0,int(self.headers.get('Last-Event-ID') or q.get('after','0')))
            self.event_stream(store,after)
        except (ValueError,TypeError):self.send(400,json.dumps({'error':'invalid cursor or filter'}),'application/json')
        except (OSError,sqlite3.Error) as e:self.send(503,json.dumps({'error':str(e)[:120]}),'application/json')
        return True

    def event_stream(self,store,after):
        if not STREAMS.acquire(blocking=False):
            return self.send(503,'Too many streams','text/plain')
        try:
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Accel-Buffering','no')
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers();self.connection.settimeout(5)
            beat=0
            while True:
                now=time.monotonic()
                status=store.status()
                if after and ((status['oldest_id'] and after<status['oldest_id']-1) or after>status['latest_id']):
                    self.wfile.write(b'event: gap\ndata: {"message":"Cursor cu da het han; tai lai lich su"}\n\n')
                    self.wfile.flush();return
                rows=store.history(after=after,limit=200)['events']
                for row in rows:
                    data=json.dumps(row,ensure_ascii=False)
                    self.wfile.write(f"id: {row['id']}\ndata: {data}\n\n".encode())
                    after=row['id']
                if now-beat>5:
                    self.wfile.write(('event: heartbeat\ndata: '+json.dumps({'active':status['active'],'at':time.time()})+'\n\n').encode());beat=now
                self.wfile.flush();time.sleep(.3 if len(rows)<200 else .01)
        except (BrokenPipeError,ConnectionResetError,socket.timeout):pass
        finally:STREAMS.release()


def augment_page(page):
    panel=(ASSETS/'logs.html').read_text(encoding='utf-8')
    page=page.replace('<!-- LIVE_LOGS -->',panel)
    page=page.replace('</head>','<link rel="stylesheet" href="/assets/logs.css"></head>')
    return page.replace('</body>','<script src="/assets/logs.js" defer></script></body>')
