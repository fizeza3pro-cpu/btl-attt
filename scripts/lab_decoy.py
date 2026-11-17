"""In-memory shop facade for the deception listener. Never opens the real DB."""
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs,urlsplit

LOCK=threading.Lock()
SESSIONS={}
PRODUCTS=[{'id':i+1,'name':name,'price':price,'icon':icon,'color':'#e7eef8','rate':4.7,'n':120,'old':None,'tag':None}
          for i,(name,price,icon) in enumerate([
          ('Tai nghe không dây ANC',590000,'🎧'),('Bàn phím cơ RGB',1250000,'⌨️'),('Chuột gaming 26K DPI',450000,'🖱️'),
          ('Màn hình 24 inch 165Hz',2890000,'🖥️'),('Loa bluetooth',720000,'🔊'),('Webcam Full HD',650000,'📷'),
          ('Ổ cứng SSD 1TB',1690000,'💾'),('Sạc dự phòng',390000,'🔋')])]


def shop_api(handler,path,body='',log=None):
    url=urlsplit(path)
    if not url.path.startswith('/api/') or url.path.startswith('/api/admin'):return False
    log=log or (lambda *a,**k:None)
    method=handler.command
    try:
        cookies=SimpleCookie(handler.headers.get('Cookie',''));sid=cookies.get('decoy_sid')
        sid=sid.value if sid else ''
    except Exception:sid=''
    with LOCK:
        now=time.time()
        for key in list(SESSIONS):
            if SESSIONS[key]['expires']<now:del SESSIONS[key]
        if sid not in SESSIONS:
            if len(SESSIONS)>=1000:del SESSIONS[next(iter(SESSIONS))]
            sid=secrets.token_hex(16);SESSIONS[sid]={'email':None,'cart':{},'expires':now+3600}
        s=SESSIONS[sid]
        try:data=json.loads(body) if body else {}
        except ValueError:data={}
        if not isinstance(data,dict):data={}
        def send(data,code=200):
            handler.send(code,json.dumps(data,ensure_ascii=False),'application/json; charset=utf-8',extra={'Set-Cookie':f'decoy_sid={sid}; Path=/; HttpOnly; SameSite=Lax'})
            return True
        def cart():
            items=[{**PRODUCTS[pid-1],'qty':qty,'line':PRODUCTS[pid-1]['price']*qty} for pid,qty in s['cart'].items()]
            return {'items':items,'count':sum(i['qty'] for i in items),'total':sum(i['line'] for i in items)}
        if url.path=='/api/health':return send({'status':'ok','server':'B 10.77.0.20','time':time.strftime('%H:%M:%S'),'uptime_s':3600,'vuln_mode':False})
        log(handler.ip(),'deception_web_request',path=url.path,method=method)
        if url.path=='/api/products':return send({'products':PRODUCTS})
        if url.path=='/api/search':
            q=parse_qs(url.query).get('q',[''])[0][:100]
            return send({'query':q,'results':[p for p in PRODUCTS if q.lower() in p['name'].lower()]})
        if url.path=='/api/login' and method=='POST':
            email=data.get('email','')
            if not isinstance(email,str) or not email or len(email)>256:return send({'error':'dữ liệu không hợp lệ'},400)
            s['email']=email;s['role']='admin' if 'admin' in email.lower() else 'customer'
            log(handler.ip(),'honeypot_admin_login',user=email,note='deception facade; no real authentication')
            return send({'ok':True,'name':'Khách hàng','role':s['role']})
        if url.path=='/api/me':return send({'logged_in':bool(s['email']),'email':s['email'],'name':'Khách hàng' if s['email'] else None,'role':s.get('role')})
        if url.path=='/api/logout' and method=='POST':s['email']=None;s['role']=None;return send({'ok':True})
        if url.path=='/api/cart':
            if method=='POST':
                pid=data.get('id')
                if type(pid) is not int or not 1<=pid<=len(PRODUCTS):return send({'error':'sản phẩm không hợp lệ'},400)
                s['cart'][pid]=min(99,s['cart'].get(pid,0)+1)
            return send(cart())
        if url.path=='/api/order' and method=='POST':
            if not s['email']:return send({'error':'cần đăng nhập'},401)
            c=cart();s['cart']={}
            return send({'order_id':'LS'+secrets.token_hex(6).upper(),'count':c['count'],'total':c['total'],'customer':s['email']},201)
        if url.path.startswith('/api/staff/'):
            log(handler.ip(),'honeypot_admin_view',path=url.path,note='deception staff facade')
            if s.get('role')!='admin':return send({'error':'chỉ quản trị viên mới được truy cập'},403)
            if url.path.endswith('/users'):
                return send({'users':[{'id':9001,'email':'customer@example.test','name':'Khách hàng','role':'customer'}]})
            return send({'orders':[],'count':0})
        if url.path=='/api/orders':return send({'orders':[]})
        return send({'error':'không tìm thấy'},404)
