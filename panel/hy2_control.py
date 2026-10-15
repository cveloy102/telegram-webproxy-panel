"""Hysteria controller: local authentication, persistent accounting and owner-only IPC."""
import copy
import datetime as dt
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import socketserver
import sqlite3
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit
import urllib.request
import yaml

TZ = dt.timezone.utc
LOG = logging.getLogger('hy2-controller')

def atomic(path, content, mode=0o600):
    path = Path(path)
    temp = path.with_name(path.name + '.tmp')
    with temp.open('w', encoding='utf-8') as f:
        f.write(content); f.flush(); os.fsync(f.fileno())
    temp.chmod(mode)
    os.replace(temp, path)

class Controller:
    def __init__(self, data='/var/lib/relay-hy2', config='/etc/hysteria/config.yaml', test=False):
        self.data = Path(data); self.data.mkdir(parents=True, exist_ok=True)
        self.config = Path(config); self.test = test; self.lock = threading.RLock()
        self.path = self.data / 'hy2.sqlite3'
        self.updated = 0; self.online = {}; self.cpu = None; self.last_cpu = None
        with self.db() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,grp TEXT,secret TEXT,
              enabled INTEGER,created INTEGER,expires INTEGER DEFAULT 0,quota INTEGER DEFAULT 0,
              enforce INTEGER DEFAULT 0,last INTEGER DEFAULT 0,up INTEGER DEFAULT 0,down INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS days(id TEXT,day TEXT,up INTEGER,down INTEGER,PRIMARY KEY(id,day));
            CREATE TABLE IF NOT EXISTS samples(id TEXT PRIMARY KEY,up INTEGER,down INTEGER);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time INTEGER,kind TEXT,user TEXT,text TEXT);
            CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,reason TEXT);
            CREATE TABLE IF NOT EXISTS revoked(id TEXT PRIMARY KEY);
            ''')
            cfg = yaml.safe_load(self.config.read_text())
            initialized = bool(c.execute("SELECT 1 FROM settings WHERE k='started'").fetchone())
            saved_host=c.execute("SELECT v FROM settings WHERE k='host'").fetchone()
            host=cfg.get('acme',{}).get('domains',[json.loads(saved_host[0]) if saved_host else ''])[0]
            if not host:raise ValueError('Не задан домен Hysteria')
            defaults = {'paused':False,'host':host,
                        'port':int(cfg['listen'].rsplit(':',1)[1]),'cover':'page','cover_url':'',
                        'obfs':False,'obfs_password':secrets.token_urlsafe(24),
                        'api_secret':secrets.token_urlsafe(32),'auth_token':secrets.token_urlsafe(32),
                        'started':int(time.time()),'epoch':''}
            for k,v in defaults.items():
                c.execute('INSERT OR IGNORE INTO settings VALUES(?,?)',(k,json.dumps(v)))
            if not initialized and c.execute('SELECT count(*) FROM users').fetchone()[0] == 0:
                secret = cfg.get('auth',{}).get('password')
                if not secret: raise ValueError('Нельзя импортировать действующий ключ')
                c.execute('INSERT INTO users(id,name,grp,secret,enabled,created) VALUES(?,?,?,?,1,?)',
                          ('default','Мой ключ','Личное',secret,int(time.time())))
        self.path.chmod(0o600)

    def db(self):
        c=sqlite3.connect(self.path,timeout=10); c.row_factory=sqlite3.Row; return c

    def settings(self, c):
        return {r['k']:json.loads(r['v']) for r in c.execute('SELECT * FROM settings')}

    def event(self,c,kind,user,text):
        c.execute('INSERT INTO events(time,kind,user,text) VALUES(?,?,?,?)',(int(time.time()),kind,user,text))

    @staticmethod
    def reason(u, now=None):
        now = int(time.time()) if now is None else now
        if u['expires'] and now>=u['expires']: return 'Срок действия закончился'
        if u['quota'] and u['up']+u['down']>=u['quota']: return 'Лимит трафика исчерпан'
        return ''

    def allowed(self,u,s):
        return bool(u['enabled'] and not s['paused'] and not (u['enforce'] and self.reason(u)))

    def authenticate(self, secret):
        if not isinstance(secret,str) or not 1<=len(secret)<=256: return {'ok':False}
        with self.lock, self.db() as c:
            s=self.settings(c)
            for u in c.execute('SELECT * FROM users'):
                if hmac.compare_digest(secret,u['secret']):
                    return {'ok':self.allowed(u,s),'id':u['id']}
        return {'ok':False}

    def stats_api(self,path,payload=None):
        with self.db() as c: s=self.settings(c)
        req=urllib.request.Request('http://127.0.0.1:9998/'+path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={'Authorization':s['api_secret'],'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as r:
            raw=r.read(2**20)
            return json.loads(raw) if raw else None

    def epoch(self):
        if self.test: return 'test'
        return subprocess.check_output(['systemctl','show','hysteria-server','-p','InvocationID','--value'],text=True,timeout=3).strip()

    def ingest(self,traffic,online,epoch,now=None):
        now=int(time.time()) if now is None else now
        day=dt.datetime.fromtimestamp(now,TZ).strftime('%Y-%m-%d')
        with self.lock,self.db() as c:
            s=self.settings(c)
            if s['epoch']!=epoch:
                c.execute('DELETE FROM samples');c.execute('UPDATE settings SET v=? WHERE k=?',(json.dumps(epoch),'epoch'))
            for u in c.execute('SELECT * FROM users').fetchall():
                vals=traffic.get(u['id'],{})
                up,down=int(vals.get('tx',0)),int(vals.get('rx',0))
                if min(up,down)<0: raise ValueError('Invalid traffic')
                old=c.execute('SELECT * FROM samples WHERE id=?',(u['id'],)).fetchone()
                du=up-(old['up'] if old else 0);dd=down-(old['down'] if old else 0)
                # A reset never subtracts previously accounted bytes.
                if du<0: du=up
                if dd<0: dd=down
                if u['id'] in traffic:
                    c.execute('INSERT INTO samples VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET up=excluded.up,down=excluded.down',(u['id'],up,down))
                if du or dd:
                    c.execute('UPDATE users SET up=up+?,down=down+? WHERE id=?',(du,dd,u['id']))
                    c.execute('INSERT INTO days VALUES(?,?,?,?) ON CONFLICT(id,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(u['id'],day,du,dd))
                if online.get(u['id'],0)>0:
                    if not u['last']: self.event(c,'first',u['id'],u['name']+': первое подключение')
                    c.execute('UPDATE users SET last=? WHERE id=?',(now,u['id']))
                u=dict(c.execute('SELECT * FROM users WHERE id=?',(u['id'],)).fetchone())
                reason=self.reason(u,now)
                alert=c.execute('SELECT reason FROM alerts WHERE id=?',(u['id'],)).fetchone()
                if reason and (not alert or alert['reason']!=reason):
                    self.event(c,'warning',u['id'],u['name']+': '+reason)
                    c.execute('INSERT INTO alerts VALUES(?,?) ON CONFLICT(id) DO UPDATE SET reason=excluded.reason',(u['id'],reason))
                elif not reason: c.execute('DELETE FROM alerts WHERE id=?',(u['id'],))
            c.execute('DELETE FROM days WHERE day<?',((dt.datetime.fromtimestamp(now,TZ)-dt.timedelta(days=90)).strftime('%Y-%m-%d'),))
            c.execute('DELETE FROM events WHERE time<?',(now-180*86400,))
        self.online=online;self.updated=now

    def collect(self):
        # Reject samples straddling a server restart.
        epoch=self.epoch();traffic=self.stats_api('traffic');online=self.stats_api('online')
        if epoch!=self.epoch(): return
        self.ingest(traffic,online,epoch)
        with self.db() as c:
            s=self.settings(c)
            blocked=[u['id'] for u in c.execute('SELECT * FROM users') if not self.allowed(u,s) and online.get(u['id'],0)>0]
            blocked.extend(r['id'] for r in c.execute('SELECT id FROM revoked') if online.get(r['id'],0)>0)
        if blocked: self.stats_api('kick',blocked)
        try:
            values=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
            current=(sum(values[:8]),values[3]+values[4])
            if self.last_cpu and current[0]>self.last_cpu[0]:
                self.cpu=round(100*(1-(current[1]-self.last_cpu[1])/(current[0]-self.last_cpu[0])),1)
            self.last_cpu=current
        except OSError: pass

    def public(self):
        now=int(time.time());day=dt.datetime.fromtimestamp(now,TZ).strftime('%Y-%m-%d')
        with self.lock,self.db() as c:
            s=self.settings(c);users=[];fresh=now-self.updated<=20
            for row in c.execute('SELECT * FROM users ORDER BY created,id'):
                u=dict(row);u['suffix']=u.pop('secret')[-4:];u['reason']=self.reason(u)
                u['allowed']=self.allowed(u,s)
                u['connections']=int(self.online.get(u['id'],0)) if fresh else None
                u['online']=bool(u['connections'] and u['allowed']) if fresh else None
                hist=[dict(r) for r in c.execute('SELECT day,up,down FROM days WHERE id=? ORDER BY day',(u['id'],))]
                u['history']=hist;today=next((r for r in hist if r['day']==day),{})
                u['today']=today.get('up',0)+today.get('down',0)
                u['month']=sum(r['up']+r['down'] for r in hist if r['day'].startswith(day[:7]));users.append(u)
            events=[dict(r) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 200')]
        metrics={'cpu':self.cpu,'memory_used':None,'memory_total':None,'service_memory':None,'certificate_expires':None}
        if not self.test:
            try:
                mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
                metrics.update(memory_total=mem['MemTotal'],memory_used=mem['MemTotal']-mem['MemAvailable'])
                metrics['service_memory']=int(subprocess.check_output(['systemctl','show','hysteria-server','-p','MemoryCurrent','--value'],text=True,timeout=3))
            except (OSError,ValueError,subprocess.SubprocessError): pass
            try:
                cert=next(Path('/var/lib/hysteria/acme/certificates').glob('*/'+s['host']+'/'+s['host']+'.crt'))
                end=subprocess.check_output(['openssl','x509','-in',str(cert),'-noout','-enddate'],text=True,timeout=3).strip().split('=',1)[1]
                metrics['certificate_expires']=int(dt.datetime.strptime(end,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc).timestamp())
            except (OSError,ValueError,StopIteration,subprocess.SubprocessError): pass
        return {'users':users,'events':events,'settings':{k:s[k] for k in ('host','port','cover','cover_url','obfs')},
                'paused':s['paused'],'started':s['started'],'updated':self.updated,'telemetry_ok':fresh,'metrics':metrics}

    def apply_settings(self,s):
        if self.test: return
        cfg=yaml.safe_load(self.config.read_text());before=self.config.read_bytes()
        cfg['listen']='0.0.0.0:'+str(s['port'])
        cfg['auth']={'type':'http','http':{'url':'http://127.0.0.1:8083/auth/'+s['auth_token']}}
        cfg['trafficStats']={'listen':'127.0.0.1:9998','secret':s['api_secret']}
        cfg['masquerade']=({'type':'file','file':{'dir':'/var/lib/hysteria/cover'}} if s['cover']=='page' else
                           {'type':'proxy','proxy':{'url':s['cover_url'],'rewriteHost':True,'insecure':False,'xForwarded':False}})
        cfg.pop('obfs',None)
        if s['obfs']: cfg['obfs']={'type':'salamander','salamander':{'password':s['obfs_password']}}
        import grp
        def install(content):
            atomic(self.config,content,0o640);os.chown(self.config,0,grp.getgrnam('hysteria').gr_gid)
        try:
            install(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False))
            subprocess.run(['systemctl','restart','hysteria-server'],check=True,capture_output=True,timeout=30)
            for _ in range(15):
                try:
                    req=urllib.request.Request('http://127.0.0.1:9998/online',headers={'Authorization':s['api_secret']})
                    with urllib.request.urlopen(req,timeout=1): return
                except OSError: time.sleep(.4)
            raise RuntimeError('Hysteria не запустилась с новыми настройками')
        except Exception:
            install(before.decode());subprocess.run(['systemctl','restart','hysteria-server'],capture_output=True,timeout=30)
            raise ValueError('Настройки не применены; прежняя конфигурация восстановлена') from None

    @staticmethod
    def validate_url(value):
        p=urlsplit(value)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.port not in (None,443) or len(value)>500:
            raise ValueError('Нужен публичный HTTPS-сайт без пароля и нестандартного порта')
        addresses=socket.getaddrinfo(p.hostname,443,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError('Адрес сайта должен быть публичным')

    def call(self,p):
        op=p.get('op')
        if op=='status': return self.public()
        with self.lock,self.db() as c:
            s=self.settings(c)
            user=c.execute('SELECT * FROM users WHERE id=?',(p.get('id'),)).fetchone()
            if op=='key':
                if not user: raise ValueError('Ключ не найден')
                params='sni='+quote(s['host'])
                if s['obfs']: params+='&obfs=salamander&obfs-password='+quote(s['obfs_password'],safe='')
                uri='hysteria2://'+quote(user['secret'],safe='')+'@'+s['host']+':'+str(s['port'])+'/?'+params+'#'+quote(user['name'],safe='')
                return {'uri':uri,'host':s['host'],'port':s['port'],'enabled':self.allowed(user,s)}
            kick=[]
            if op=='create':
                name=p.get('name','');group=p.get('group','')
                if not isinstance(name,str) or not 1<=len(name.strip())<=40 or any(ord(x)<32 for x in name): raise ValueError('Имя: от 1 до 40 символов')
                if group not in ('Личное','Семья','Друзья'): raise ValueError('Неверная группа')
                if c.execute('SELECT count(*) FROM users').fetchone()[0]>=100: raise ValueError('Не больше 100 ключей')
                uid='u_'+secrets.token_hex(6)
                c.execute('INSERT INTO users(id,name,grp,secret,enabled,created) VALUES(?,?,?,?,1,?)',(uid,name.strip(),group,secrets.token_urlsafe(32),int(time.time())))
                self.event(c,'create',uid,'Выдан ключ: '+name.strip())
            elif op in ('toggle','rotate','limits'):
                if not user: raise ValueError('Ключ не найден')
                if op=='toggle':
                    if type(p.get('enabled')) is not bool: raise ValueError('Неверное состояние')
                    c.execute('UPDATE users SET enabled=? WHERE id=?',(p['enabled'],user['id']))
                    if not p['enabled']: kick=[user['id']]
                    text='Ключ включён' if p['enabled'] else 'Ключ приостановлен'
                elif op=='rotate':
                    c.execute('UPDATE users SET secret=? WHERE id=?',(secrets.token_urlsafe(32),user['id']));kick=[user['id']];text='Ключ заменён'
                else:
                    quota=p.get('quota_gb');expires=p.get('expires','');enforce=p.get('enforce')
                    if type(quota) not in (float,int) or not 0<=quota<=100000 or type(enforce) is not bool: raise ValueError('Неверные ограничения')
                    if not isinstance(expires,str): raise ValueError('Неверная дата')
                    try: expiry=int(dt.datetime.combine(dt.date.fromisoformat(expires),dt.time(23,59,59),TZ).timestamp()) if expires else 0
                    except ValueError: raise ValueError('Неверная дата') from None
                    c.execute('UPDATE users SET quota=?,expires=?,enforce=? WHERE id=?',(int(quota*1024**3),expiry,enforce,user['id']))
                    after=c.execute('SELECT * FROM users WHERE id=?',(user['id'],)).fetchone()
                    if not self.allowed(after,s): kick=[user['id']]
                    text='Ограничения изменены'
                self.event(c,op,user['id'],text+': '+user['name'])
            elif op=='delete':
                if not user: raise ValueError('Ключ не найден')
                if p.get('confirm_name')!=user['name']: raise ValueError('Для удаления введи точное имя пользователя')
                # Retain the revoked ID so even a failed/racing kick is retried.
                c.execute('INSERT OR IGNORE INTO revoked VALUES(?)',(user['id'],))
                for table in ('users','days','samples','alerts'):
                    c.execute('DELETE FROM '+table+' WHERE id=?',(user['id'],))
                self.event(c,'delete',user['id'],'Профиль удалён: '+user['name'])
                kick=[user['id']]
            elif op=='global':
                if type(p.get('paused')) is not bool: raise ValueError('Неверное состояние')
                c.execute('UPDATE settings SET v=? WHERE k=?',(json.dumps(p['paused']),'paused'))
                if p['paused']: kick=[u['id'] for u in c.execute('SELECT id FROM users')]
                self.event(c,op,'','Все ключи приостановлены' if p['paused'] else 'Все ключи включены')
            elif op=='settings':
                port=p.get('port');cover=p.get('cover');obfs=p.get('obfs')
                if type(port) is not int or not 1024<=port<=65535 or port in (8080,8081,8082,8083,8888,9998) or cover not in ('page','proxy') or type(obfs) is not bool: raise ValueError('Неверные настройки сервера')
                url=p.get('cover_url','')
                if not isinstance(url,str): raise ValueError('Неверный адрес сайта')
                if cover=='proxy': self.validate_url(url)
                if port!=s['port'] and not self.test:
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        try: probe.bind(('0.0.0.0',port))
                        except OSError: raise ValueError('Порт уже занят') from None
                new={**s,'port':port,'cover':cover,'cover_url':url if cover=='proxy' else '', 'obfs':obfs}
                self.apply_settings(new)
                for k in ('port','cover','cover_url','obfs'): c.execute('UPDATE settings SET v=? WHERE k=?',(json.dumps(new[k]),k))
                self.updated=0;self.event(c,op,'','Настройки сервера изменены; клиенты переподключаются')
            else: raise ValueError('Неизвестное действие')
            c.commit()
            if kick and not self.test:
                try: self.stats_api('kick',kick)
                except OSError:
                    LOG.warning('Immediate kick failed; collector will retry')
                    return {'ok':True,'notice':'Ключ закрыт для новых подключений. Отключение текущих будет повторено при восстановлении связи со службой.'}
            return {'ok':True}

def serve(controller):
    import pwd
    uid=pwd.getpwnam('relayadmin').pw_uid
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(35)
            peer=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            if peer not in (0,uid): return
            try:
                raw=self.rfile.readline(16385)
                if len(raw)>16384: raise ValueError('Слишком большой запрос')
                data=controller.call(json.loads(raw));result={'ok':True,'data':data}
            except (ValueError,OSError,sqlite3.Error) as e: result={'ok':False,'error':str(e)}
            except Exception:
                LOG.exception('Controller request failed');result={'ok':False,'error':'Служба управления временно недоступна'}
            self.wfile.write(json.dumps(result,ensure_ascii=False).encode()+b'\n')
    class AuthHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            with controller.db() as c: token=controller.settings(c)['auth_token']
            if not hmac.compare_digest(self.path,'/auth/'+token): self.send_error(404);return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=4096: self.send_error(400);return
                self.connection.settimeout(3)
                payload=json.loads(self.rfile.read(size));result=controller.authenticate(payload.get('auth'))
                raw=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            except Exception: self.send_error(400)
        def log_message(self,*args): pass  # auth URL and passwords never enter access logs
    class UnixServer(socketserver.ThreadingUnixStreamServer): daemon_threads=True
    class AuthServer(ThreadingHTTPServer): daemon_threads=True
    path='/run/relay-hy2/control.sock'
    try: os.unlink(path)
    except FileNotFoundError: pass
    server=UnixServer(path,Handler);os.chmod(path,0o660)
    import grp
    os.chown(path,0,grp.getgrnam('relayadmin').gr_gid)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    threading.Thread(target=AuthServer(('127.0.0.1',8083),AuthHandler).serve_forever,daemon=True).start()
    while True:
        try: controller.collect()
        except Exception: LOG.exception('Accounting sample failed')
        time.sleep(5)

if __name__=='__main__':
    logging.basicConfig(level=logging.INFO)
    serve(Controller())
