"""AmneziaWG 3.1 peers, durable accounting and owner-only local control."""
import base64
from contextlib import contextmanager, nullcontext
import datetime as dt
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time

from migration_state import mutation, blocked

INTERFACE = 'awg-relay'
BINARY = '/usr/local/bin/awg'
TZ = dt.timezone(dt.timedelta(hours=6))
LOG = logging.getLogger('awg-controller')
OBFS = ('S1','S2','S3','S4','H1','H2','H3','H4','HeaderProtectionKey')


def key():
    return subprocess.check_output([BINARY, 'genkey'], text=True, timeout=5).strip()


def public_key(private):
    return subprocess.check_output([BINARY, 'pubkey'], input=private+'\n', text=True, timeout=5).strip()


def valid_key(value):
    try:return isinstance(value,str) and len(base64.b64decode(value,validate=True)) == 32
    except (ValueError,TypeError):return False


def validate_settings(s):
    host=s['host']
    if not isinstance(host,str) or len(host)>253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in host.split('.')):raise ValueError('Некорректный домен AmneziaWG')
    try:ipaddress.ip_address(host)
    except ValueError:pass
    else:raise ValueError('Для AmneziaWG нужен домен, а не IP')
    if type(s['port']) is not int or not 1024 <= s['port'] <= 65535:raise ValueError('Некорректный UDP-порт AmneziaWG')
    if not all(valid_key(s[k]) for k in ('private','public','HeaderProtectionKey')):raise ValueError('Некорректные ключи AmneziaWG')
    for name in ('S1','S2','S3','S4'):
        if type(s[name]) is not int or not 12 <= s[name] <= 128:raise ValueError('Некорректные параметры AmneziaWG')
    headers=[s[k] for k in ('H1','H2','H3','H4')]
    if any(type(v) is not int or not 5 <= v < 2**32 for v in headers) or len(set(headers)) != 4:raise ValueError('Некорректные заголовки AmneziaWG')
    if type(s['paused']) is not bool:raise ValueError('Некорректное состояние AmneziaWG')


class Controller:
    def __init__(self, data='/var/lib/relay-awg', initial=None, test=False):
        self.data=Path(data);self.test=test;self.lock=threading.RLock();self.updated=0;self.online={}
        self.data.mkdir(parents=True,exist_ok=True);self.path=self.data/'awg.sqlite3'
        if not self.path.exists() and initial is None:raise ValueError('AmneziaWG не установлена')
        with self.db() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,grp TEXT,private TEXT,public TEXT UNIQUE,psk TEXT,
              address INTEGER UNIQUE,enabled INTEGER,created INTEGER,expires INTEGER DEFAULT 0,quota INTEGER DEFAULT 0,
              enforce INTEGER DEFAULT 0,last INTEGER DEFAULT 0,up INTEGER DEFAULT 0,down INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS samples(id TEXT PRIMARY KEY,up INTEGER,down INTEGER,epoch TEXT);
            CREATE TABLE IF NOT EXISTS days(id TEXT,day TEXT,up INTEGER,down INTEGER,PRIMARY KEY(id,day));
            ''')
            if not c.execute('SELECT 1 FROM settings').fetchone():
                private=key()
                settings={'host':initial['awg_domain'],'port':initial['awg_port'],'private':private,'public':public_key(private),
                          'paused':False,'HeaderProtectionKey':key()}
                settings.update({k:16+secrets.randbelow(49) for k in ('S1','S2','S3','S4')})
                headers=secrets.SystemRandom().sample(range(256,2**32),4)
                settings.update(zip(('H1','H2','H3','H4'),headers))
                c.executemany('INSERT INTO settings VALUES(?,?)',[(k,json.dumps(v)) for k,v in settings.items()])
            validate_settings(self.settings(c))
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=15);c.row_factory=sqlite3.Row
        try:
            with c:yield c
        finally:c.close()

    @staticmethod
    def settings(c):return {r['k']:json.loads(r['v']) for r in c.execute('SELECT * FROM settings')}

    @staticmethod
    def reason(u,now=None):
        now=int(time.time()) if now is None else now
        if u['expires'] and now>=u['expires']:return 'Срок действия закончился'
        if u['quota'] and u['up']+u['down']>=u['quota']:return 'Лимит трафика исчерпан'
        return ''

    def allowed(self,u,s):return bool(u['enabled'] and not s['paused'] and not (u['enforce'] and self.reason(u)))

    def render(self,c):
        s=self.settings(c);validate_settings(s)
        lines=['[Interface]','PrivateKey = '+s['private'],'ListenPort = '+str(s['port'])]
        lines += [k+' = '+str(s[k]) for k in OBFS]
        for u in c.execute('SELECT * FROM users ORDER BY address'):
            if self.allowed(u,s):lines+=['','[Peer]','PublicKey = '+u['public'],'PresharedKey = '+u['psk'],
                                       'AllowedIPs = 10.77.0.'+str(u['address'])+'/32, fd77:77::'+format(u['address'],'x')+'/128']
        return '\n'.join(lines)+'\n'

    def apply(self,c):
        if self.test:return
        # syncconf preserves sessions/counters of unchanged peers. No keys in argv or logs.
        with tempfile.NamedTemporaryFile(mode='w',dir='/run/relay-awg',prefix='peers-',delete=False) as f:
            path=Path(f.name)
            try:
                path.chmod(0o600);f.write(self.render(c));f.flush()
                subprocess.run([BINARY,'syncconf',INTERFACE,str(path)],check=True,capture_output=True,timeout=10)
            finally:path.unlink(missing_ok=True)

    def epoch(self):
        return subprocess.check_output(['systemctl','show','amneziawg-server','-p','InvocationID','--value'],text=True,timeout=5).strip()

    def ingest(self,rows,epoch,now=None):
        now=int(time.time()) if now is None else now;day=dt.datetime.fromtimestamp(now,TZ).strftime('%Y-%m-%d')
        online={}
        with self.db() as c:
            for u in c.execute('SELECT * FROM users').fetchall():
                row=rows.get(u['public'])
                if row is None:
                    c.execute('DELETE FROM samples WHERE id=?',(u['id'],));continue
                up,down,last=row
                if any(type(v) is not int or v<0 for v in row):raise ValueError('Некорректные счётчики AmneziaWG')
                old=c.execute('SELECT * FROM samples WHERE id=?',(u['id'],)).fetchone()
                du=up-old['up'] if old and old['epoch']==epoch and up>=old['up'] else up
                dd=down-old['down'] if old and old['epoch']==epoch and down>=old['down'] else down
                c.execute('INSERT OR REPLACE INTO samples VALUES(?,?,?,?)',(u['id'],up,down,epoch))
                c.execute('UPDATE users SET up=up+?,down=down+?,last=max(last,?) WHERE id=?',(du,dd,last,u['id']))
                c.execute('INSERT INTO days VALUES(?,?,?,?) ON CONFLICT(id,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(u['id'],day,du,dd))
                online[u['id']]=bool(last and now-last<180)
            c.execute('DELETE FROM days WHERE day<?',((dt.datetime.fromtimestamp(now,TZ)-dt.timedelta(days=90)).strftime('%Y-%m-%d'),))
        self.online=online;self.updated=now

    def collect(self):
        epoch=self.epoch()
        raw=subprocess.check_output([BINARY,'show',INTERFACE,'dump'],text=True,timeout=5)
        rows={}
        for line in raw.splitlines()[1:]:
            fields=line.split('\t')
            if len(fields)!=8:raise ValueError('Неизвестный формат статистики AmneziaWG')
            # Server RX is client upload; server TX is client download.
            rows[fields[0]]=(int(fields[5]),int(fields[6]),int(fields[4]))
        if epoch!=self.epoch():return
        self.ingest(rows,epoch)
        with self.db() as c:self.apply(c)  # enforce quotas/expiry and retry earlier failed sync

    def public(self):
        with self.lock,self.db() as c:
            s=self.settings(c);users=[]
            for u in c.execute('SELECT * FROM users ORDER BY created,id'):
                users.append({**{k:u[k] for k in ('id','name','grp','enabled','created','expires','quota','enforce','last','up','down')},
                              'allowed':self.allowed(u,s),'reason':self.reason(u),'online':bool(time.time()-self.updated<20 and self.online.get(u['id'])),
                              'address':'10.77.0.'+str(u['address']),
                              'history':[dict(r) for r in c.execute('SELECT day,up,down FROM days WHERE id=? ORDER BY day',(u['id'],))]})
            return {'users':users,'host':s['host'],'port':s['port'],'paused':s['paused'],'updated':self.updated,'version':'3.1'}

    def config(self,u,s):
        lines=['[Interface]','PrivateKey = '+u['private'],
               'Address = 10.77.0.'+str(u['address'])+'/32, fd77:77::'+format(u['address'],'x')+'/128',
               'DNS = 1.1.1.1, 1.0.0.1','MTU = 1280','Jc = 4','Jmin = 40','Jmax = 100']
        lines += [k+' = '+str(s[k]) for k in OBFS]
        lines += ['','[Peer]','PublicKey = '+s['public'],'PresharedKey = '+u['psk'],
                  'Endpoint = '+s['host']+':'+str(s['port']),'AllowedIPs = 0.0.0.0/0, ::/0','PersistentKeepalive = 25']
        return '\n'.join(lines)+'\n'

    def call(self,p):
        op=p.get('op')
        if op=='status':return self.public()
        if op=='migration_ready':
            subprocess.run([BINARY,'show',INTERFACE,'public-key'],check=True,capture_output=True,timeout=5);return {'ok':True}
        if op=='migration_sample':
            with self.lock:self.collect()
            return {'ok':True}
        with self.lock,mutation() if op!='key' else nullcontext(),self.db() as c:
            s=self.settings(c);u=c.execute('SELECT * FROM users WHERE id=?',(p.get('id'),)).fetchone()
            if op=='key':
                if not u:raise ValueError('Ключ не найден')
                return {'conf':self.config(u,s),'filename':u['id']+'.conf','enabled':self.allowed(u,s)}
            if op not in ('create','toggle','rotate','limits','delete','global'):raise ValueError('Неизвестная операция')
            # Take a final sample before removing/resetting a peer and its counters.
            if not self.test:self.collect()
            if op=='create':
                name=p.get('name');group=p.get('group')
                if not isinstance(name,str) or not 1<=len(name.strip())<=40 or any(ord(v)<32 for v in name):raise ValueError('Имя: от 1 до 40 символов')
                if group not in ('Личное','Семья','Друзья'):raise ValueError('Неверная группа')
                addresses={r[0] for r in c.execute('SELECT address FROM users')}
                if len(addresses)>=100:raise ValueError('Не больше 100 ключей')
                address=next(v for v in range(2,255) if v not in addresses);uid='u_'+secrets.token_hex(6);private=key()
                c.execute('INSERT INTO users(id,name,grp,private,public,psk,address,enabled,created) VALUES(?,?,?,?,?,?,?,1,?)',
                          (uid,name.strip(),group,private,public_key(private),key(),address,int(time.time())))
            elif op=='global':
                if type(p.get('paused')) is not bool:raise ValueError('Неверное состояние')
                c.execute("UPDATE settings SET v=? WHERE k='paused'",(json.dumps(p['paused']),))
            else:
                if not u:raise ValueError('Ключ не найден')
                if op=='toggle':
                    if type(p.get('enabled')) is not bool:raise ValueError('Неверное состояние')
                    c.execute('UPDATE users SET enabled=? WHERE id=?',(p['enabled'],u['id']))
                    if not p['enabled']:c.execute('DELETE FROM samples WHERE id=?',(u['id'],))
                elif op=='rotate':
                    private=key();c.execute('UPDATE users SET private=?,public=?,psk=? WHERE id=?',(private,public_key(private),key(),u['id']))
                    c.execute('DELETE FROM samples WHERE id=?',(u['id'],))
                elif op=='delete':
                    if p.get('confirm_name')!=u['name']:raise ValueError('Введи точное имя пользователя')
                    for table in ('users','samples','days'):c.execute('DELETE FROM '+table+' WHERE id=?',(u['id'],))
                elif op=='limits':
                    quota=p.get('quota_gb');expires=p.get('expires','');enforce=p.get('enforce')
                    if type(quota) not in (int,float) or not math.isfinite(quota) or not 0<=quota<=100000 or type(enforce) is not bool or not isinstance(expires,str):raise ValueError('Неверные ограничения')
                    try:expiry=int(dt.datetime.combine(dt.date.fromisoformat(expires),dt.time(23,59,59),TZ).timestamp()) if expires else 0
                    except ValueError:raise ValueError('Неверная дата') from None
                    c.execute('UPDATE users SET quota=?,expires=?,enforce=? WHERE id=?',(int(quota*1024**3),expiry,enforce,u['id']))
            if op=='global' and p['paused']:c.execute('DELETE FROM samples')
            # Commit desired state first: collector reapplies it if the service is interrupted.
            c.commit()
            try:self.apply(c)
            except (OSError,subprocess.SubprocessError):
                LOG.error('AmneziaWG configuration sync failed')
                return {'ok':True,'notice':'Изменения сохранены. Применение к VPN пока не подтверждено; служба повторит попытку.'}
        from backup_notify import changed
        changed('awg')
        return {'ok':True}


def serve(controller):
    import pwd,grp
    uid=pwd.getpwnam('relayadmin').pw_uid
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(35)
            peer=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            if peer not in (0,uid):return
            try:
                raw=self.rfile.readline(16385)
                if len(raw)>16384:raise ValueError('Слишком большой запрос')
                p=json.loads(raw)
                if not isinstance(p,dict):raise ValueError('Неверный запрос')
                if str(p.get('op','')).startswith('migration_') and peer!=0:raise ValueError('Нужен root')
                result={'ok':True,'data':controller.call(p)}
            except (ValueError,OSError,sqlite3.Error,subprocess.SubprocessError):result={'ok':False,'error':'Операция AmneziaWG не выполнена. Проверь данные и состояние службы.'}
            self.wfile.write(json.dumps(result,ensure_ascii=False).encode()+b'\n')
    class Server(socketserver.ThreadingUnixStreamServer):daemon_threads=True
    path='/run/relay-awg-control/control.sock';Path(path).unlink(missing_ok=True)
    server=Server(path,Handler);os.chmod(path,0o660);os.chown(path,0,grp.getgrnam('relayadmin').gr_gid)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    while True:
        try:
            with controller.lock:controller.collect()
        except Exception:LOG.error('AmneziaWG accounting/sync unavailable')
        time.sleep(5)


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO)
    serve(Controller())
