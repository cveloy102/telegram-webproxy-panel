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
import unicodedata

from migration_state import mutation
import awg_routing as routing

INTERFACE = 'awg-relay'
BINARY = '/usr/local/bin/awg'
TZ = dt.timezone(dt.timedelta(hours=6))
LOG = logging.getLogger('awg-controller')
OBFS = ('S1','S2','S3','S4','H1','H2','H3','H4','HeaderProtectionKey')


def cascade_state():
    try:return json.loads(Path('/etc/relay-cascade/state.json').read_text())
    except (OSError,ValueError):return {}


def profile_filename(name, fallback):
    # awg-quick uses the filename as an interface name: ASCII, at most 15 chars.
    name = str(name or '')
    letters = dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
                       ('a','b','v','g','d','e','yo','zh','z','i','y','k','l','m','n','o','p','r','s','t','u','f','kh','ts','ch','sh','shch','','y','','e','yu','ya')))
    translated = ''.join((letters[char.lower()].capitalize() if char.isupper() else letters[char.lower()])
                         if char.lower() in letters else char for char in name)
    if name.isupper(): translated = translated.upper()
    ascii_name = unicodedata.normalize('NFKD', translated).encode('ascii', 'ignore').decode()
    stem = re.sub(r'[^A-Za-z0-9_-]+', '-', ascii_name).strip('-_')[:15].rstrip('-_')
    if not stem: stem = re.sub(r'[^A-Za-z0-9_-]', '', fallback)[:15] or 'AmneziaWG'
    if re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', stem.upper()):
        stem += '-VPN'
    return stem + '.conf'


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
        self.routing_runtime=routing.Runtime();self.routing_error='';self.geo_lock=threading.Lock()
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
            CREATE TABLE IF NOT EXISTS routing_pending(address INTEGER PRIMARY KEY);
            ''')
            # Legacy rows retain the exact previous all-through-cascade behavior.
            if 'routing' not in {r['name'] for r in c.execute('PRAGMA table_info(users)')}:
                c.execute("ALTER TABLE users ADD COLUMN routing TEXT NOT NULL DEFAULT 'cascade'")
            if not c.execute('SELECT 1 FROM settings').fetchone():
                private=key()
                settings={'host':initial['awg_domain'],'port':initial['awg_port'],'private':private,'public':public_key(private),
                          'paused':False,'HeaderProtectionKey':key()}
                settings.update({k:16+secrets.randbelow(49) for k in ('S1','S2','S3','S4')})
                headers=secrets.SystemRandom().sample(range(256,2**32),4)
                settings.update(zip(('H1','H2','H3','H4'),headers))
                c.executemany('INSERT INTO settings VALUES(?,?)',[(k,json.dumps(v)) for k,v in settings.items()])
            validate_settings(self.settings(c))
            if not c.execute("SELECT 1 FROM settings WHERE k='routing_geo'").fetchone():
                try:routing.put(c,'routing_geo',routing.seed())
                except (ValueError,OSError):LOG.error('AWG RU seed unavailable; split profiles will be blocked')
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
        self.apply_routing(c)
        # syncconf preserves sessions/counters of unchanged peers. No keys in argv or logs.
        with tempfile.NamedTemporaryFile(mode='w',dir='/run/amneziawg',prefix='peers-',delete=False) as f:
            path=Path(f.name)
            try:
                path.chmod(0o600);f.write(self.render(c));f.flush()
                subprocess.run([BINARY,'syncconf',INTERFACE,str(path)],check=True,capture_output=True,timeout=10)
            finally:path.unlink(missing_ok=True)

    def apply_routing(self,c):
        split=['10.77.0.'+str(u['address']) for u in c.execute("SELECT address FROM users WHERE routing='ru_split'")]
        try:geo=routing.load(c)
        except (ValueError,TypeError):geo=None
        pending=[r['address'] for r in c.execute('SELECT address FROM routing_pending ORDER BY address')]
        self.routing_runtime.install(split,geo['networks'] if geo else [],['10.77.0.'+str(x) for x in pending])
        # Desired modes are durable. Until old NAT flows are removed, only the
        # affected peers are blocked; a controller restart retries the reset.
        deadline=time.monotonic()+3
        for address in pending:
            if time.monotonic()>=deadline:break
            routing.clear_connections('10.77.0.'+str(address))
            c.execute('DELETE FROM routing_pending WHERE address=?',(address,))
        remaining=[r['address'] for r in c.execute('SELECT address FROM routing_pending')]
        self.routing_runtime.install(split,geo['networks'] if geo else [],['10.77.0.'+str(x) for x in remaining])
        self.routing_error=''

    @staticmethod
    def queue_routing_reset(c,address=None):
        if address is None:
            c.execute("INSERT OR IGNORE INTO routing_pending SELECT address FROM users WHERE routing='ru_split'")
        else:c.execute('INSERT OR IGNORE INTO routing_pending VALUES(?)',(address,))

    def geo_update(self):
        if not self.geo_lock.acquire(blocking=False):raise ValueError('Обновление RU-базы уже выполняется.')
        try:
            with mutation():
                # Download outside the controller lock: stats and peer actions
                # remain available while the source is slow/unreachable.
                try:new=routing.fetch()
                except (OSError,ValueError,subprocess.SubprocessError):
                    with self.lock,self.db() as c:
                        routing.put(c,'routing_checked',int(time.time()))
                        routing.put(c,'routing_error','Не удалось загрузить RU-базу. Сохранён последний исправный список.')
                    raise ValueError('Не удалось загрузить RU-базу. Сохранён последний исправный список.') from None
                with self.lock,self.db() as c:
                    try:
                        try:old=routing.load(c)
                        except (ValueError,TypeError):old=None
                        if old:routing.check_change(old,new)
                    except ValueError as error:
                        routing.put(c,'routing_checked',int(time.time()));routing.put(c,'routing_error',str(error));c.commit()
                        raise
                    if not old or old['sha256']!=new['sha256']:
                        if old:routing.put(c,'routing_previous',old)
                        routing.put(c,'routing_geo',new)
                        self.queue_routing_reset(c)
                    routing.put(c,'routing_checked',int(time.time()));routing.put(c,'routing_error','')
                    routing.put(c,'routing_hold',False);c.commit()
                    from backup_notify import changed
                    changed('awg')
                    try:
                        if not self.test:self.apply_routing(c)
                    except (OSError,subprocess.SubprocessError):
                        self.routing_error='RU-база сохранена; применение маршрутов будет повторено.'
                        return {'ok':True,'notice':self.routing_error}
            return {'ok':True,'notice':'RU-база проверена и обновлена.'}
        finally:self.geo_lock.release()

    def geo_worker(self):
        while True:
            try:
                with self.db() as c:s=self.settings(c)
                delay=3600 if s.get('routing_error') else routing.DAY
                if not s.get('routing_hold') and time.time()-s.get('routing_checked',0)>=delay:self.geo_update()
            except Exception:LOG.error('AWG RU list update unavailable')
            time.sleep(60)

    def routing_status(self,c,s):
        try:geo=routing.load(c)
        except (ValueError,TypeError):geo=None
        try:previous=routing.load(c,'routing_previous')
        except (ValueError,TypeError):previous=None
        cascade=cascade_state()
        configured=bool(cascade.get('exit_public_key'))
        return {'source':routing.SOURCE,'ready':bool(geo),'count':len(geo['networks']) if geo else 0,
                'fetched':geo['fetched'] if geo else 0,'sha256':geo['sha256'] if geo else '',
                'checked':s.get('routing_checked',0),'error':s.get('routing_error','') or self.routing_error,
                'can_rollback':bool(previous),'cascade_enabled':cascade.get('enabled') is True,
                'cascade_configured':configured,'default':'ru_split' if configured else 'cascade',
                'auto_paused':bool(s.get('routing_hold')),
                'classifier':'geoip-v1','dns_enabled':False}

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
                online[u['id']]=bool(last and 0<=now-last<180)
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
            s=self.settings(c);users=[];now=time.time()
            fresh=bool(self.updated and 0<=now-self.updated<20)
            pending={r['address'] for r in c.execute('SELECT address FROM routing_pending')}
            route_state=self.routing_status(c,s)
            day=dt.datetime.fromtimestamp(now,TZ).strftime('%Y-%m-%d');month=day[:7]
            for u in c.execute('SELECT * FROM users ORDER BY created,id'):
                history=[dict(r) for r in c.execute('SELECT day,up,down FROM days WHERE id=? ORDER BY day',(u['id'],))]
                allowed=self.allowed(u,s)
                users.append({**{k:u[k] for k in ('id','name','grp','enabled','created','expires','quota','enforce','last','up','down')},
                              'allowed':allowed,'reason':self.reason(u),
                              'online':bool(allowed and fresh and self.online.get(u['id']) and u['address'] not in pending
                                            and (u['routing']!='ru_split' or route_state['ready'])),
                              'address':'10.77.0.'+str(u['address']),
                              'routing':u['routing'],'routing_pending':u['address'] in pending,
                              'today':sum(r['up']+r['down'] for r in history if r['day']==day),
                              'month':sum(r['up']+r['down'] for r in history if r['day'].startswith(month)),
                              'history':history})
            return {'users':users,'host':s['host'],'port':s['port'],'paused':s['paused'],'updated':self.updated,'telemetry_ok':fresh,'version':'3.1',
                    'routing':route_state}

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
        if op=='geo_update':return self.geo_update()
        if op=='route_check':
            try:address=ipaddress.IPv4Address(p.get('address'))
            except (ValueError,TypeError):raise ValueError('Введи IPv4-адрес назначения.') from None
            if not address.is_global or any(address in net for net in routing.FORBIDDEN):raise ValueError('Нужен публичный IPv4-адрес.')
            with self.lock,self.db() as c:
                u=c.execute('SELECT * FROM users WHERE id=?',(p.get('id'),)).fetchone()
                if not u:raise ValueError('Профиль не найден.')
                if c.execute('SELECT 1 FROM routing_pending WHERE address=?',(u['address'],)).fetchone():
                    return {'route':'blocked','reason':'Применяется режим; прежние соединения сбрасываются.'}
                try:geo=routing.load(c)
                except (ValueError,TypeError):geo=None
                if u['routing']=='ru_split' and not geo:return {'route':'blocked','reason':'Нет исправной RU-базы.'}
                if not self.routing_status(c,self.settings(c))['cascade_enabled']:
                    return {'route':'ru','reason':'Каскад глобально выключен: разрешён прямой выход через RU.'}
                if u['routing']=='cascade':return {'route':'cascade','reason':'Для профиля выбран полный каскад.'}
                network=next((x for x in geo['networks'] if address in ipaddress.ip_network(x)),None)
                return {'route':'ru' if network else 'cascade','reason':'RU-сеть '+network if network else 'Адрес не входит в RU-базу.'}
        if op=='migration_ready':
            actual=subprocess.check_output([BINARY,'show',INTERFACE,'public-key'],text=True,timeout=5).strip()
            port=subprocess.check_output([BINARY,'show',INTERFACE,'listen-port'],text=True,timeout=5).strip()
            with self.db() as c:s=self.settings(c)
            if actual!=s['public'] or port!=str(s['port']):raise ValueError('AmneziaWG ещё применяет настройки')
            return {'ok':True}
        if op=='migration_sample':
            with self.lock:self.collect()
            return {'ok':True}
        with (self.geo_lock if op=='geo_rollback' else nullcontext()),self.lock,mutation() if op!='key' else nullcontext(),self.db() as c:
            s=self.settings(c);u=c.execute('SELECT * FROM users WHERE id=?',(p.get('id'),)).fetchone()
            if op=='key':
                if not u:raise ValueError('Ключ не найден')
                return {'conf':self.config(u,s),'filename':profile_filename(u['name'],u['id']),'name':u['name'],'enabled':self.allowed(u,s)}
            if op=='rename':
                if not u:raise ValueError('Профиль не найден')
                name=p.get('name')
                if not isinstance(name,str) or not 1<=len(name.strip())<=40 or any(ord(v)<32 for v in name):raise ValueError('Имя: от 1 до 40 символов')
                c.execute('UPDATE users SET name=? WHERE id=?',(name.strip(),u['id']))
                c.commit()
                from backup_notify import changed
                changed('awg')
                return {'ok':True}
            if op not in ('create','toggle','rotate','limits','delete','global','routing','geo_rollback'):raise ValueError('Неизвестная операция')
            # Take a final sample before removing/resetting a peer and its counters.
            if not self.test:self.collect()
            if op=='create':
                name=p.get('name');group=p.get('group')
                if not isinstance(name,str) or not 1<=len(name.strip())<=40 or any(ord(v)<32 for v in name):raise ValueError('Имя: от 1 до 40 символов')
                if group not in ('Личное','Семья','Друзья'):raise ValueError('Неверная группа')
                addresses={r[0] for r in c.execute('SELECT address FROM users')}
                if len(addresses)>=100:raise ValueError('Не больше 100 ключей')
                address=next(v for v in range(2,255) if v not in addresses);uid='u_'+secrets.token_hex(6);private=key()
                mode=routing.policy(p.get('routing','ru_split' if cascade_state().get('exit_public_key') else 'cascade'))
                c.execute('INSERT INTO users(id,name,grp,private,public,psk,address,enabled,created,routing) VALUES(?,?,?,?,?,?,?,1,?,?)',
                          (uid,name.strip(),group,private,public_key(private),key(),address,int(time.time()),mode))
                self.queue_routing_reset(c,address)
            elif op=='geo_rollback':
                previous=routing.load(c,'routing_previous')
                if not previous:raise ValueError('Нет предыдущей исправной RU-базы.')
                try:current=routing.load(c)
                except (ValueError,TypeError):current=None
                routing.put(c,'routing_geo',previous)
                if current:routing.put(c,'routing_previous',current)
                else:c.execute("DELETE FROM settings WHERE k='routing_previous'")
                routing.put(c,'routing_checked',int(time.time()));routing.put(c,'routing_error','')
                routing.put(c,'routing_hold',True)
                self.queue_routing_reset(c)
            elif op=='global':
                if type(p.get('paused')) is not bool:raise ValueError('Неверное состояние')
                c.execute("UPDATE settings SET v=? WHERE k='paused'",(json.dumps(p['paused']),))
            else:
                if not u:raise ValueError('Ключ не найден')
                if op=='routing':
                    mode=routing.policy(p.get('routing'))
                    if mode!=u['routing']:
                        c.execute('UPDATE users SET routing=? WHERE id=?',(mode,u['id']))
                        self.queue_routing_reset(c,u['address'])
                elif op=='toggle':
                    if type(p.get('enabled')) is not bool:raise ValueError('Неверное состояние')
                    c.execute('UPDATE users SET enabled=? WHERE id=?',(p['enabled'],u['id']))
                    if not p['enabled']:c.execute('DELETE FROM samples WHERE id=?',(u['id'],))
                elif op=='rotate':
                    private=key();c.execute('UPDATE users SET private=?,public=?,psk=? WHERE id=?',(private,public_key(private),key(),u['id']))
                    c.execute('DELETE FROM samples WHERE id=?',(u['id'],))
                elif op=='delete':
                    if p.get('confirm_name')!=u['name']:raise ValueError('Введи точное имя пользователя')
                    self.queue_routing_reset(c,u['address'])
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
            from backup_notify import changed
            changed('awg')
            try:self.apply(c)
            except (OSError,subprocess.SubprocessError):
                LOG.error('AmneziaWG configuration sync failed')
                self.routing_error='Применение настроек AWG не подтверждено; служба повторит попытку.'
                return {'ok':True,'notice':'Изменения сохранены. Применение к VPN пока не подтверждено; служба повторит попытку.'}
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
    threading.Thread(target=controller.geo_worker,daemon=True).start()
    while True:
        try:
            with controller.lock:controller.collect()
        except Exception:LOG.error('AmneziaWG accounting/sync unavailable')
        time.sleep(5)


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO)
    serve(Controller())
