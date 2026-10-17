from backup_notify import changed as backup_changed
import base64
import datetime as dt
import hashlib
import hmac
import io
import ipaddress
import json
import os
import pathlib
import secrets
import socket
import sqlite3
import struct
import threading
import time
from urllib.parse import quote

import qrcode
from flask import Flask, abort, jsonify, redirect, render_template, request, session, g
from migration_state import mutation, blocked, state as migration_state
from werkzeug.middleware.proxy_fix import ProxyFix

DATA = pathlib.Path(os.getenv('RELAY_DATA', '/var/lib/relay-panel'))
CONFIG = json.loads((DATA / 'auth.json').read_text())
DB = DATA / 'panel.sqlite3'
USAGE = pathlib.Path(os.getenv('RELAY_USAGE', '/var/lib/tproxy-accounting/usage.json'))
HOST = CONFIG['host']
PREFIX = '/control'
app = Flask(__name__)
app.secret_key = CONFIG['session_key']
app.config.update(SESSION_COOKIE_NAME='relay_owner', SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_PATH=PREFIX, MAX_CONTENT_LENGTH=16384,
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1),salt TEXT,hash TEXT,totp TEXT,verified INTEGER,last_step INTEGER);
        CREATE TABLE IF NOT EXISTS recovery(hash TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),networks INTEGER,traffic_gb INTEGER,minutes INTEGER);
        INSERT OR IGNORE INTO settings VALUES(1,3,2,5);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time INTEGER,profile TEXT,kind TEXT,text TEXT,ack INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS monitor(profile TEXT,kind TEXT,since INTEGER,active INTEGER DEFAULT 0,PRIMARY KEY(profile,kind));
        CREATE TABLE IF NOT EXISTS failures(ip TEXT PRIMARY KEY,count INTEGER,start INTEGER);
        ''')
    os.chmod(DB, 0o600)
init_db()

def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=128*1024*1024).hex()

def otp(seed, step):
    key = base64.b32decode(seed + '=' * (-len(seed) % 8))
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)

def otp_step(seed, code):
    if not isinstance(code, str) or not code.isascii() or not code.isdigit() or len(code)!=6:
        return None
    now=int(time.time())//30
    return next((step for step in range(now-1, now+2) if hmac.compare_digest(otp(seed,step),code)),None)

def recovery_hash(value):
    return hmac.new(CONFIG['session_key'].encode(), value.strip().upper().encode(), hashlib.sha256).hexdigest()

def csrf():
    if 'csrf' not in session:
        session['csrf']=secrets.token_hex(24)
    return session['csrf']

def owner():
    with db() as conn:
        return conn.execute('SELECT * FROM owner WHERE id=1').fetchone()

def authorized():
    return session.get('owner') is True and bool(owner() and owner()['verified'])

from hy2_routes import register as register_hysteria
register_hysteria(app,authorized,csrf)
from awg_routes import register as register_amnezia
register_amnezia(app,authorized,csrf)

from backup_routes import register as register_backups
register_backups(app,authorized,csrf)
from migration_routes import register as register_migration
register_migration(app,authorized,csrf)

@app.context_processor
def migration_context():
    return {'migration_blocked':blocked()}

@app.before_request
def protect():
    if request.host != HOST:
        abort(400)
    if request.method=='POST':
        origin=request.headers.get('Origin')
        if origin != 'https://'+HOST:
            abort(403)
        value=request.headers.get('X-CSRF-Token') or request.form.get('csrf','')
        if not hmac.compare_digest(value, session.get('csrf','missing')):
            abort(403)
    if request.path.startswith(PREFIX+'/api/') and not authorized():
        abort(401)
    phase=migration_state().get('phase')
    backup_payload=request.get_json(silent=True)
    repair_backup=request.path==PREFIX+'/api/backup/action' and phase=='error' and isinstance(backup_payload,dict) and backup_payload.get('op') in ('configure','connect')
    auth_stopped=request.path==PREFIX+'/login' and phase not in ('running','freezing','resuming')
    if request.method=='POST' and request.path not in (PREFIX+'/logout',PREFIX+'/api/migration/action') and not auth_stopped and not repair_backup:
        try:
            guard=mutation();guard.__enter__();g.migration_guard=guard
        except ValueError as error:return jsonify(error=str(error)),409
    if request.method=='POST' and request.path==PREFIX+'/login' and phase in ('freezing','resuming'):
        return 'Перенос выполняется. Дождись завершения и повтори вход.',409

@app.teardown_request
def release_migration_guard(error):
    guard=g.pop('migration_guard',None)
    if guard is not None:guard.__exit__(None,None,None)

@app.get('/maintenance')
def maintenance():
    return ('Сервер остановлен для переноса. Подключения временно недоступны.' if blocked() else 'Служба временно недоступна. Попробуй подключиться позже.'),503

@app.after_request
def headers(response):
    response.headers['Cache-Control']='no-store'
    # Native form POSTs may send Origin:null under no-referrer.
    # Keep same-origin form provenance; do not disclose referrers externally.
    response.headers['Referrer-Policy']='same-origin'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    return response

def helper(payload):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(80)
        sock.connect('/run/relay-helper/control.sock')
        sock.sendall(json.dumps(payload,ensure_ascii=False).encode()+b'\n')
        data=b''
        while not data.endswith(b'\n'):
            chunk=sock.recv(65536)
            if not chunk or len(data)>1048576:
                break
            data+=chunk
    result=json.loads(data)
    if not result['ok']:
        raise ValueError(result['error'])
    return result['data']

def usage():
    try:
        return json.loads(USAGE.read_text())
    except (OSError,ValueError):
        return {'started':None,'updated':0,'rows':{}}

def subnet(address):
    parsed=ipaddress.ip_address(address)
    return str(ipaddress.ip_network(f'{parsed}/{24 if parsed.version==4 else 64}',strict=False))

def state_data():
    state=helper({'op':'status'})
    account=usage()
    now=int(time.time())
    fresh=now-account['updated']<=20
    day=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
    for u in state['users']:
        rows=[dict(row) for row in account['rows'].values() if row['profile']==u['id']]
        enabled=u['enabled'] and not state['paused']
        groups={}
        u.update(up=0,down=0,today_up=0,today_down=0,last=0,connected=0,live=0,groups=[])
        for row in rows:
            row['live']=row['live'] if fresh and enabled else 0
            network=subnet(row['ip'])
            row['network']=network
            groups.setdefault(network,[]).append(row)
            u['up']+=row['up'];u['down']+=row['down'];u['live']+=row['live']
            u['last']=max(u['last'],row['last']);u['connected']=max(u['connected'],row['connected'])
            today=row.get('days',{}).get(day,{})
            u['today_up']+=today.get('up',0);u['today_down']+=today.get('down',0)
        for network,ips in groups.items():
            ips.sort(key=lambda r:r['last'],reverse=True)
            u['groups'].append({'network':network,'ips':ips,'live':sum(r['live'] for r in ips)})
        u['groups'].sort(key=lambda g:(g['live']>0,max(i['last'] for i in g['ips'])),reverse=True)
        u['online']=enabled and u['live']>0
    with db() as conn:
        alerts=[dict(r) for r in conn.execute("SELECT * FROM events WHERE kind IN ('networks','traffic') AND ack=0 ORDER BY time DESC LIMIT 100")]
        events=[dict(r) for r in conn.execute('SELECT * FROM events ORDER BY time DESC LIMIT 200')]
        settings=dict(conn.execute('SELECT networks,traffic_gb,minutes FROM settings WHERE id=1').fetchone())
    return {**state,'alerts':alerts,'activity_events':events,'settings':settings,
            'started':account['started'],'updated':account['updated'],'telemetry_ok':fresh}

def monitor_once():
    state=helper({'op':'status'}); account=usage(); now=int(time.time())
    if now-account['updated']>20:
        return
    hour=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H')
    with db() as conn:
        cfg=conn.execute('SELECT * FROM settings WHERE id=1').fetchone()
        for u in state['users']:
            rows=[r for r in account['rows'].values() if r['profile']==u['id']]
            enabled=u['enabled'] and not state['paused']
            networks={subnet(r['ip']) for r in rows if r['live']>0 and enabled}
            traffic=sum(sum(r.get('hours',{}).get(hour,{}).values()) for r in rows)
            conditions={'networks':len(networks)>=cfg['networks'],
                        'traffic':cfg['traffic_gb']>0 and traffic>=cfg['traffic_gb']*1024**3,
                        'first':bool(rows)}
            for kind,condition in conditions.items():
                entry=conn.execute('SELECT * FROM monitor WHERE profile=? AND kind=?',(u['id'],kind)).fetchone()
                if not condition:
                    if entry and kind!='first':
                        conn.execute('DELETE FROM monitor WHERE profile=? AND kind=?',(u['id'],kind))
                    continue
                if not entry:
                    conn.execute('INSERT INTO monitor(profile,kind,since) VALUES(?,?,?)',(u['id'],kind,now))
                    since,active=now,False
                else:
                    since,active=entry['since'],entry['active']
                delay=cfg['minutes']*60 if kind=='networks' else 0
                if not active and now-since>=delay:
                    texts={'networks':f"{u['name']}: {len(networks)} подсети одновременно более {cfg['minutes']} минут. Проверь подключения.",
                           'traffic':f"{u['name']}: больше {cfg['traffic_gb']} ГБ за текущий час.",
                           'first':f"{u['name']}: первое подключение после включения учёта."}
                    conn.execute('INSERT INTO events(time,profile,kind,text) VALUES(?,?,?,?)',(now,u['id'],kind,texts[kind]))
                    conn.execute('UPDATE monitor SET active=1 WHERE profile=? AND kind=?',(u['id'],kind))
        conn.execute('DELETE FROM events WHERE time<?',(now-180*86400,))

def monitor_loop():
    while True:
        try:
            with mutation():monitor_once()
        except Exception:
            pass
        time.sleep(5)

@app.get(PREFIX)
def slash():
    return redirect(PREFIX+'/')

@app.get(PREFIX+'/')
def home():
    if not owner():
        return render_template('auth.html',mode='setup',csrf=csrf(),error=None)
    if session.get('enroll') and not owner()['verified']:
        return enrollment()
    if not authorized():
        return render_template('auth.html',mode='login',csrf=csrf(),error=None)
    return render_template('index.html',csrf=csrf(),host=HOST)

def enrollment(error=None):
    seed=owner()['totp']
    uri='otpauth://totp/RELAY:owner?secret='+seed+'&issuer=RELAY&algorithm=SHA1&digits=6&period=30'
    image=qrcode.make(uri); buffer=io.BytesIO();image.save(buffer,format='PNG')
    return render_template('auth.html',mode='enroll',csrf=csrf(),error=error,
                           qr=base64.b64encode(buffer.getvalue()).decode(),seed=seed)

def limited():
    now=int(time.time())
    with db() as conn:
        row=conn.execute('SELECT * FROM failures WHERE ip=?',(request.remote_addr,)).fetchone()
        if row and now-row['start']<900 and row['count']>=10:
            return True
    return False

def failed():
    now=int(time.time())
    with db() as conn:
        conn.execute('DELETE FROM failures WHERE start<?',(now-900,))
        conn.execute('INSERT INTO failures VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=count+1',(request.remote_addr,now))

@app.post(PREFIX+'/setup')
def setup():
    if owner() or limited():
        abort(403)
    token=request.form.get('code','')
    if time.time()>CONFIG['setup_expires'] or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),CONFIG['setup_hash']):
        failed()
        return render_template('auth.html',mode='setup',csrf=csrf(),error='Неверный или просроченный код владельца.'),400
    password=request.form.get('password','')
    if len(password)<12 or len(password)>256:
        return render_template('auth.html',mode='setup',csrf=csrf(),error='Пароль должен содержать от 12 до 256 символов.'),400
    salt=secrets.token_hex(16); seed=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    with db() as conn:
        try:
            conn.execute('INSERT INTO owner VALUES(1,?,?,?,0,-1)',(salt,password_hash(password,salt),seed))
        except sqlite3.IntegrityError:
            abort(403)
    session.clear();session['enroll']=True;csrf()
    return redirect(PREFIX+'/')

@app.post(PREFIX+'/enroll')
def enroll():
    if not session.get('enroll') or not owner() or owner()['verified']:
        abort(403)
    step=otp_step(owner()['totp'],request.form.get('otp',''))
    if step is None:
        return enrollment('Код не подошёл. Проверь время на телефоне и попробуй новый код.'),400
    codes=[secrets.token_hex(6).upper() for _ in range(10)]
    with db() as conn:
        conn.execute('UPDATE owner SET verified=1,last_step=? WHERE id=1',(step,))
        conn.executemany('INSERT INTO recovery VALUES(?)',[(recovery_hash(c),) for c in codes])
    session.clear();session['owner']=True;session.permanent=True;csrf()
    return render_template('auth.html',mode='recovery',codes=codes,csrf=csrf(),error=None)

@app.post(PREFIX+'/login')
def login():
    value=owner()
    if limited():
        return render_template('auth.html',mode='login',csrf=csrf(),error='Слишком много попыток. Попробуй через 15 минут.'),429
    password=request.form.get('password','')
    valid=value and len(password)<=256 and hmac.compare_digest(password_hash(password,value['salt']),value['hash'])
    if valid and not value['verified']:
        session.clear();session['enroll']=True;csrf();return redirect(PREFIX+'/')
    code=request.form.get('otp','')
    verified=False
    if valid:
        step=otp_step(value['totp'],code)
        with db() as conn:
            if step is not None:
                verified=conn.execute('UPDATE owner SET last_step=? WHERE id=1 AND last_step<?',(step,step)).rowcount==1
            else:
                verified=conn.execute('DELETE FROM recovery WHERE hash=?',(recovery_hash(code),)).rowcount==1
    if not verified:
        failed()
        return render_template('auth.html',mode='login',csrf=csrf(),error='Неверный пароль или код.'),400
    with db() as conn:
        conn.execute('DELETE FROM failures WHERE ip=?',(request.remote_addr,))
    session.clear();session['owner']=True;session.permanent=True;csrf()
    return redirect(PREFIX+'/')

@app.post(PREFIX+'/logout')
def logout():
    session.clear()
    return redirect(PREFIX+'/')

@app.get(PREFIX+'/api/state')
def api_state():
    try:
        return jsonify(state_data())
    except (OSError,ValueError):
        return jsonify(error='Служба управления временно недоступна.'),503

@app.post(PREFIX+'/api/action')
def api_action():
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict) or data.get('op') not in ('create','toggle','rotate','global','delete'):
        abort(400)
    try:
        helper(data)
        if data['op']=='delete':
            with db() as conn:
                conn.execute('UPDATE events SET ack=1 WHERE profile=?',(data.get('id'),))
                conn.execute('DELETE FROM monitor WHERE profile=?',(data.get('id'),))
        return jsonify(ok=True)
    except (ValueError,OSError) as error:
        return jsonify(error=str(error)),400

@app.post(PREFIX+'/api/key')
def api_key():
    data=request.get_json(silent=True) or {}
    try:
        key=helper({'op':'key','id':data.get('id')})
    except (ValueError,OSError):
        abort(404)
    uri='tg://webproxy?server='+quote(key['host'])+'&secret='+quote(key['secret'])
    image=qrcode.make(uri);buffer=io.BytesIO();image.save(buffer,format='PNG')
    return jsonify(**key,uri=uri,qr=base64.b64encode(buffer.getvalue()).decode())

@app.post(PREFIX+'/api/settings')
def api_settings():
    data=request.get_json(silent=True) or {}
    values=[data.get(k) for k in ('networks','traffic_gb','minutes')]
    if not all(type(v) is int for v in values) or not 2<=values[0]<=20 or not 0<=values[1]<=100 or not 1<=values[2]<=60:
        abort(400)
    with db() as conn:
        conn.execute('UPDATE settings SET networks=?,traffic_gb=?,minutes=? WHERE id=1',values)
    backup_changed('settings')
    return jsonify(ok=True)

@app.post(PREFIX+'/api/ack')
def api_ack():
    data=request.get_json(silent=True) or {}
    if type(data.get('id')) is not int:
        abort(400)
    with db() as conn:
        conn.execute('UPDATE events SET ack=1 WHERE id=?',(data['id'],))
    return jsonify(ok=True)

@app.get(PREFIX+'/static/<path:name>')
def assets(name):
    if name not in ('panel.css','panel.js','hysteria.css','hysteria.js','amnezia.js','backups.js','backups.css','migration.js'):
        abort(404)
    return app.send_static_file(name)


if not os.getenv('RELAY_TEST'):
    threading.Thread(target=monitor_loop,daemon=True).start()
