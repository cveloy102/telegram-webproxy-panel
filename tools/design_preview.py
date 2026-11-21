"""Run the panel on loopback with sample data.

    python tools/design_preview.py --compare
    python tools/design_preview.py . 5055

Open http://localhost:5055/preview-login. Use /preview-logout to inspect login.
"""
import hashlib
import io
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from urllib.parse import quote, urlencode

STANDS = [
    (5055, 'Новый дизайн', None),
    (5056, 'Релиз 0.6.0', 'v0.6.0'),
    (5058, 'Terminal 2.0', '553bf2feb5322ee612d25a8c0811877cf043ee51'),
    (5057, 'Без украшений', '263e0c5936d9cd5dc43ed363bb7ddb681277030b'),
]


def compare():
    script = pathlib.Path(__file__).resolve()
    repo = script.parent.parent
    processes = []
    with tempfile.TemporaryDirectory(prefix='panelturn-compare-') as folder:
        for port, _, _ in STANDS:
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', port))
                except OSError:
                    raise SystemExit(f'Порт {port} уже занят.') from None
        try:
            for port, _, ref in STANDS:
                source = repo
                if ref:
                    source = pathlib.Path(folder) / str(port)
                    archive = subprocess.check_output(
                        ['git', 'archive', '--format=zip', ref, 'panel'], cwd=repo
                    )
                    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                        zipped.extractall(source)
                processes.append(subprocess.Popen([sys.executable, str(script), str(source), str(port)]))
            print('http://localhost:5055/preview-login', flush=True)
            while all(process.poll() is None for process in processes):
                time.sleep(0.5)
            raise SystemExit('Одна из версий стенда завершилась.')
        except KeyboardInterrupt:
            pass
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                process.wait()


if sys.argv[1:] == ['--compare']:
    compare()
    raise SystemExit

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5055
sys.path.insert(0, str(SRC / 'panel'))
storage = tempfile.TemporaryDirectory(prefix='panelturn-sample-')
root = pathlib.Path(storage.name)
os.environ.update(
    RELAY_TEST='1', RELAY_DATA=str(root), RELAY_USAGE=str(root / 'usage.json'),
    RELAY_MIGRATION_DATA=str(root / 'migration'), RELAY_BACKUP_SOCKET=str(root / 'backup.sock'),
    RELAY_SVALKA_CREDENTIALS=str(root / 'svalka.json'),
)
(root / 'auth.json').write_text(json.dumps({'host': f'localhost:{PORT}', 'session_key': secrets.token_hex(32),
    'setup_hash': hashlib.sha256(b'x').hexdigest(), 'setup_expires': time.time() + 3600}))
now = int(time.time())
day = time.strftime('%Y-%m-%d', time.gmtime())
(root / 'usage.json').write_text(json.dumps({'started': now - 86400 * 20, 'updated': now, 'rows': {
    'a': {'profile': 'default', 'ip': '93.184.216.34', 'up': 41_000_000, 'down': 210_000_000, 'live': 3, 'last': now - 30,
          'connected': now - 4000, 'first': now - 86400 * 9, 'connections': 41, 'days': {day: {'up': 9_000_000, 'down': 71_000_000}}},
    'b': {'profile': 'default', 'ip': '93.184.216.80', 'up': 1_000_000, 'down': 9_000_000, 'live': 0, 'last': now - 9000,
          'connected': now - 9500, 'first': now - 86400 * 3, 'connections': 4, 'days': {}},
    'c': {'profile': 'mom', 'ip': '178.62.1.9', 'up': 3_000_000, 'down': 77_000_000, 'live': 0, 'last': now - 3600,
          'connected': now - 7200, 'first': now - 86400 * 5, 'connections': 12, 'days': {day: {'up': 1_000_000, 'down': 20_000_000}}}}}))

import app as panel
import hy2_routes, awg_routes, backup_routes, cascade_routes, migration_routes, svalka_routes
from flask import session, redirect, request

panel.app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_NAME=f'panelturn_demo_{PORT}')
panel_wsgi = panel.app.wsgi_app
sample_state_lock = threading.Lock()


def preview_wsgi(environ, start_response):
    # Local HTTP serves the demo; retain the panel's exact-origin and CSRF checks.
    if environ.get('HTTP_ORIGIN') == f'http://localhost:{PORT}':
        environ['HTTP_ORIGIN'] = f'https://localhost:{PORT}'
    with sample_state_lock:
        return panel_wsgi(environ, start_response)


panel.app.wsgi_app = preview_wsgi
with panel.db() as c:
    c.execute("INSERT OR REPLACE INTO owner VALUES(1,'00','00','AAAA',1,0)")
    c.execute("INSERT INTO events(time,profile,kind,text,ack) VALUES(?,?,?,?,0)", (now - 600, 'default', 'networks', 'Мой ключ: подключения из 3 разных подсетей'))
    c.execute("INSERT INTO events(time,profile,kind,text,ack) VALUES(?,?,?,?,1)", (now - 7200, 'mom', 'created', 'Выдан ключ «Мама»'))

tg = {'host': 'tg.example.com', 'paused': False, 'events': [{'id': 9, 'time': now - 5000, 'profile': 'friend', 'kind': 'toggle', 'text': 'Ключ «Друг» приостановлен', 'ack': 1}], 'users': [
    {'id': 'default', 'name': 'Мой ключ', 'group': 'Личное', 'enabled': True, 'created': 1, 'suffix': 'A1F3'},
    {'id': 'mom', 'name': 'Мама', 'group': 'Семья', 'enabled': True, 'created': 2, 'suffix': '77C0'},
    {'id': 'friend', 'name': 'Друг', 'group': 'Друзья', 'enabled': False, 'created': 3, 'suffix': '0B2E'}]}
panel.backup_changed = lambda reason: None

hist = [{'day': time.strftime('%Y-%m-%d', time.gmtime(now - 86400 * i)), 'up': 5_000_000 * (i % 4 + 1), 'down': 40_000_000 * ((i * 7) % 5 + 1)} for i in range(14)]
hy = {'users': [
    {'id': 'one', 'name': 'Телефон', 'grp': 'Личное', 'enabled': True, 'allowed': True, 'online': True, 'connections': 2, 'history': hist,
     'today': 180_000_000, 'month': 4_200_000_000, 'up': 400_000_000, 'down': 3_800_000_000, 'last': now - 20, 'expires': now + 86400 * 40,
     'quota': 50_000_000_000, 'enforce': True, 'suffix': '1234'},
    {'id': 'two', 'name': 'Ноутбук', 'grp': 'Личное', 'enabled': True, 'allowed': False, 'reason': 'Лимит трафика', 'online': False, 'connections': 0,
     'history': [], 'today': 0, 'month': 0, 'up': 0, 'down': 0, 'last': now - 86400, 'expires': 0, 'quota': 0, 'enforce': False, 'suffix': '9F00'}],
    'events': [{'time': now - 300, 'text': 'Телефон подключился'}], 'telemetry_ok': True, 'updated': now, 'started': now - 86400 * 30, 'paused': False,
    'settings': {'host': 'hy2.example.com', 'port': 24443, 'cover': 'page', 'cover_url': '', 'obfs': True},
    'metrics': {'cpu': 7.5, 'memory_used': 612_000_000, 'memory_total': 2_000_000_000, 'service_memory': 41_000_000, 'certificate_expires': now + 86400 * 61}}

def awg_user(i, name, online, routing):
    return {'id': i, 'name': name, 'online': online, 'enabled': True, 'allowed': True, 'grp': 'Семья', 'address': '10.77.0.' + str(len(i) + 2),
            'today': 100_000_000, 'month': 2_000_000_000, 'up': 50_000_000, 'down': 1_500_000_000, 'created': 1, 'last': now - 50,
            'expires': 0, 'quota': 0, 'enforce': False, 'history': hist, 'routing': routing}
awg = {'host': 'awg.example.com', 'port': 51820, 'paused': False, 'updated': now, 'telemetry_ok': True,
       'routing': {'ready': True, 'count': 12987, 'fetched': now - 3600, 'checked': now - 600, 'cascade_enabled': True, 'cascade_configured': True, 'can_rollback': True},
       'users': [awg_user('one', 'Папа', True, 'ru_split'), awg_user('two', 'Сестра', False, 'cascade')]}

def sample_key(protocol, state, user):
    host = state.get('host', state.get('settings', {}).get('host'))
    if protocol == 'telegram':
        return {'host': host, 'secret': '0' * 32, 'name': user['name'], 'enabled': user['enabled']}
    if protocol == 'hysteria':
        port = state['settings']['port']
        return {'host': host, 'port': port, 'enabled': user['enabled'],
                'uri': f'hysteria2://demo@{host}:{port}#{quote(user["name"])}'}
    conf = f"""[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = {user['address']}/32
DNS = 192.0.2.53
MTU = 1280

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = {host}:{state['port']}
AllowedIPs = 192.0.2.0/24
PersistentKeepalive = 25
"""
    return {'conf': conf, 'filename': 'panelturn-demo.conf', 'name': user['name']}


def protocol_helper(protocol, state):
    users = state['users']

    def helper(payload):
        op = payload['op']
        if op == 'status':
            if 'updated' in state:
                state['updated'] = int(time.time())
            return state
        if op == 'global':
            state['paused'] = payload['paused']
        elif op == 'create':
            user = dict(id=secrets.token_hex(4), name=payload['name'], group=payload['group'],
                        grp=payload['group'], enabled=True, allowed=True, online=False, created=int(time.time()),
                        address='10.77.0.42', routing=payload.get('routing', 'cascade'), suffix='0000',
                        connections=0, history=[], today=0, month=0, up=0, down=0, last=0, expires=0,
                        quota=0, enforce=False)
            users.append(user)
        elif op == 'settings':
            state['settings'].update({key: payload[key] for key in ('port', 'cover', 'cover_url', 'obfs')})
        elif op in ('geo_update', 'geo_rollback'):
            state['routing']['fetched'] = int(time.time())
        else:
            user = next((item for item in users if item['id'] == payload.get('id')), None)
            if user is None:
                raise ValueError('Демонстрационный профиль не найден.')
            if op == 'key':
                return sample_key(protocol, state, user)
            if op == 'delete':
                users.remove(user)
            elif op == 'rename':
                user['name'] = payload['name']
            elif op == 'toggle':
                user['enabled'] = user['allowed'] = payload['enabled']
                if not user['enabled']:
                    user['online'] = False
            elif op == 'rotate':
                user['suffix'] = secrets.token_hex(2).upper()
            elif op == 'limits':
                expires = payload.get('expires')
                user.update(expires=int(time.mktime(time.strptime(expires, '%Y-%m-%d'))) if expires else 0,
                            quota=int(payload['quota_gb'] * 1024**3), enforce=payload['enforce'])
            elif op == 'routing':
                user['routing'] = payload['routing']
            elif op == 'route_check':
                raise ValueError('Проверка адресов доступна на подключённом сервере.')
        return {'ok': True}

    return helper


panel.helper = protocol_helper('telegram', tg)
hy2_routes.helper = protocol_helper('hysteria', hy)
awg_routes.helper = protocol_helper('awg', awg)

cascade = {'enabled': True, 'configured': True, 'name': 'Norway', 'host': '192.0.2.21', 'port': 51821,
           'pairing': {'schema': 1, 'ru_public_key': 'demo'}, 'handshake': now - 40}
backup = {'folder': '', 'recipient': '', 'automatic': True, 'connected': False,
          'pending': False, 'running': False, 'uploaded': 0, 'error': ''}
migration = {'phase': 'running', 'services': ['Telegram', 'Hysteria', 'AmneziaWG'], 'backup': backup}
svalka = {'domain': 'sync.example.com', 'signup': False, 'users': [
    {'id': 'sampleuser00001', 'email': 'owner@example.com', 'created': '2026-11-10 10:00:00Z'},
]}


def manage_cascade(payload):
    op = payload['op']
    if op in ('enable', 'disable'):
        cascade['enabled'] = op == 'enable'
    elif op == 'configure':
        cascade.update({key: payload[key] for key in ('name', 'host', 'port')})
    elif op == 'check':
        cascade['last_check'] = {'time': int(time.time()), 'ok': True, 'ip': '192.0.2.21'}
    return cascade


def manage_backup(payload):
    op = payload['op']
    if op == 'configure':
        backup.update({key: payload[key] for key in ('folder', 'recipient', 'automatic')})
    elif op == 'connect':
        backup['connected'] = True
    elif op == 'manual':
        backup['uploaded'] = int(time.time())
        backup['file'] = 'panelturn-demo.tar.age'
    elif op.startswith('migration_'):
        if op in ('migration_stop', 'migration_resume'):
            migration['phase'] = 'stopped' if op == 'migration_stop' else 'running'
        return migration
    return backup


def manage_svalka(payload):
    if payload['op'] == 'signup':
        svalka['signup'] = payload['open']
    elif payload['op'] == 'create':
        svalka['users'].append({'id': secrets.token_hex(7), 'email': payload['email'], 'created': day})
    elif payload['op'] == 'delete':
        svalka['users'] = [user for user in svalka['users'] if user['id'] != payload.get('id')]
    return svalka


cascade_routes.helper = manage_cascade
backup_routes.helper = migration_routes.helper = manage_backup
svalka_routes.installed = lambda: True
panel.app.jinja_env.globals['svalka_installed'] = svalka_routes.installed
svalka_routes.state = lambda: svalka
svalka_routes.action = manage_svalka

@panel.app.get('/preview-login')
def preview_login():
    session['owner'] = True
    target = request.args.get('next', '/control/')
    pages = ('', 'hysteria', 'amnezia', 'cascade', 'backups', 'migration', 'svalka')
    return redirect(target if target in {f'/control/{page}' for page in pages} else '/control/')

@panel.app.get('/preview-logout')
def preview_logout():
    session.clear()
    return redirect('/control/')

# Keep the made-up traffic "fresh" so the pages show online users, not "no fresh data".
_usage = panel.usage
def fresh_usage():
    data = _usage(); data['updated'] = int(time.time()); return data
panel.usage = fresh_usage

SWITCH_CSS = """
.pv-switch{position:sticky;bottom:0;z-index:10;display:flex;flex-wrap:wrap;justify-content:center;align-items:center;
  gap:4px;margin:0;padding:6px 8px;background:#171717;color:#eee;border-top:1px solid #515151;font:500 13px/1.2 system-ui,sans-serif}
.pv-switch a{display:flex;align-items:center;min-height:36px;padding:5px 11px;border-radius:5px;color:#ddd;text-decoration:none;white-space:nowrap}
.pv-switch a:hover{color:#fff}
.pv-switch a[aria-current]{background:#eee;color:#1b1b1b}
.pv-switch a:focus-visible{outline:2px solid #fff}
.pv-switch .pv-login{background:#eee;color:#1b1b1b}
.pv-switch span{padding:0 7px;color:#bbb}
@media(max-width:600px){
  .pv-switch{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:2px;padding:4px}
  .pv-switch span{display:none}
  .pv-switch a{justify-content:center;text-align:center;white-space:normal;padding:4px 3px;min-height:44px;font-size:11px}
  .pv-switch .pv-login{grid-column:1/-1}
}
"""

@panel.app.get('/preview-switch.css')
def preview_switch_css():
    return SWITCH_CSS, 200, {'Content-Type': 'text/css; charset=utf-8'}

@panel.app.after_request
def inject_switch(response):
    if response.mimetype != 'text/html' or response.direct_passthrough or response.status_code != 200:
        return response
    html = response.get_data(as_text=True)
    if '</body>' not in html:
        return response
    logged_in = session.get('owner')
    target = '/preview-login?' + urlencode({'next': request.path}) if logged_in else '/preview-logout'
    links = ''.join(f'<a href="http://localhost:{port}{target}"{" aria-current=page" if port == PORT else ""}>{name}</a>'
                    for port, name, _ in STANDS)
    if not logged_in:
        links += '<a class="pv-login" href="/preview-login">Войти в демо</a>'
    html = html.replace('</head>', '<link rel="stylesheet" href="/preview-switch.css"></head>', 1)
    html = html.replace('</body>', f'<nav class="pv-switch" aria-label="Сравнение дизайна"><span>Демо · тестовые данные</span>{links}</nav></body>', 1)
    response.set_data(html)
    return response

panel.app.run(host='127.0.0.1', port=PORT, threaded=True)
