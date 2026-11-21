"""Design preview of the panel with made-up data. Never run on a server.

Runs the real Flask panel locally with every service mocked, so the look can be checked without a VPS.

    python tools/design_preview.py .                      # this checkout on http://localhost:5055
    git archive main panel | tar -x -C /tmp/old           # optional: the released look for comparison
    python tools/design_preview.py /tmp/old 5056

Open http://localhost:5055/preview-login (no password: the stand only). The pill at the bottom switches
between stands on ports 5056 (0.6.0), 5055 (Terminal 2.0) and 5057 (branch backup/terminal-2-clean).
/preview-logout shows the login page.
"""
import hashlib, json, os, pathlib, sys, tempfile, time

SRC = pathlib.Path(sys.argv[1]).resolve()
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5055
# The three stands, shown in the switcher in this order.
STANDS = [(5056, 'Старая 0.6.0'), (5055, 'Terminal 2.0'), (5057, 'Без украшений')]
sys.path.insert(0, str(SRC / 'panel'))
root = pathlib.Path(tempfile.mkdtemp())
os.environ.update(RELAY_TEST='1', RELAY_DATA=str(root), RELAY_USAGE=str(root / 'usage.json'))
(root / 'auth.json').write_text(json.dumps({'host': f'localhost:{PORT}', 'session_key': 'preview',
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
import hy2_routes, awg_routes, backup_routes, cascade_routes
from flask import session, redirect

panel.app.config['SESSION_COOKIE_SECURE'] = False
with panel.db() as c:
    c.execute("INSERT OR REPLACE INTO owner VALUES(1,'00','00','AAAA',1,0)")
    c.execute("INSERT INTO events(time,profile,kind,text,ack) VALUES(?,?,?,?,0)", (now - 600, 'default', 'networks', 'Мой ключ: подключения из 3 разных подсетей'))
    c.execute("INSERT INTO events(time,profile,kind,text,ack) VALUES(?,?,?,?,1)", (now - 7200, 'mom', 'created', 'Выдан ключ «Мама»'))

tg = {'host': 'tg.example.com', 'paused': False, 'events': [{'id': 9, 'time': now - 5000, 'profile': 'friend', 'kind': 'toggle', 'text': 'Ключ «Друг» приостановлен', 'ack': 1}], 'users': [
    {'id': 'default', 'name': 'Мой ключ', 'group': 'Личное', 'enabled': True, 'created': 1, 'suffix': 'A1F3'},
    {'id': 'mom', 'name': 'Мама', 'group': 'Семья', 'enabled': True, 'created': 2, 'suffix': '77C0'},
    {'id': 'friend', 'name': 'Друг', 'group': 'Друзья', 'enabled': False, 'created': 3, 'suffix': '0B2E'}]}
panel.helper = lambda p: json.loads(json.dumps(tg)) if p.get('op') == 'status' else {'ok': True}

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
hy2_routes.helper = lambda p: hy if p.get('op') == 'status' else {'ok': True}

def awg_user(i, name, online, routing):
    return {'id': i, 'name': name, 'online': online, 'enabled': True, 'allowed': True, 'grp': 'Семья', 'address': '10.77.0.' + str(len(i) + 2),
            'today': 100_000_000, 'month': 2_000_000_000, 'up': 50_000_000, 'down': 1_500_000_000, 'created': 1, 'last': now - 50,
            'expires': 0, 'quota': 0, 'enforce': False, 'history': hist, 'routing': routing}
awg = {'host': 'awg.example.com', 'port': 51820, 'paused': False, 'updated': now, 'telemetry_ok': True,
       'routing': {'ready': True, 'count': 12987, 'fetched': now - 3600, 'checked': now - 600, 'cascade_enabled': True, 'cascade_configured': True, 'can_rollback': True},
       'users': [awg_user('one', 'Папа', True, 'ru_split'), awg_user('two', 'Сестра', False, 'cascade')]}
awg_routes.helper = lambda p: awg if p.get('op') == 'status' else {'ok': True}
cascade_routes.helper = lambda p: {'enabled': True, 'configured': True, 'name': 'Norway', 'host': '138.16.143.97', 'port': 51821,
                                   'pairing': {'schema': 1, 'ru_public_key': 'public'}, 'handshake': now - 40}
backup_routes.helper = lambda p: {}

@panel.app.get('/preview-login')
def preview_login():
    session['owner'] = True
    return redirect('/control/')

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
.pv-switch{position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:2147483647;display:flex;gap:4px;padding:4px;
  background:#000000e6;border:1px solid #555;border-radius:999px;font:500 12px/1 ui-monospace,Consolas,monospace;box-shadow:0 6px 24px #0008}
.pv-switch a{padding:9px 14px;border-radius:999px;color:#ccc;text-decoration:none;white-space:nowrap}
.pv-switch a:hover{color:#fff}
.pv-switch a[aria-current]{background:#fff;color:#000}
.pv-switch span{padding:9px 6px 9px 12px;color:#888}
@media(max-width:520px){.pv-switch span{display:none}.pv-switch a{padding:9px 10px}}
"""

@panel.app.get('/preview-switch.css')
def preview_switch_css():
    return SWITCH_CSS, 200, {'Content-Type': 'text/css; charset=utf-8'}

@panel.app.after_request
def inject_switch(response):
    from flask import request
    if response.mimetype != 'text/html' or response.direct_passthrough:
        return response
    html = response.get_data(as_text=True)
    if '</body>' not in html:
        return response
    path = request.full_path.rstrip('?')
    links = ''.join(f'<a href="http://localhost:{port}{path}"{" aria-current=page" if port == PORT else ""}>{name}</a>'
                    for port, name in STANDS)
    html = html.replace('</head>', '<link rel="stylesheet" href="/preview-switch.css"></head>', 1)
    html = html.replace('</body>', f'<nav class="pv-switch" aria-label="Версия панели (только стенд)"><span>стенд:</span>{links}</nav></body>', 1)
    response.set_data(html)
    return response

panel.app.run(host='127.0.0.1', port=PORT)
