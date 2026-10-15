"""Small privileged controller; the HTTP app runs as a separate unprivileged user."""
import copy
import json
import os
import pathlib
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import threading
import time
import urllib.request

BASE = pathlib.Path(os.getenv('RELAY_ROOT', '/etc/relay-panel'))

def atomic(path, value, mode=0o600, group=None):
    path = pathlib.Path(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=False)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(tmp, mode)
    if group:
        import grp
        os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
    os.replace(tmp, path)

class Controller:
    def __init__(self, base=BASE, apply=None):
        self.base = pathlib.Path(base)
        self.lock = threading.Lock()
        self.apply_override = apply
        self.path = self.base / 'users.json'

    def read(self):
        return json.loads(self.path.read_text(encoding='utf-8'))

    def public(self, state):
        state = copy.deepcopy(state)
        for user in state['users']:
            user['suffix'] = user.pop('secret')[-4:]
        return state

    def apply(self, state):
        if self.apply_override:
            return self.apply_override(state)
        active = [u for u in state['users'] if u['enabled'] and not state['paused']]
        if len(active)>16:
            raise ValueError('MTProxy поддерживает до 16 активных ключей. Приостанови один из ключей.')
        profiles = [{'name': u['id'], 'secret': u['secret'], 'backend': '127.0.0.1:2398',
                     'carrier_mode': 'https'} for u in active]
        if not profiles:
            profiles = [{'name': 'suspended', 'secret': secrets.token_hex(16),
                         'backend': '127.0.0.1:2398'}]
        paths = [pathlib.Path('/etc/tproxy-server/profiles.json'), pathlib.Path('/etc/mtproxy/managed-secrets.json')]
        before = [(p.read_bytes() if p.exists() else None) for p in paths]
        try:
            atomic(paths[0], {'profiles': profiles}, 0o400, 'tproxy')
            atomic(paths[1], {'secrets': [p['secret'] for p in profiles]}, 0o640, 'mtproxy')
            subprocess.run(['/usr/local/bin/tproxy-server', '-config', '/etc/tproxy-server/config.json',
                            '-profiles-file', str(paths[0]), '-check'], check=True, capture_output=True, timeout=15)
            subprocess.run(['systemctl', 'restart', 'mtproxy', 'tproxy-server'], check=True, capture_output=True, timeout=60)
            for _ in range(30):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:8081/readyz', timeout=2) as response:
                        if response.status == 200:
                            return
                except OSError:
                    pass
                time.sleep(0.3)
            raise RuntimeError('Backend did not become ready')
        except Exception:
            for path, data in zip(paths, before):
                if data is not None:
                    path.write_bytes(data)
            subprocess.run(['systemctl', 'restart', 'mtproxy', 'tproxy-server'], capture_output=True, timeout=60)
            raise RuntimeError('Change rolled back; previous keys restored') from None

    def call(self, request):
        with self.lock:
            state = self.read()
            previous = copy.deepcopy(state)
            op = request.get('op')
            if op == 'status':
                return self.public(state)
            user = next((u for u in state['users'] if u['id'] == request.get('id')), None)
            if op == 'key':
                if not user:
                    raise ValueError('Key not found')
                return {'secret': user['secret'], 'host': state['host'], 'enabled': user['enabled'], 'paused': state['paused']}
            if op == 'create':
                name = str(request.get('name', '')).strip()
                group = str(request.get('group', ''))
                if not 1 <= len(name) <= 40 or any(ord(c) < 32 for c in name):
                    raise ValueError('Invalid name')
                if group not in ('Семья', 'Друзья', 'Личное') or len(state['users']) >= 100:
                    raise ValueError('Invalid group or key limit reached')
                user = {'id': 'u_' + secrets.token_hex(6), 'name': name, 'group': group,
                        'secret': secrets.token_hex(16), 'enabled': True, 'created': int(time.time())}
                state['users'].append(user)
            elif op == 'toggle':
                if not user or type(request.get('enabled')) is not bool:
                    raise ValueError('Invalid key action')
                user['enabled'] = request['enabled']
            elif op == 'rotate':
                if not user:
                    raise ValueError('Key not found')
                user['secret'] = secrets.token_hex(16)
            elif op == 'delete':
                if not user:
                    raise ValueError('Ключ не найден')
                if request.get('confirm_name') != user['name']:
                    raise ValueError('Для удаления введи точное имя пользователя')
                state['users'] = [u for u in state['users'] if u['id'] != user['id']]
            elif op == 'global':
                if type(request.get('paused')) is not bool:
                    raise ValueError('Invalid global action')
                state['paused'] = request['paused']
            else:
                raise ValueError('Unknown action')
            event = {'time': int(time.time()), 'op': op, 'name': user['name'] if user else 'Все ключи',
                     'enabled': user['enabled'] if user else not state['paused']}
            state.setdefault('events', []).insert(0, event)
            state['events'] = state['events'][:1000]
            # Confirm that the private state is writable before changing live keys.
            pending = self.base / 'users.pending.json'
            atomic(pending, state)
            applied = False
            try:
                self.apply(state)
                applied = True
                os.replace(pending, self.path)
            except Exception:
                if applied:
                    self.apply(previous)
                raise
            finally:
                pending.unlink(missing_ok=True)
            return self.public(state)

def run():
    import grp
    import pwd
    controller = Controller()
    allowed = pwd.getpwnam('relayadmin').pw_uid
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(70)
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in (0, allowed):
                return
            raw = self.rfile.readline(8193)
            if len(raw) > 8192:
                return
            try:
                data = controller.call(json.loads(raw))
                response = {'ok': True, 'data': data}
            except ValueError as error:
                response = {'ok': False, 'error': str(error)}
            except Exception:
                response = {'ok': False, 'error': 'Изменение не применено. Предыдущие настройки восстановлены.'}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode() + b'\n')
    path = '/run/relay-helper/control.sock'
    if os.path.exists(path):
        os.unlink(path)
    with socketserver.ThreadingUnixStreamServer(path, Handler) as server:
        os.chown(path, 0, grp.getgrnam('relayadmin').gr_gid)
        os.chmod(path, 0o660)
        server.serve_forever()

if __name__ == '__main__':
    run()
