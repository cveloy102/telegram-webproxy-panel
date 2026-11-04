"""Root-only tunnel controller. HTTP never receives a private key or SSH credentials."""
from contextlib import nullcontext
import json
import logging
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time

from cascade_network import (ROOT, INTERFACE, ENTRY, TABLE, PRIORITIES, run, public_key, endpoint,
                             entry_firewall, replace_table, setup_interface, policy_routes, remove_runtime, validate_state)
from migration_state import mutation


def atomic(path, value):
    pending = path.with_suffix('.pending')
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, ensure_ascii=False)
        output.flush(); os.fsync(output.fileno())
    pending.replace(path)


def notify_ready():
    """Do not release dependent VPN services until guard, routes and socket exist."""
    address = os.getenv('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'): address = '\0' + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
            notification.connect(address)
            notification.sendall(b'READY=1')


class Controller:
    def __init__(self, root=ROOT, uids=None):
        self.root = Path(root)
        self.path = self.root / 'state.json'
        self.lock = threading.Lock()
        if uids is None:
            import pwd
            uids = [pwd.getpwnam(name).pw_uid for name in ('hysteria', 'mtproxy')]
        self.uids = uids
        self.last_check = None
        self.health_error = ''

    def read(self):
        if not self.path.exists(): return {'schema': 1, 'enabled': False}
        return validate_state(json.loads(self.path.read_text()))

    def apply(self, state):
        # Install the kill switch BEFORE recreating routes or WireGuard after restart.
        replace_table('relay_cascade', entry_firewall(self.uids, state['enabled']))
        if state.get('exit_public_key'):
            setup_interface(self.root / 'private.key', state['exit_public_key'], host=state['host'], port=state['port'])
            policy_routes()
        elif state['enabled']:
            raise ValueError('У включённого каскада отсутствует ключ выходного сервера.')

    def status(self):
        value = self.read()
        result = {k: value[k] for k in ('enabled', 'name', 'host', 'port', 'exit_public_key') if k in value}
        result.update(configured=bool(value.get('exit_public_key')), last_check=self.last_check, error=self.health_error,
                      handshake=0, available=True)
        if (self.root / 'public.key').exists():
            result['pairing'] = {'schema': 1, 'ru_public_key': (self.root / 'public.key').read_text().strip(),
                                 'port': value.get('port', 51821)}
        if result['configured']:
            try:
                rows = run('wg', 'show', INTERFACE, 'latest-handshakes').stdout.splitlines()
                result['handshake'] = max((int(row.split()[1]) for row in rows), default=0)
            except Exception:
                # Status must remain readable when the tunnel is down.
                result['handshake'] = 0
        return result

    def probe(self, state):
        if not state.get('exit_public_key'): raise ValueError('Сначала добавь ответ выходного узла.')
        self.apply(state)
        # Use an IP literal and fixed SNI: no host DNS, proxy env or curlrc can bypass the probe.
        try:
            response = run('curl', '-q', '--noproxy', '*', '--ipv4', '--fail', '--silent', '--show-error',
                           '--max-time', '12', '--interface', ENTRY,
                           '--resolve', 'one.one.one.one:443:1.1.1.1',
                           'https://one.one.one.one/cdn-cgi/trace').stdout
            address = next(line[3:].strip() for line in response.splitlines() if line.startswith('ip='))
            address = endpoint(address)
            if address != state['host']:
                raise ValueError('Выходной IP не совпал с адресом Норвегии: проверь NAT у хостера.')
        except Exception:
            self.last_check = {'time': int(time.time()), 'ok': False}
            raise ValueError('Выход через зарубежный сервер не подтверждён. Проверь UDP-порт, ключи и firewall обоих VPS.') from None
        self.last_check = {'time': int(time.time()), 'ok': True, 'ip': address}
        return self.last_check

    def reconcile(self):
        """Linux removes device routes on link-down; repair without opening direct egress."""
        state = self.read()
        if not state['enabled']: return
        try: routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', TABLE).stdout)
        except subprocess.CalledProcessError: routes = []
        rules = json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
        rules_ready = all(any(str(rule.get('priority')) == priority and str(rule.get('table')) == TABLE for rule in rules) for priority in PRIORITIES)
        if not rules_ready or not any(route.get('dst') == 'default' and route.get('dev') == INTERFACE for route in routes):
            self.apply(state)

    def monitor(self):
        while True:
            time.sleep(5)
            with self.lock:
                try:
                    self.reconcile(); self.health_error = ''
                except Exception:
                    message = 'Не удалось восстановить маршрут каскада. Прямой выход через RU остаётся запрещён; проверь журнал relay-cascade.'
                    if not self.health_error: logging.error(message)
                    self.health_error = message

    def stop_clients(self):
        names = [name for name in ('mtproxy', 'hysteria-server', 'amneziawg-server', 'relay-awg')
                 if subprocess.run(['systemctl', 'is-active', '--quiet', name], capture_output=True).returncode == 0]
        if names: run('systemctl', 'stop', *names)
        return names

    def start_clients(self, names):
        if names: run('systemctl', 'start', *names)

    def call(self, payload):
        op = payload.get('op')
        with self.lock, (nullcontext() if op == 'status' else mutation()):
            state = self.read()
            if op == 'status': return self.status()
            if op == 'configure':
                if state['enabled']: raise ValueError('Сначала явно выключи каскад перед заменой узла.')
                name = payload.get('name', '')
                port = payload.get('port')
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60 or any(ord(c) < 32 for c in name):
                    raise ValueError('Название: от 1 до 60 символов.')
                if type(port) is not int or not 1024 <= port <= 65535: raise ValueError('UDP-порт: от 1024 до 65535.')
                host = endpoint(payload.get('host'))
                key = self.root / 'private.key'
                if not key.exists():
                    private = run('wg', 'genkey').stdout.strip()
                    public = run('wg', 'pubkey', input=private + '\n').stdout.strip()
                    key.write_text(private + '\n'); key.chmod(0o600)
                    (self.root / 'public.key').write_text(public + '\n')
                    (self.root / 'public.key').chmod(0o600)
                new = {'schema': 1, 'enabled': False, 'name': name.strip(), 'host': host, 'port': port}
                self.apply(new); remove_runtime()
                atomic(self.path, new); self.last_check = None
            elif op == 'pair':
                if state['enabled']: raise ValueError('Сначала выключи каскад.')
                if not state.get('host'): raise ValueError('Сначала сохрани адрес выходного сервера.')
                reply = payload.get('reply')
                if not isinstance(reply, dict) or reply.get('schema') != 1: raise ValueError('Вставь ответ установщика выходного узла.')
                key = public_key(reply.get('exit_public_key'))
                if key == (self.root / 'public.key').read_text().strip(): raise ValueError('Нужен ключ выходного узла, а не RU.')
                state['exit_public_key'] = key
                self.apply(state); atomic(self.path, state); self.last_check = None
            elif op == 'check':
                self.probe(state)
            elif op == 'enable':
                self.probe(state)
                names = self.stop_clients()
                # Persist desired mode first: a crash/reboot must not silently restore direct RU egress.
                state['enabled'] = True; atomic(self.path, state)
                self.apply(state)
                self.start_clients(names)
            elif op == 'disable':
                if payload.get('confirm') != 'DIRECT':
                    raise ValueError('Выключение разрешит прямой выход через RU. Подтверди DIRECT.')
                names = self.stop_clients()
                state['enabled'] = False
                self.apply(state); atomic(self.path, state)
                self.start_clients(names)
            else: raise ValueError('Неизвестная операция каскада.')
            if op not in ('status', 'check'):
                from backup_notify import changed
                changed()
            return self.status()


def serve():
    import grp
    import pwd
    controller = Controller()
    controller.apply(controller.read())
    allowed = pwd.getpwnam('relayadmin').pw_uid
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(30)
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in (0, allowed): return
            raw = self.rfile.readline(8193)
            if len(raw) > 8192: return
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict): raise ValueError('Нужен объект запроса.')
                response = {'ok': True, 'data': controller.call(payload)}
            except ValueError as error:
                response = {'ok': False, 'error': str(error)}
            except Exception:
                response = {'ok': False, 'error': 'Операция не завершена. Проверь состояние каскада и journalctl -u relay-cascade; режим автоматически не выключается.'}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode() + b'\n')
    path = Path('/run/relay-cascade/control.sock')
    path.unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(str(path), Handler) as server:
        os.chown(path, 0, grp.getgrnam('relayadmin').gr_gid); path.chmod(0o660)
        threading.Thread(target=controller.monitor, daemon=True).start()
        notify_ready()
        server.serve_forever()


if __name__ == '__main__': serve()
