"""Owner-only cascade UI; uses the same origin/CSRF/migration guards as the panel."""
import json
import socket
from flask import jsonify, redirect, render_template, request


def helper(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(65)
        sock.connect('/run/relay-cascade/control.sock')
        sock.sendall(json.dumps(payload).encode() + b'\n')
        raw = b''
        while not raw.endswith(b'\n'):
            chunk = sock.recv(65536)
            if not chunk or len(raw) > 1048576: raise OSError('Служба каскада не ответила.')
            raw += chunk
    result = json.loads(raw)
    if not result['ok']: raise ValueError(result['error'])
    return result['data']


def register(app, authorized, csrf):
    @app.get('/control/cascade')
    def cascade_home():
        if not authorized(): return redirect('/control/')
        return render_template('cascade.html', csrf=csrf())

    @app.get('/control/api/cascade/state')
    def cascade_state():
        try: return jsonify(helper({'op': 'status'}))
        except (OSError, ValueError): return jsonify(error='Служба каскада недоступна. Проверь relay-panel status.'), 503

    @app.post('/control/api/cascade/action')
    def cascade_action():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or payload.get('op') not in ('configure', 'pair', 'check', 'enable', 'disable'):
            return jsonify(error='Неизвестная операция.'), 400
        try: return jsonify(helper(payload))
        except (OSError, ValueError) as error: return jsonify(error=str(error)), 400
