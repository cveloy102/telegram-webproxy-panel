"""Owner-only backup controls, sharing the panel's Origin and CSRF checks."""
import json
import os
import socket
from flask import jsonify, redirect, render_template, request

def helper(payload):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(20);s.connect(os.getenv('RELAY_BACKUP_SOCKET','/run/relay-backup/control.sock'))
        s.sendall(json.dumps(payload).encode()+b'\n');raw=b''
        while not raw.endswith(b'\n'):
            part=s.recv(65536)
            if not part or len(raw)>65536:raise OSError('Нет ответа службы копирования.')
            raw+=part
    result=json.loads(raw)
    if not result['ok']:raise ValueError(result['error'])
    return result['data']

def register(app,authorized,csrf):
    @app.get('/control/backups')
    def backup_home():
        if not authorized():return redirect('/control/')
        return render_template('backups.html',csrf=csrf())
    @app.get('/control/api/backup/state')
    def backup_state():
        try:return jsonify(helper({'op':'status'}))
        except (OSError,ValueError):return jsonify(error='Служба резервных копий недоступна.'),503
    @app.post('/control/api/backup/action')
    def backup_action():
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or data.get('op') not in ('configure','connect','manual'):return jsonify(error='Неизвестная операция.'),400
        try:return jsonify(helper(data))
        except (OSError,ValueError) as error:return jsonify(error=str(error)),400
