"""Routes share the existing owner login, TOTP, Origin and CSRF protection."""
import base64
import io
import json
import socket
import qrcode
from flask import abort, jsonify, redirect, render_template, request

def helper(payload):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(40);s.connect('/run/relay-hy2/control.sock')
        s.sendall(json.dumps(payload,ensure_ascii=False).encode()+b'\n');raw=b''
        while not raw.endswith(b'\n'):
            part=s.recv(65536)
            if not part or len(raw)>2**20: raise OSError('Служба управления не ответила')
            raw+=part
    result=json.loads(raw)
    if not result['ok']: raise ValueError(result['error'])
    return result['data']

def register(app,authorized,csrf):
    @app.get('/control/hysteria')
    def hy2_home():
        if not authorized(): return redirect('/control/')
        return render_template('hysteria.html',csrf=csrf())

    @app.get('/control/api/hy2/state')
    def hy2_state():
        try: return jsonify(helper({'op':'status'}))
        except (OSError,ValueError): return jsonify(error='Служба Hysteria временно недоступна'),503

    @app.post('/control/api/hy2/action')
    def hy2_action():
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or data.get('op') not in ('create','toggle','rotate','limits','global','settings','delete'): abort(400)
        try: return jsonify(helper(data))
        except (OSError,ValueError) as e: return jsonify(error=str(e)),400

    @app.post('/control/api/hy2/key')
    def hy2_key():
        data=request.get_json(silent=True)
        if not isinstance(data,dict): abort(400)
        try:
            result=helper({'op':'key','id':data.get('id')})
            buffer=io.BytesIO();qrcode.make(result['uri']).save(buffer,format='PNG')
            return jsonify(**result,qr=base64.b64encode(buffer.getvalue()).decode())
        except (OSError,ValueError) as e: return jsonify(error=str(e)),400
