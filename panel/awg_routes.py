"""Owner-authenticated AmneziaWG UI, config download and QR export."""
import base64
import io
import json
import socket
import qrcode
from flask import abort,jsonify,redirect,render_template,request


def helper(payload):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(40);s.connect('/run/relay-awg-control/control.sock')
        s.sendall(json.dumps(payload,ensure_ascii=False).encode()+b'\n');raw=b''
        while not raw.endswith(b'\n'):
            part=s.recv(65536)
            if not part or len(raw)>2**20:raise OSError('Служба управления не ответила')
            raw+=part
    result=json.loads(raw)
    if not result['ok']:raise ValueError(result['error'])
    return result['data']


def register(app,authorized,csrf):
    @app.get('/control/amnezia')
    def awg_home():
        if not authorized():return redirect('/control/')
        return render_template('amnezia.html',csrf=csrf())

    @app.get('/control/api/awg/state')
    def awg_state():
        try:return jsonify(helper({'op':'status'}))
        except (OSError,ValueError):return jsonify(error='AmneziaWG не установлена или служба временно недоступна'),503

    @app.post('/control/api/awg/action')
    def awg_action():
        p=request.get_json(silent=True)
        if not isinstance(p,dict) or p.get('op') not in ('create','toggle','rotate','limits','delete','global'):abort(400)
        try:return jsonify(helper(p))
        except (OSError,ValueError) as e:return jsonify(error=str(e)),400

    @app.post('/control/api/awg/key')
    def awg_key():
        p=request.get_json(silent=True)
        if not isinstance(p,dict):abort(400)
        try:
            result=helper({'op':'key','id':p.get('id')})
            image=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,box_size=6,border=4)
            image.add_data(result['conf']);image.make(fit=True)
            buffer=io.BytesIO();image.make_image().save(buffer,format='PNG')
            return jsonify(**result,qr=base64.b64encode(buffer.getvalue()).decode())
        except (OSError,ValueError) as e:return jsonify(error=str(e)),400
