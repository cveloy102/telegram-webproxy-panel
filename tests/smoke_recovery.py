"""Optional Hysteria and encrypted disaster recovery on the expendable CI VPS."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import yaml

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
import hysteria_install
from hy2_control import Controller as Hysteria
from backup_archive import layout,encrypt,decrypt
from restore import main as restore

options=json.loads(setup.STATE.read_text());options.update(hy2_domain='hy2.example.com',hy2_port=24443)
awg_before={}
if options.get('awg_domain'):
    from awg_routes import helper as amnezia
    awg_before={u['id']:amnezia({'op':'key','id':u['id']})['conf'] for u in amnezia({'op':'status'})['users']}
setup.json_write(setup.STATE,options,mode=0o600)
with tempfile.TemporaryDirectory(prefix='relay-recovery-smoke-') as tmp:
    work=Path(tmp);hysteria_install.install(setup,options,work)
    # Initialize stable users, then use a test-only self-signed certificate on this CI runner.
    control=Hysteria()
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=hy2.example.com','-keyout','/var/lib/hysteria/test.key','-out','/var/lib/hysteria/test.crt'],check=True,capture_output=True)
    for name in ('test.key','test.crt'):shutil.chown('/var/lib/hysteria/'+name,'hysteria','hysteria')
    cfg=yaml.safe_load(control.config.read_text());cfg.pop('acme');cfg['tls']={'cert':'/var/lib/hysteria/test.crt','key':'/var/lib/hysteria/test.key'}
    setup.write(control.config,yaml.safe_dump(cfg),mode=0o640,group='hysteria')
    setup.run('systemctl','daemon-reload');hysteria_install.activate(setup,options)
    for _ in range(30):
        try:control.stats_api('online');break
        except OSError:time.sleep(1)
    else:raise AssertionError('Hysteria stats API unavailable')
    def helper(payload):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(40);s.connect('/run/relay-hy2/control.sock');s.sendall(json.dumps(payload).encode()+b'\n');raw=b''
            while not raw.endswith(b'\n'):raw+=s.recv(65536)
        result=json.loads(raw);assert result['ok'],result;return result['data']
    helper({'op':'create','name':'Recovery friend','group':'Семья'})
    original=helper({'op':'key','id':'default'})['uri']
    # A real QUIC connection must carry traffic before we test recovery.
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import threading
    class Response(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b'recovery-network-ok')
        def log_message(self,*args):pass
    http=ThreadingHTTPServer(('127.0.0.1',18085),Response);threading.Thread(target=http.serve_forever,daemon=True).start()
    with control.db() as c:password=c.execute("SELECT secret FROM users WHERE id='default'").fetchone()[0]
    client_config=work/'client.yaml';client_config.write_text(yaml.safe_dump({'server':'127.0.0.1:24443','auth':password,'tls':{'sni':'hy2.example.com','insecure':True},'socks5':{'listen':'127.0.0.1:18086'}}));client_config.chmod(0o600)
    client=subprocess.Popen(['/usr/local/bin/hysteria','client','--config',str(client_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(20):
            result=subprocess.run(['curl','--silent','--show-error','--max-time','3','--noproxy','','--proxy','socks5h://127.0.0.1:18086','http://127.0.0.1:18085/'],capture_output=True)
            if result.returncode==0:assert result.stdout==b'recovery-network-ok';break
            time.sleep(1)
        else:raise AssertionError('Real Hysteria QUIC tunnel failed')
    finally:client.terminate();client.wait(timeout=10);http.shutdown()
    # Root backup reads the production paths but only synthetic CI profiles exist here.
    key=work/'key.txt';subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
    recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
    encrypted=work/'snapshot.age';manifest=encrypt(encrypted,recipient,layout())
    assert manifest['hysteria'];staging=work/'restore';decrypt(encrypted,key.read_text(),staging)
    helper({'op':'rotate','id':'default'})
    assert helper({'op':'key','id':'default'})['uri']!=original
    from unittest.mock import patch
    restore([str(encrypted),'--identity',str(key),'--inspect'])
    with patch('builtins.input',return_value='ВОССТАНОВИТЬ'):restore([str(encrypted),'--identity',str(key)])
    assert helper({'op':'key','id':'default'})['uri']==original
    assert len(helper({'op':'status'})['users'])==2
    if awg_before:
        assert awg_before=={u['id']:amnezia({'op':'key','id':u['id']})['conf'] for u in amnezia({'op':'status'})['users']}
    setup.health(options['domain'],public=False)
    print('Hysteria install, key lifecycle and encrypted restore: PASS')
