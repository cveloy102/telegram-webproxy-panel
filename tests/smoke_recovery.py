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
from restore import restore_files

options=json.loads(setup.STATE.read_text());options.update(hy2_domain='hy2.example.com',hy2_port=24443)
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
    helper({'op':'create','name':'Recovery friend','group':'Family'})
    original=helper({'op':'key','id':'default'})['uri']
    # Root backup reads the production paths but only synthetic CI profiles exist here.
    key=work/'key.txt';subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
    recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
    encrypted=work/'snapshot.age';manifest=encrypt(encrypted,recipient,layout())
    assert manifest['hysteria'];staging=work/'restore';decrypt(encrypted,key.read_text(),staging)
    helper({'op':'rotate','id':'default'})
    assert helper({'op':'key','id':'default'})['uri']!=original
    setup.run('systemctl','stop','relay-backup','relay-panel','relay-helper','relay-hy2','hysteria-server','tproxy-server','mtproxy')
    restore_files(staging/'files',layout())
    from helper import Controller
    telegram=Controller();telegram.apply(telegram.read())
    restored=Hysteria()
    with restored.db() as c:settings=restored.settings(c)
    restored.apply_settings(settings)
    setup.run('systemctl','restart','relay-hy2','hysteria-server','relay-helper','relay-panel','relay-backup')
    assert helper({'op':'key','id':'default'})['uri']==original
    assert len(helper({'op':'status'})['users'])==2
    setup.health(options['domain'],public=False)
    print('Hysteria install, key lifecycle and encrypted restore: PASS')
