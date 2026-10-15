"""Run ONLY on an expendable GitHub Actions Ubuntu runner. Mutates its OS."""
import contextlib
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.request

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:
    raise SystemExit('This test may only run as root on an expendable GitHub Actions runner.')
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import installer as setup
import manage

options=dict(domain='relay.example.com',ip='127.0.0.1',email='',title='Test relay',contact='',theme='pixel',phase='testing')
setup.directory('/etc/relay-panel',mode=0o700)
setup.json_write(setup.STATE,options,mode=0o600)
setup.packages();setup.users()
with tempfile.TemporaryDirectory(prefix='relay-smoke-',dir='/var/tmp') as folder:
    work=pathlib.Path(folder)
    candidate,mtproxy=setup.build(ROOT,work)
    setup.install_files(ROOT,options,work,candidate,mtproxy)
    # Test-only local issuer. The real installer always uses publicly trusted automatic HTTPS.
    config=setup.caddyfile(options['domain']).replace('relay.example.com {','relay.example.com {\n tls internal')
    setup.write('/etc/caddy/Caddyfile',config)
    with open('/etc/hosts','a') as hosts:hosts.write('\n127.0.0.1 relay.example.com\n')
    setup.activate();setup.health(options['domain'],public=False)
    roots=list(pathlib.Path('/var/lib/caddy').rglob('root.crt'))
    assert roots,'Caddy test CA was not created'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(roots[0]))))
    with opener.open('https://relay.example.com/control/',timeout=10) as response:
        assert response.status==200
        assert response.headers['Referrer-Policy']=='same-origin'
        assert b'csrf' in response.read()
    try:opener.open('https://relay.example.com/control/api/state',timeout=10)
    except urllib.error.HTTPError as error:assert error.code==401
    else:raise AssertionError('Unauthenticated API was exposed')
    def helper(payload):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(80);sock.connect('/run/relay-helper/control.sock')
            sock.sendall(json.dumps(payload).encode()+b'\n');data=b''
            while not data.endswith(b'\n'):data+=sock.recv(65536)
        result=json.loads(data);assert result['ok'],result.get('error');return result['data']
    before=json.loads(pathlib.Path('/etc/relay-panel/users.json').read_text())
    created=helper({'op':'create','name':'Test friend','group':'Друзья'})
    user=next(u for u in created['users'] if u['id']!='default')
    helper({'op':'toggle','id':user['id'],'enabled':False})
    helper({'op':'rotate','id':user['id']})
    helper({'op':'toggle','id':user['id'],'enabled':True})
    helper({'op':'delete','id':user['id'],'confirm_name':'Test friend'})
    helper({'op':'global','paused':True});setup.health(options['domain'],public=False)
    with opener.open('https://relay.example.com/control/') as response:assert response.status==200
    helper({'op':'global','paused':False})
    assert json.loads(pathlib.Path('/etc/relay-panel/users.json').read_text())['users']==before['users']
    subprocess.run(['runuser','-u','relayadmin','--','test','-r','/var/lib/tproxy-accounting/usage.json'],check=True)
    auth=pathlib.Path('/var/lib/relay-panel/auth.json').read_bytes()
    setup.run('systemctl','stop','relay-panel','relay-helper')
    snapshot=manage.backup(include_programs=True)
    setup.install_files(ROOT,options,work,candidate,mtproxy)
    # Exercise restoration after a failed update, including root-only files and current symlink.
    setup.write('/etc/tproxy-server/config.json','broken')
    manage.restore_internal(snapshot)
    setup.health(options['domain'],public=False)
    assert pathlib.Path('/var/lib/relay-panel/auth.json').read_bytes()==auth
    assert json.loads(pathlib.Path('/etc/relay-panel/users.json').read_text())['users']==before['users']
    assert pathlib.Path('/opt/relay-panel/current').is_symlink()
print('PASS: install, real services, HTTPS, private API, key actions, pause/resume, accounting access, update persistence, rollback')
