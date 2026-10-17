"""Fresh-VPS wizard and interrupted/resumed recovery on an expendable CI runner."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:
    raise SystemExit('Expendable GitHub runner only')
SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE));sys.path.insert(0,str(SOURCE/'panel'))
import installer as setup
import hysteria_install
import recovery_wizard as wizard
from backup_archive import encrypt,layout
from migration_control import SERVICES


def active(name):return subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0


with tempfile.TemporaryDirectory(prefix='relay-wizard-smoke-') as folder:
    work=Path(folder)
    key=work/'key.txt'
    subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
    recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
    archive=work/'backup.tar.gz.age';encrypt(archive,recipient,layout())
    before=Path('/etc/relay-panel/users.json').read_bytes()
    auth=Path('/var/lib/relay-panel/auth.json').read_bytes()
    # Use already compiled, tested binaries; this stage tests orchestration rather
    # than rebuilding the same upstream sources for a third time on this runner.
    shutil.copyfile('/usr/local/bin/tproxy-server',work/'tproxy-server')
    for name in ('test.key','test.crt'):shutil.copyfile('/var/lib/hysteria/'+name,work/name)
    ca=next(Path('/var/lib/caddy').rglob('root.crt'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
    names=['relay-panel','relay-helper','relay-hy2','hysteria-server','tproxy-server','mtproxy','relay-backup','relay-refresh.timer','relay-refresh.service','caddy','tproxy-firewall']
    subprocess.run(['systemctl','stop',*names],check=True)
    # Move a strict allowlist into the fixture directory to model a clean VPS.
    # This script refuses to run outside the disposable GitHub runner.
    moved=work/'old';moved.mkdir()
    paths=['/opt/relay-panel','/opt/MTProxy','/etc/relay-panel','/etc/tproxy-server','/etc/mtproxy','/etc/hysteria','/etc/caddy/Caddyfile','/var/lib/relay-panel','/var/lib/relay-hy2','/var/lib/relay-backup','/var/lib/relay-migration','/var/lib/hysteria','/var/lib/tproxy-accounting','/srv/relay-site']
    for i,name in enumerate(paths):
        path=Path(name)
        if path.exists():shutil.move(str(path),str(moved/str(i)))
    mtproxy=moved/str(paths.index('/opt/MTProxy'))
    source_caddy=setup.caddyfile
    hy2_caddy=hysteria_install.caddy
    hy2_install=hysteria_install.install
    def local_caddy(domain,email=''):
        return source_caddy(domain,email).replace(domain+' {',domain+' {\n tls internal',1)
    def local_hy2(domain):
        return hy2_caddy(domain).replace('\n'+domain+' {','\n'+domain+' {\n tls internal',1)
    def local_hy2_install(*args):
        hy2_install(*args)
        from hy2_control import Controller
        import yaml
        controller=Controller()  # Seed the host setting before replacing ACME.
        for name in ('test.key','test.crt'):
            target=Path('/var/lib/hysteria')/name;shutil.copyfile(work/name,target);shutil.chown(target,'hysteria','hysteria');target.chmod(0o600)
        cfg=yaml.safe_load(controller.config.read_text());cfg.pop('acme',None)
        cfg['tls']={'cert':'/var/lib/hysteria/test.crt','key':'/var/lib/hysteria/test.key'}
        setup.write(controller.config,yaml.safe_dump(cfg),mode=0o640,group='hysteria')
    failed=set()
    def dns(domain,address):
        # Deterministically exercise polling; actual TLS is tested against local CA.
        if domain not in failed:failed.add(domain);raise RuntimeError('Synthetic old DNS; waiting')
    def https(domain,panel=False):
        with opener.open('https://'+domain+('/control/' if panel else '/'),timeout=5) as response:
            assert response.status==200
    def answers(prompt):
        if 'Путь к архиву' in prompt:return str(archive)
        if 'relay-recovery-key.txt' in prompt:return str(key)
        if 'IPv4 НОВОГО' in prompt:return '1.1.1.1'
        if 'Восстановить эту копию' in prompt:return 'да'
        if 'Старый сервер выключен' in prompt:return 'нет'
        raise AssertionError(prompt)
    original_wait=wizard.wait_check
    def fast_wait(label,check):
        attempts=0
        def bounded_check():
            nonlocal attempts
            attempts+=1
            if attempts>20:raise AssertionError('Wizard check did not become ready: '+label)
            check()
        return original_wait(label,bounded_check,interval=1)
    # Hysteria's DNS name must resolve locally for its HTTPS cover check.
    with open('/etc/hosts','a') as hosts:hosts.write('\n127.0.0.1 hy2.example.com\n')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(setup,'packages'))
        stack.enter_context(patch.object(setup,'build',return_value=(work/'tproxy-server',mtproxy)))
        stack.enter_context(patch.object(setup,'public_ipv4',return_value='1.1.1.1'))
        stack.enter_context(patch.object(setup,'check_dns',side_effect=dns))
        stack.enter_context(patch.object(setup,'caddyfile',side_effect=local_caddy))
        stack.enter_context(patch.object(hysteria_install,'caddy',side_effect=local_hy2))
        stack.enter_context(patch.object(hysteria_install,'install',side_effect=local_hy2_install))
        stack.enter_context(patch.object(wizard,'check_https',side_effect=https))
        stack.enter_context(patch.object(wizard,'wait_check',side_effect=fast_wait))
        # A failed import must roll back to standby, never publish bootstrap keys.
        import restore
        with patch('builtins.input',side_effect=answers),patch.object(restore,'restore_files',side_effect=RuntimeError('Synthetic interrupted import')):
            try:wizard.run_wizard(SOURCE,'wizard-smoke',setup=setup)
            except ValueError:pass
            else:raise AssertionError('Synthetic import failure was ignored')
        assert wizard.read_state()['installed'] and not wizard.read_state().get('imported')
        assert Path('/var/lib/relay-migration/blocked').exists()
        for name in SERVICES:assert not active(name),name
        with patch('builtins.input',side_effect=answers):
            wizard.run_wizard(SOURCE,'wizard-smoke',setup=setup)
        state=wizard.read_state()
        assert state['imported'] and state['https'] and not state.get('complete')
        assert wizard.pending()
        checkpoint=(wizard.ROOT/'state.json').read_text()
        assert key.read_text() not in checkpoint and str(key) not in checkpoint
        assert before==Path('/etc/relay-panel/users.json').read_bytes()
        assert auth==Path('/var/lib/relay-panel/auth.json').read_bytes()
        for name in SERVICES:
            # Optional protocol units need not exist in a Telegram/Hysteria-only fixture.
            load=subprocess.run(['systemctl','show',name,'-p','LoadState','--value'],capture_output=True,text=True)
            if load.stdout.strip() in ('','not-found'):continue
            subprocess.run(['systemctl','start',name],check=True)
            assert not active(name),name
        # Simulate terminal loss while DNS has drifted: no key or reimport allowed.
        with patch.object(setup,'check_dns',side_effect=KeyboardInterrupt),patch.object(wizard,'identity_file',side_effect=AssertionError('Key must not be requested after import')):
            try:wizard.run_wizard(SOURCE,'wizard-smoke',setup=setup)
            except KeyboardInterrupt:pass
            else:raise AssertionError('Interrupted DNS poll was ignored')
        assert wizard.read_state()['imported'] and not wizard.read_state()['dns']
        with patch('builtins.input',return_value='да'),patch.object(wizard,'identity_file',side_effect=AssertionError('Key must not be requested after import')):
            wizard.run_wizard(SOURCE,'wizard-smoke',setup=setup)
        assert wizard.read_state()['complete'] and not wizard.pending()
        for name in ('mtproxy','tproxy-server','relay-hy2','hysteria-server'):assert active(name),name
        assert before==Path('/etc/relay-panel/users.json').read_bytes()
        assert auth==Path('/var/lib/relay-panel/auth.json').read_bytes()
        setup.health('relay.example.com',public=False)
        # Authenticate a real QUIC client using the recovered key, not just /online.
        from hy2_control import Controller
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        import yaml
        controller=Controller()
        with controller.db() as db:
            secret=db.execute("SELECT secret FROM users WHERE id='default'").fetchone()[0]
            settings=controller.settings(db)
        class Response(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(b'wizard-recovered-key-ok')
            def log_message(self,*args):pass
        http=ThreadingHTTPServer(('127.0.0.1',0),Response)
        threading.Thread(target=http.serve_forever,daemon=True).start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0));socks_port=reservation.getsockname()[1]
        config={'server':'127.0.0.1:'+str(settings['port']),'auth':secret,
                'tls':{'sni':'hy2.example.com','insecure':True},'socks5':{'listen':'127.0.0.1:'+str(socks_port)}}
        if settings['obfs']:config['obfs']={'type':'salamander','salamander':{'password':settings['obfs_password']}}
        client_config=work/'client.yaml';client_config.write_text(yaml.safe_dump(config));client_config.chmod(0o600)
        client=subprocess.Popen(['/usr/local/bin/hysteria','client','--config',str(client_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(20):
                result=subprocess.run(['curl','--fail','--silent','--max-time','3','--noproxy','','--proxy','socks5h://127.0.0.1:'+str(socks_port),'http://127.0.0.1:'+str(http.server_port)+'/'],capture_output=True)
                if result.returncode==0:
                    assert result.stdout==b'wizard-recovered-key-ok';break
                time.sleep(1)
            else:raise AssertionError('Recovered Hysteria key did not carry traffic')
        finally:client.terminate();client.wait(timeout=10);http.shutdown()
        # A third invocation must never replace a completed installation.
        with patch.object(setup,'preflight',side_effect=AssertionError('Completed session reinstalled')):
            wizard.run_wizard(SOURCE,'wizard-smoke',setup=setup)
    print('PASS: fresh wizard, inactive bootstrap, preserved keys, DNS polling, TLS, interrupted/resumed checkpoint and explicit enable')
