"""Actual fresh installer dialogue for each optional-protocol combination in CI."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'panel')]
import installer as setup
import hysteria_install
from helper import Controller as Telegram

mode=sys.argv[1];assert mode in ('none','hysteria','amnezia','both')
assert not setup.STATE.exists(),'Fresh installation requires a fresh CI runner'
want_hy=mode in ('hysteria','both');want_awg=mode in ('amnezia','both')
caddyfile=setup.caddyfile;health=setup.health;hy_activate=hysteria_install.activate


def local_caddy(domain,email=''):
    return caddyfile(domain,email).replace(domain+' {',domain+' {\n tls internal',1)


def local_hysteria(context,options,standby=False):
    if not options.get('hy2_domain'):return
    import yaml
    from hy2_control import Controller
    control=Controller()
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=hy2.example.com',
                    '-keyout','/var/lib/hysteria/test.key','-out','/var/lib/hysteria/test.crt'],check=True,capture_output=True)
    import shutil
    for name in ('test.key','test.crt'):shutil.chown('/var/lib/hysteria/'+name,'hysteria','hysteria')
    cfg=yaml.safe_load(control.config.read_text());cfg.pop('acme',None)
    cfg['tls']={'cert':'/var/lib/hysteria/test.crt','key':'/var/lib/hysteria/test.key'}
    setup.write(control.config,yaml.safe_dump(cfg),mode=0o640,group='hysteria')
    hy_activate(context,options,standby=standby)


answers=['1','relay.example.com','','','','','']
answers+=['да','hy2.example.com','24443'] if want_hy else ['нет']
answers+=['да','vpn.example.com','51820'] if want_awg else ['нет']
answers+=['да']
with patch.object(sys,'argv',['installer.py','--source',str(ROOT),'--revision','fresh-'+mode]),\
     patch.object(setup,'public_ipv4',return_value='1.1.1.1'),patch.object(setup,'check_dns'),\
     patch.object(setup,'caddyfile',local_caddy),patch.object(setup,'health',lambda domain,public=True:health(domain,public=False)),\
     patch('hysteria_install.activate',local_hysteria),patch('manage.show_access'),patch('builtins.input',side_effect=answers):
    setup.main()
from awg_routes import helper as awg
from hy2_routes import helper as hy2
state=json.loads(setup.STATE.read_text())
assert state['phase']=='complete' and state['version']==setup.VERSION
assert bool(state.get('hy2_domain'))==want_hy
assert bool(state.get('awg_domain'))==want_awg
tg=Telegram();tg.call({'op':'create','name':'Fresh friend','group':'Семья'})
before=Path('/etc/relay-panel/users.json').read_bytes()
auth=Path('/var/lib/relay-panel/auth.json').read_bytes()
if want_hy:
    hy2({'op':'create','name':'Fresh HY friend','group':'Семья'});hy2({'op':'migration_ready'})
if want_awg:
    awg({'op':'create','name':'Fresh AWG friend','group':'Семья'});awg({'op':'migration_ready'})
for service,expected in (('hysteria-server',want_hy),('relay-hy2',want_hy),('amneziawg-server',want_awg),('relay-awg',want_awg)):
    assert (subprocess.run(['systemctl','is-active','--quiet',service]).returncode==0)==expected,service
# Exercise existing-installation check, backup, invalid entry and exit through main.
for answer in (['1'],['2'],['invalid','0']):
    with patch.object(sys,'argv',['installer.py','--source',str(ROOT)]),patch('builtins.input',side_effect=answer),\
         patch.object(setup,'health',lambda domain,public=True:health(domain,public=False)),patch('manage.show_access'):
        setup.main()
assert Path('/etc/relay-panel/users.json').read_bytes()==before
assert Path('/var/lib/relay-panel/auth.json').read_bytes()==auth
assert list(Path('/var/backups/relay-panel').glob('*.tar.gz'))
print('PASS: fresh real installer dialogue, optional services, user creation, check, backup and exit:',mode)
