"""A failed addition of both VPNs must restore Telegram-only selection and keys."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
from backup_archive import build_tar,layout

state=json.loads(setup.STATE.read_text());assert not state.get('hy2_domain') and not state.get('awg_domain')
users=Path('/etc/relay-panel/users.json').read_bytes();owner=Path('/var/lib/relay-panel/auth.json').read_bytes()
subprocess.run(['sysctl','-w','net.ipv4.ip_forward=0'],check=True,capture_output=True)
forwarding=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
caddyfile=setup.caddyfile;activate=setup.activate


def local_caddy(domain,email=''):
    return caddyfile(domain,email).replace(domain+' {',domain+' {\n tls internal',1)


def seed_hysteria(setup,options,standby=False):
    # Certificate issuance is tested separately; initialize real keys and enabled
    # units here so rollback must clean a partially installed Hysteria as well.
    from hy2_control import Controller
    Controller()
    setup.run('systemctl','enable','relay-hy2','hysteria-server')


def fail_activation():
    with patch('hysteria_install.activate',seed_hysteria):activate()
    assert subprocess.run(['systemctl','is-active','--quiet','amneziawg-server']).returncode==0
    raise RuntimeError('injected optional-protocol activation failure')


answers=['3','да','hy2.example.com','24443','да','vpn.example.com','51820','да']
with patch.object(setup,'caddyfile',local_caddy),patch.object(setup,'check_dns'),patch.object(setup,'activate',fail_activation),\
     patch.object(sys,'argv',['installer.py','--source',str(ROOT)]),patch('builtins.input',side_effect=answers):
    try:setup.main()
    except RuntimeError as error:assert str(error)=='injected optional-protocol activation failure'
    else:raise AssertionError('Injected failure did not trigger rollback')

assert json.loads(setup.STATE.read_text())==state
assert Path('/etc/relay-panel/users.json').read_bytes()==users
assert Path('/var/lib/relay-panel/auth.json').read_bytes()==owner
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()==forwarding
for name in ('relay-hy2','hysteria-server','relay-awg','amneziawg-server'):
    assert subprocess.run(['systemctl','is-active','--quiet',name]).returncode!=0
    assert subprocess.run(['systemctl','is-enabled','--quiet',name]).returncode!=0
    load=subprocess.run(['systemctl','show',name,'-p','LoadState','--value'],capture_output=True,text=True)
    assert load.stdout.strip()=='not-found',name
for path in ('/var/lib/relay-hy2','/var/lib/relay-awg','/etc/hysteria','/etc/sysctl.d/80-relay-awg.conf'):
    assert not Path(path).exists(),path
manifest=build_tar(io.BytesIO(),layout())
assert not manifest['hysteria'] and not manifest.get('amnezia')
setup.health(state['domain'],public=False)
print('PASS: failed VPN addition preserves old users, protocol selection and forwarding; neither reboot nor backup re-enables partial protocols')
