"""Run the real update entry point with both protocols and test its rollback."""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
from hy2_routes import helper as hy2
from awg_routes import helper as awg


def saved():
    return {'telegram':json.loads(Path('/etc/relay-panel/users.json').read_text())['users'],
            'owner':Path('/var/lib/relay-panel/auth.json').read_bytes(),
            'hy2':{u['id']:hy2({'op':'key','id':u['id']})['uri'] for u in hy2({'op':'status'})['users']},
            'awg':{u['id']:awg({'op':'key','id':u['id']})['conf'] for u in awg({'op':'status'})['users']}}


options=json.loads(setup.STATE.read_text());assert options.get('hy2_domain') and options.get('awg_domain')
before=saved();assert before['telegram'] and before['hy2'] and before['awg']
caddyfile=setup.caddyfile;health=setup.health


def local_caddy(domain,email=''):
    return caddyfile(domain,email).replace(domain+' {',domain+' {\n tls internal',1)


with patch.object(setup,'caddyfile',local_caddy),patch.object(setup,'health',lambda domain,public=True:health(domain,public=False)),\
     patch.object(sys,'argv',['installer.py','--source',str(ROOT),'--revision','protocol-update-smoke']),\
     patch('builtins.input',side_effect=['3','да']):
    setup.main()
assert saved()==before
assert json.loads(setup.STATE.read_text())['version']==setup.VERSION

# A real failed update stops services, snapshots state and executes rollback.
def fail_install(*args,**kwargs):
    Path('/etc/tproxy-server/config.json').write_text('injected-invalid-config')
    raise RuntimeError('injected update failure')


with patch.object(setup,'install_files',fail_install),\
     patch.object(sys,'argv',['installer.py','--source',str(ROOT)]),\
     patch('builtins.input',side_effect=['3','да']):
    try:setup.main()
    except RuntimeError as error:assert str(error)=='injected update failure'
    else:raise AssertionError('Failure injection was ignored')
health(options['domain'],public=False)
awg({'op':'migration_ready'});hy2({'op':'migration_ready'})
assert saved()==before
print('PASS: real updater and failed-update rollback preserve both protocols, existing users and original client configurations')
