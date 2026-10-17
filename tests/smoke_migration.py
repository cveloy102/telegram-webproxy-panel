"""Real service stop, boot gate, encrypted final snapshot and standby recovery in CI."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:
    raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
from backup_control import Controller
from migration_control import Migration
from backup_routes import helper
from backup_archive import decrypt
from restore import main as restore
from installer import health


def wait(control):
    deadline=time.monotonic()+120
    while control.busy:
        if time.monotonic()>deadline:raise AssertionError('Migration timed out')
        time.sleep(.2)
    return control.status()


def active(name):
    return subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0


host=json.loads(Path('/etc/relay-panel/users.json').read_text())['host']
before=Path('/etc/relay-panel/users.json').read_bytes()
subprocess.run(['systemctl','stop','relay-backup'],check=True)
with tempfile.TemporaryDirectory(prefix='relay-migration-smoke-') as folder:
    work=Path(folder);key=work/'key.txt'
    subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
    recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
    backup=Controller(work/'backup')
    backup.config.update(folder='synthetic_folder_123',recipient=recipient)
    (backup.data/'rclone.conf').write_text('synthetic test token, never sent anywhere')
    cloud=work/'cloud';cloud.mkdir()
    def local_upload(*args):
        if args[0]=='copyto':
            shutil.copyfile(args[1],cloud/args[2].split(':',1)[1]);return b''
        path=cloud/args[-1].split(':',1)[1]
        return json.dumps({'Size':path.stat().st_size,'Hashes':{'MD5':hashlib.md5(path.read_bytes()).hexdigest()}}).encode()
    backup.rclone=local_upload
    migration=Migration(backup)
    # Failed upload must stop services without claiming a successful migration.
    with patch.object(backup,'rclone',side_effect=ValueError('Synthetic upload failure')):
        migration.call('stop',host)
        assert wait(migration)['phase']=='error'
    assert not active('mtproxy') and not active('hysteria-server')
    migration.call('stop',host)
    final=wait(migration);assert final['phase']=='stopped',final
    assert before==Path('/etc/relay-panel/users.json').read_bytes()
    # Explicit starts (also used on boot) cannot bypass the persistent gate.
    for name in ('mtproxy','tproxy-server','relay-hy2','hysteria-server','relay-refresh.timer'):
        subprocess.run(['systemctl','start',name],check=True)
        assert not active(name),name
    decrypt(cloud/final['file'],key.read_text(),work/'inspect')
    # A daemon restart keeps the stop; root CLI/API can resume without cloud access.
    subprocess.run(['systemctl','start','relay-backup'],check=True)
    for _ in range(30):
        try:
            assert helper({'op':'migration_status'})['phase']=='stopped';break
        except OSError:time.sleep(.2)
    else:raise AssertionError('Backup worker did not start')
    helper({'op':'migration_resume','confirm':host})
    for _ in range(120):
        state=helper({'op':'migration_status'})
        if not state['busy']:break
        time.sleep(.25)
    assert state['phase']=='running',state
    health(host,public=False)
    # Standby import of the final archive must not start user traffic.
    with patch('builtins.input',return_value='ВОССТАНОВИТЬ'):
        restore([str(cloud/final['file']),'--identity',str(key),'--standby'])
    assert helper({'op':'migration_status'})['phase']=='standby'
    assert not active('mtproxy') and not active('hysteria-server')
    helper({'op':'migration_resume','confirm':host})
    for _ in range(120):
        state=helper({'op':'migration_status'})
        if not state['busy']:break
        time.sleep(.25)
    assert state['phase']=='running',state
    health(host,public=False)
    assert before==Path('/etc/relay-panel/users.json').read_bytes()
    print('Migration failure/retry, persistent service gate, resume and standby restore: PASS')
