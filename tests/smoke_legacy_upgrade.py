"""Upgrade an actual pinned pre-AWG release, preserving its existing users."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import installer as setup

COMMIT='3428d536ca6a4496568c6faff87f44c8a4be6a27'  # 0.4.0-beta.4
SHA256='04beaada59ac870fb6d122871f175de31698883f24efbc6a8f612b7320784c3c'

with tempfile.TemporaryDirectory(prefix='relay-legacy-',dir='/var/tmp') as folder:
    work=Path(folder);archive=work/'legacy.tar.gz'
    setup.download(f'https://codeload.github.com/cveloy102/telegram-webproxy-panel/tar.gz/{COMMIT}',archive,SHA256)
    legacy=setup.extract(archive,work/'source')
    subprocess.run([sys.executable,str(legacy/'tests/smoke_ubuntu.py')],check=True)
    users=Path('/etc/relay-panel/users.json');auth=Path('/var/lib/relay-panel/auth.json')
    before=json.loads(users.read_text())['users'];owner=auth.read_bytes()
    assert before,'Legacy fixture must contain pre-existing users'
    subprocess.run([sys.executable,str(ROOT/'tests/smoke_ubuntu.py')],check=True)
    assert before==json.loads(users.read_text())['users']
    assert owner==auth.read_bytes()
    current=Path('/opt/relay-panel/current').resolve()
    assert "VERSION='"+setup.VERSION+"'" in (current/'installer.py').read_text()
    print('PASS: pinned 0.4.0-beta.4 upgraded to current source with original Telegram users and owner credentials')
