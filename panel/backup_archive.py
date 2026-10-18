"""Portable, allowlisted logical archive. No programs or executable configuration."""
import contextlib
import hashlib
import io
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

MAX_EXPANDED=512*1024*1024

def layout(prefix='relay',panel_dir=None):
    return {
      'users':Path('/etc/'+prefix+'-panel/users.json'),
      'owner':Path('/var/lib/'+prefix+'-panel'),
      'hy2':Path('/var/lib/'+prefix+'-hy2'),
      'awg':Path('/var/lib/'+prefix+'-awg'),
      'usage':Path('/var/lib/tproxy-accounting/usage.json'),
      'site':Path(os.getenv('RELAY_BACKUP_SITE','/srv/relay-site')),
      'hy2config':Path('/etc/hysteria/config.yaml'),
      'hy2cover':Path('/var/lib/hysteria/cover'),
      'caddy':Path('/etc/caddy/Caddyfile'),
      'panel_dir':Path(panel_dir or '/opt/relay-panel/current/panel'),
    }

def sqlite_snapshot(source,target):
    with contextlib.closing(sqlite3.connect(f'file:{source}?mode=ro',uri=True)) as a,contextlib.closing(sqlite3.connect(target)) as b:a.backup(b)
    target.chmod(0o600)

def build_tar(output,paths,backup_dir=None):
    """Create a consistent SQLite snapshot and stream the compressed plaintext only to age."""
    base=Path(os.getenv('RELAY_BACKUP_TMP','/run')) if os.name=='posix' and Path('/run').is_dir() else None
    with tempfile.TemporaryDirectory(prefix='relay-snapshot-',dir=base) as tmp:
        temp=Path(tmp);files={}
        for logical,path in [('telegram/users.json',paths['users']),('telegram/usage.json',paths['usage']),('owner/auth.json',paths['owner']/'auth.json')]:
            if path.exists():
                dest=temp/(logical.replace('/','_'));dest.write_bytes(path.read_bytes());dest.chmod(0o600);files[logical]=dest
        for logical,path in [('owner/panel.sqlite3',paths['owner']/'panel.sqlite3'),('hysteria/hy2.sqlite3',paths['hy2']/'hy2.sqlite3')]:
            if path.exists():
                dest=temp/logical.replace('/','_');sqlite_snapshot(path,dest);files[logical]=dest
        if paths.get('awg') and (paths['awg']/'awg.sqlite3').exists():
            dest=temp/'awg.sqlite3';sqlite_snapshot(paths['awg']/'awg.sqlite3',dest);files['amnezia/awg.sqlite3']=dest
        for logical,folder in [('site',paths['site']),('hysteria/cover',paths['hy2cover'])]:
            if folder.exists():
                for path in folder.rglob('*'):
                    if path.is_file() and not path.is_symlink():files[logical+'/'+path.relative_to(folder).as_posix()]=path
        if backup_dir:
            for name in ('config.json','rclone.conf'):
                path=Path(backup_dir)/name
                if path.exists():files['backup/'+name]=path
        if len(files)+1>2000:raise ValueError('В копии слишком много файлов (не больше 2000 вместе с манифестом).')
        users=json.loads(files['telegram/users.json'].read_text())
        redirects=[]
        if paths.get('caddy') and paths['caddy'].exists():
            pattern=r'(?m)^([A-Za-z0-9., -]+)\s*\{\s*redir\s+https://'+re.escape(users['host'])+r'\{uri\}\s+(permanent|temporary|301|302|307|308)\s*\}'
            for match in re.finditer(pattern,paths['caddy'].read_text()):
                for host in re.split(r'[,\s]+',match[1].strip()):
                    if host:redirects.append({'host':host,'code':match[2]})
        metadata={'schema':1,'created':int(time.time()),'telegram_domain':users['host'],'hysteria':False,'redirects':redirects,'files':{}}
        if 'hysteria/hy2.sqlite3' in files:
            with contextlib.closing(sqlite3.connect(files['hysteria/hy2.sqlite3'])) as c:
                settings={k:json.loads(v) for k,v in c.execute('SELECT k,v FROM settings WHERE k IN (?,?)',('host','port'))}
            metadata.update(hysteria=True,hysteria_domain=settings['host'],hysteria_port=settings['port'])
        if 'amnezia/awg.sqlite3' in files:
            with contextlib.closing(sqlite3.connect(files['amnezia/awg.sqlite3'])) as c:
                settings={k:json.loads(v) for k,v in c.execute("SELECT k,v FROM settings WHERE k IN ('host','port')")}
            metadata.update(amnezia=True,amnezia_domain=settings['host'],amnezia_port=settings['port'])
        total=0
        with tarfile.open(fileobj=output,mode='w|gz') as archive:
            for name,path in files.items():
                # Snapshot mutable files again before hashing/streaming; no payload content is logged.
                body=path.read_bytes();total+=len(body)
                if total>MAX_EXPANDED:raise ValueError('Копия слишком велика для этой версии (512 МБ).')
                metadata['files'][name]={'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}
                item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o600;archive.addfile(item,io.BytesIO(body))
            body=json.dumps(metadata,ensure_ascii=False).encode()
            item=tarfile.TarInfo('manifest.json');item.size=len(body);item.mode=0o600;archive.addfile(item,io.BytesIO(body))
        return metadata

def encrypt(path,recipient,paths,backup_dir=None):
    path=Path(path);pending=path.with_name(path.name+'.pending')
    pending.unlink(missing_ok=True)
    try:
        process=subprocess.Popen(['age','--encrypt','--recipient',recipient,'--output',str(pending)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:metadata=build_tar(process.stdin,paths,backup_dir)
        except Exception:
            process.stdin.close();process.kill();process.wait();raise
        process.stdin.close();error=process.stderr.read();process.stderr.close();status=process.wait(timeout=120)
        if status:raise ValueError('Не удалось зашифровать копию. Проверь публичный ключ age.')
        pending.chmod(0o600);pending.replace(path);return metadata
    finally:pending.unlink(missing_ok=True)

def inspect_tar(path,destination):
    """Validate everything before creating target files; reject links, duplicates and traversal."""
    destination=Path(destination)
    with tarfile.open(path,'r:gz') as archive:
        members=[];names=set();total=0
        for item in archive:
            name=item.name
            if not item.isfile() or name.startswith('/') or '..' in Path(name).parts or '\\' in name or name in names:raise ValueError('Небезопасная структура архива.')
            if name!='manifest.json' and name not in ('telegram/users.json','telegram/usage.json','owner/auth.json','owner/panel.sqlite3','hysteria/hy2.sqlite3','amnezia/awg.sqlite3','backup/config.json','backup/rclone.conf') and not name.startswith(('site/','hysteria/cover/')):raise ValueError('Неизвестный файл в архиве.')
            names.add(name);total+=item.size
            if total>MAX_EXPANDED or len(names)>2000:raise ValueError('Архив превышает допустимый размер.')
            members.append(item)
        if 'manifest.json' not in names:raise ValueError('Нет манифеста резервной копии.')
        manifest=json.load(archive.extractfile('manifest.json'))
        if not isinstance(manifest,dict) or manifest.get('schema')!=1 or not isinstance(manifest.get('files'),dict) or set(manifest['files'])!=names-{'manifest.json'}:raise ValueError('Неподдерживаемая или повреждённая копия.')
        if not {'telegram/users.json','owner/auth.json','owner/panel.sqlite3'}<=names:raise ValueError('В копии нет обязательных данных.')
        if type(manifest.get('hysteria')) is not bool or manifest['hysteria']!=('hysteria/hy2.sqlite3' in names):raise ValueError('Неполная копия Hysteria.')
        for item in members:
            body=archive.extractfile(item).read()
            if item.name!='manifest.json':
                expected=manifest['files'][item.name]
                if not isinstance(expected,dict) or expected.get('size')!=len(body) or expected.get('sha256')!=hashlib.sha256(body).hexdigest():raise ValueError('Проверка целостности копии не пройдена.')
            target=destination/item.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(0o600)
    for name in ('owner/panel.sqlite3','hysteria/hy2.sqlite3','amnezia/awg.sqlite3'):
        p=destination/name
        if p.exists():
            with contextlib.closing(sqlite3.connect(f'file:{p}?mode=ro',uri=True)) as db:
                if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Повреждена база данных в копии.')
    users=json.loads((destination/'telegram/users.json').read_text())
    if not isinstance(users,dict) or users.get('host')!=manifest.get('telegram_domain') or not isinstance(users.get('users'),list) or len(users['users'])>100:raise ValueError('Некорректные профили в копии.')
    for user in users['users']:
        if not isinstance(user,dict) or not isinstance(user.get('secret'),str) or not isinstance(user.get('id'),str) or not re.fullmatch(r'[0-9a-f]{32}',user['secret']) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',user['id']) or type(user.get('enabled')) is not bool:raise ValueError('Некорректный ключ в копии.')
    awg=destination/'amnezia/awg.sqlite3'
    if bool(manifest.get('amnezia'))!=awg.exists():raise ValueError('Неполная копия AmneziaWG')
    if awg.exists():
        from awg_control import validate_settings,valid_key
        with contextlib.closing(sqlite3.connect(awg)) as c:
            c.row_factory=sqlite3.Row
            settings={r['k']:json.loads(r['v']) for r in c.execute('SELECT * FROM settings')}
            validate_settings(settings)
            if settings['host']!=manifest.get('amnezia_domain') or settings['port']!=manifest.get('amnezia_port'):raise ValueError('Настройки AmneziaWG не совпадают с манифестом')
            peers=c.execute('SELECT * FROM users').fetchall()
            if len(peers)>100:raise ValueError('Слишком много пользователей AmneziaWG')
            addresses=set();publics=set()
            for u in peers:
                if not re.fullmatch(r'u_[0-9a-f]{12}',u['id']) or not all(valid_key(u[k]) for k in ('private','public','psk')) or type(u['address']) is not int or not 2<=u['address']<=254 or u['address'] in addresses or u['public'] in publics:raise ValueError('Некорректный профиль AmneziaWG')
                addresses.add(u['address']);publics.add(u['public'])
    return manifest

def decrypt(ciphertext,identity,destination):
    """The private identity lives in a tmpfs file only for this operation."""
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    key=destination/'identity.txt';plain=destination/'archive.tar.gz'
    try:
        key.write_text(identity);key.chmod(0o600)
        result=subprocess.run(['age','--decrypt','--identity',str(key),'--output',str(plain),str(ciphertext)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=120)
        if result.returncode:raise ValueError('Ключ восстановления не подходит или архив повреждён.')
        return inspect_tar(plain,destination/'files')
    finally:
        key.unlink(missing_ok=True);plain.unlink(missing_ok=True)
