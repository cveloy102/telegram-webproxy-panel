#!/usr/bin/env python3
"""Local management. This utility never connects to an external control server."""
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

P=pathlib.Path
DATA=P('/var/lib/relay-panel')
ROOT=P('/etc/relay-panel')
BACKUPS=P('/var/backups/relay-panel')
NAMES=['relay-awg','amneziawg-server','relay-backup','relay-hy2','hysteria-server','relay-panel','relay-helper','tproxy-server','mtproxy','relay-refresh.timer']

def owner_exists():
    path=DATA/'panel.sqlite3'
    if not path.exists():return False
    with contextlib.closing(sqlite3.connect(f'file:{path}?mode=ro',uri=True)) as conn:
        return bool(conn.execute('SELECT 1 FROM owner WHERE id=1').fetchone())

def show_access():
    state=json.loads((ROOT/'install.json').read_text())
    print('Панель: https://'+state['domain']+'/control/')
    if owner_exists():
        print('Владелец уже настроен. Войди со своим паролем. Ключи сохранены.')
    else:
        cfg=json.loads((DATA/'auth.json').read_text())
        if cfg['setup_expires']<time.time():print('Код первого входа истёк. Получить новый: relay-panel setup-code')
        else:
            print('Одноразовый код владельца: '+(ROOT/'setup-code').read_text().strip())
            expires=dt.datetime.fromtimestamp(cfg['setup_expires'],dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
            print('Действует до '+expires+'. Задай пароль в браузере и подключи аутентификатор.')
    print('Дальше: «Выдать ключ» → «Ссылка / QR». Нужен Telegram с типом прокси WEB.')
    print('Состояние служб: relay-panel status\nРезервная копия: relay-panel backup')

def backup(include_programs=False):
    BACKUPS.mkdir(parents=True,exist_ok=True);BACKUPS.chmod(0o700)
    path=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(3)+'.tar.gz')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with tempfile.TemporaryDirectory(prefix='relay-backup-') as temp,os.fdopen(descriptor,'wb') as output,tarfile.open(fileobj=output,mode='w:gz') as archive:
        def no_database(item):
            return None if P(item.name).name in ('awg.sqlite3','awg.sqlite3-wal','awg.sqlite3-shm','awg.sqlite3-journal') else (None if item.name.endswith(('panel.sqlite3','panel.sqlite3-wal','panel.sqlite3-shm','panel.sqlite3-journal','hy2.sqlite3','hy2.sqlite3-wal','hy2.sqlite3-shm','hy2.sqlite3-journal')) else item)
        paths=['/var/lib/relay-awg','/etc/systemd/system/relay-awg.service','/etc/systemd/system/amneziawg-server.service','/etc/tmpfiles.d/relay-awg.conf','/etc/sysctl.d/80-relay-awg.conf','/usr/local/bin/awg','/usr/local/bin/amneziawg-go','/etc/hysteria','/var/lib/hysteria','/var/lib/relay-hy2','/var/lib/relay-backup','/srv/relay-site','/etc/systemd/system/relay-backup.service','/etc/systemd/system/relay-hy2.service','/etc/systemd/system/hysteria-server.service','/usr/local/bin/hysteria','/etc/relay-panel','/etc/tproxy-server','/etc/mtproxy','/etc/caddy/Caddyfile','/var/lib/relay-panel','/var/lib/tproxy-accounting','/var/lib/caddy','/usr/local/sbin/relay-panel']
        if include_programs:
            paths+=['/opt/relay-panel','/opt/MTProxy','/usr/local/bin/tproxy-server']
        from units import units
        paths += [str(P('/etc/systemd/system')/name) for name in units()]
        for source in paths:
            if P(source).exists():archive.add(source,arcname=source.lstrip('/'),filter=no_database)
        for database in (DATA/'panel.sqlite3',P('/var/lib/relay-hy2/hy2.sqlite3'),P('/var/lib/relay-awg/awg.sqlite3')):
            if database.exists():
                target=P(temp)/database.name
                with contextlib.closing(sqlite3.connect(f'file:{database}?mode=ro',uri=True)) as source,contextlib.closing(sqlite3.connect(target)) as destination:source.backup(destination)
                info=archive.gettarinfo(str(target),arcname=str(database).lstrip('/'))
                import pwd,grp
                stat=database.stat();info.uid=stat.st_uid;info.gid=stat.st_gid;info.mode=0o600
                info.uname=pwd.getpwuid(stat.st_uid).pw_name;info.gname=grp.getgrgid(stat.st_gid).gr_name
                with open(target,'rb') as file:archive.addfile(info,file)
    return path

def restore_internal(path):
    """Only installer-created local backups, for a failed update on the same host."""
    path=P(path)
    if path.parent.resolve()!=BACKUPS.resolve() or path.stat().st_uid!=0:raise RuntimeError('Неподходящий файл резервной копии.')
    subprocess.run(['systemctl','stop',*NAMES],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    current=P('/opt/relay-panel/current')
    if current.is_symlink():current.unlink()
    with tarfile.open(path) as archive:
        members=archive.getmembers()
        for item in members:
            if item.name.startswith('/') or '..' in P(item.name).parts:raise RuntimeError('Небезопасный путь в резервной копии.')
        binaries={'usr/local/bin/amneziawg-go','usr/local/bin/awg','usr/local/bin/hysteria','usr/local/bin/tproxy-server'}
        ordinary=[]
        for item in members:
            if item.name not in binaries or not item.isfile():
                ordinary.append(item);continue
            # A different interface/client may still be using this executable.
            # Rename gives the restored service a new inode without ETXTBSY.
            target=P('/')/item.name
            with tempfile.NamedTemporaryFile(dir=target.parent,prefix=target.name+'.restore-',delete=False) as output:
                pending=P(output.name)
                try:
                    with archive.extractfile(item) as source:shutil.copyfileobj(source,output)
                    output.flush();os.fsync(output.fileno())
                    pending.chmod(item.mode & 0o777);os.chown(pending,item.uid,item.gid)
                    pending.replace(target)
                finally:pending.unlink(missing_ok=True)
        archive.extractall('/',members=ordinary)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','reset-failed','mtproxy','tproxy-server','relay-helper','relay-panel'],check=True)
    sys.path.insert(0,str(P(__file__).parent/'panel'))
    from migration_state import blocked
    names=['relay-helper','relay-panel','caddy']
    if not blocked():names+=['mtproxy','tproxy-server','relay-refresh.timer']
    subprocess.run(['systemctl','restart',*names],check=True)
    state=json.loads((ROOT/'install.json').read_text())
    selected=['relay-backup']
    if not blocked() and state.get('hy2_domain'):selected+=['relay-hy2','hysteria-server']
    if not blocked() and state.get('awg_domain'):selected+=['amneziawg-server','relay-awg']
    for field,services,paths in (
        ('hy2_domain',('relay-hy2','hysteria-server'),('/var/lib/relay-hy2','/etc/hysteria','/var/lib/hysteria')),
        ('awg_domain',('relay-awg','amneziawg-server'),('/var/lib/relay-awg',))):
        if state.get(field):continue
        subprocess.run(['systemctl','disable',*services],capture_output=True)
        for name in services:P('/etc/systemd/system/'+name+'.service').unlink(missing_ok=True)
        if field=='awg_domain':
            previous=P('/var/lib/relay-awg/previous-forwarding')
            if previous.exists() and previous.read_text().strip() in ('0','1'):
                subprocess.run(['sysctl','-w','net.ipv4.ip_forward='+previous.read_text().strip()],check=True,capture_output=True)
            for name in ('/etc/sysctl.d/80-relay-awg.conf','/etc/tmpfiles.d/relay-awg.conf'):P(name).unlink(missing_ok=True)
        # Retain failed-addition secrets privately, outside the portable backup
        # inventory. Neither reboot nor later recovery may re-enable that protocol.
        present=[P(path) for path in paths if P(path).exists()]
        if present:
            quarantine=BACKUPS/('incomplete-'+field+'-'+secrets.token_hex(6));quarantine.mkdir(mode=0o700)
            for index,path in enumerate(present):shutil.move(str(path),str(quarantine/(str(index)+'-'+path.name)))
    subprocess.run(['systemctl','daemon-reload'],check=True)
    optional=[name for name in selected if P('/etc/systemd/system/'+name+'.service').exists()]
    if optional:
        subprocess.run(['systemctl','reset-failed',*optional],check=True)
        subprocess.run(['systemctl','restart',*optional],check=True)
    # Type=simple reports started before the control socket and tunnel are ready.
    # Finish rollback only after the restored protocols actually accept requests.
    if not blocked():
        for field,module in (('awg_domain','awg_routes'),('hy2_domain','hy2_routes')):
            if not state.get(field):continue
            helper=__import__(module,fromlist=['helper']).helper
            for attempt in range(60):
                try:helper({'op':'migration_ready'});break
                except (OSError,ValueError):time.sleep(1)
            else:raise RuntimeError('После отката не готов протокол: '+field)

def refresh():
    sys.path.insert(0,str(P(__file__).parent/'panel'))
    from migration_state import mutation
    with mutation():return refresh_active()


def refresh_active():
    # Download once and replace only after format checks; preserve the last good config on failure.
    path=P('/etc/mtproxy/proxy-multi.conf');temp=path.with_name('proxy-multi.conf.new')
    try:
        with urllib.request.urlopen('https://core.telegram.org/getProxyConfig',timeout=30) as response:content=response.read(1024*1024)
        if len(content)<100 or b'default ' not in content or b'proxy_for ' not in content:raise RuntimeError('Неожиданный формат Telegram config.')
        if content==path.read_bytes():return
        temp.write_bytes(content);shutil.chown(temp,'root','mtproxy');temp.chmod(0o640);temp.replace(path)
        subprocess.run(['systemctl','restart','mtproxy'],check=True)
    finally:temp.unlink(missing_ok=True)

def main():
    if os.geteuid()!=0:raise RuntimeError('Нужен root: sudo relay-panel '+(' '.join(sys.argv[1:])))
    command=sys.argv[1] if len(sys.argv)>1 else 'status'
    sys.path.insert(0,str(P(__file__).parent/'panel'))
    if command=='migration':
        from backup_routes import helper
        action=sys.argv[2] if len(sys.argv)>2 else 'status'
        if action not in ('status','stop','resume'):raise ValueError('Команды: migration status, migration stop, migration resume')
        payload={'op':'migration_'+action}
        if action!='status':payload['confirm']=input('Введи домен этого сервера для подтверждения '+action+': ').strip()
        print(json.dumps(helper(payload),ensure_ascii=False,indent=2));return
    if command=='status':
        state=json.loads((ROOT/'install.json').read_text())
        print('Relay Panel '+state.get('version','· установка не завершена')+'\nhttps://'+state['domain']+'/control/')
        subprocess.run(['systemctl','--no-pager','--full','status',*NAMES,'caddy'],check=False)
    elif command=='backup':print('Копия с ключами и настройками (храни как пароль): '+str(backup()))
    elif command=='restore':
        from restore import main as restore
        restore(sys.argv[2:])
    elif command=='setup-code':
        if owner_exists():raise RuntimeError('Владелец уже создан. Этот пункт не сбрасывает пароль или 2FA.')
        from installer import json_write,write
        cfg=json.loads((DATA/'auth.json').read_text());code=secrets.token_urlsafe(24)
        cfg.update(setup_hash=hashlib.sha256(code.encode()).hexdigest(),setup_expires=int(time.time())+86400)
        json_write(DATA/'auth.json',cfg,mode=0o600,user='relayadmin',group='relayadmin');write(ROOT/'setup-code',code+'\n',mode=0o600)
        subprocess.run(['systemctl','restart','relay-panel'],check=True);show_access()
    elif command=='refresh':refresh()
    else:raise RuntimeError('Команды: status, backup, restore, migration status|stop|resume, setup-code. Для обновления повтори команду установки из README.')

if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError) as error:print('Ошибка: '+str(error),file=sys.stderr);sys.exit(1)
