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
NAMES=['relay-panel','relay-helper','tproxy-server','mtproxy','relay-refresh.timer']

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
            return None if item.name.endswith(('panel.sqlite3','panel.sqlite3-wal','panel.sqlite3-shm','panel.sqlite3-journal')) else item
        paths=['/etc/relay-panel','/etc/tproxy-server','/etc/mtproxy','/etc/caddy/Caddyfile','/var/lib/relay-panel','/var/lib/tproxy-accounting','/var/lib/caddy','/usr/local/sbin/relay-panel']
        if include_programs:
            paths+=['/opt/relay-panel','/opt/MTProxy','/usr/local/bin/tproxy-server']
        from units import units
        paths += [str(P('/etc/systemd/system')/name) for name in units()]
        for source in paths:
            if P(source).exists():archive.add(source,arcname=source.lstrip('/'),filter=no_database)
        database=DATA/'panel.sqlite3'
        if database.exists():
            target=P(temp)/'panel.sqlite3'
            with contextlib.closing(sqlite3.connect(f'file:{database}?mode=ro',uri=True)) as source,contextlib.closing(sqlite3.connect(target)) as destination:source.backup(destination)
            info=archive.gettarinfo(str(target),arcname='var/lib/relay-panel/panel.sqlite3')
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
        for item in archive.getmembers():
            if item.name.startswith('/') or '..' in P(item.name).parts:raise RuntimeError('Небезопасный путь в резервной копии.')
        archive.extractall('/')
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','reset-failed','mtproxy','tproxy-server','relay-helper','relay-panel'],check=True)
    subprocess.run(['systemctl','restart','mtproxy','tproxy-server','relay-helper','relay-panel','caddy','relay-refresh.timer'],check=True)

def refresh():
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
    if command=='status':
        state=json.loads((ROOT/'install.json').read_text())
        print('Relay Panel '+state.get('version','· установка не завершена')+'\nhttps://'+state['domain']+'/control/')
        subprocess.run(['systemctl','--no-pager','--full','status',*NAMES,'caddy'],check=False)
    elif command=='backup':print('Копия с ключами и настройками (храни как пароль): '+str(backup()))
    elif command=='setup-code':
        if owner_exists():raise RuntimeError('Владелец уже создан. Этот пункт не сбрасывает пароль или 2FA.')
        from installer import json_write,write
        cfg=json.loads((DATA/'auth.json').read_text());code=secrets.token_urlsafe(24)
        cfg.update(setup_hash=hashlib.sha256(code.encode()).hexdigest(),setup_expires=int(time.time())+86400)
        json_write(DATA/'auth.json',cfg,mode=0o600,user='relayadmin',group='relayadmin');write(ROOT/'setup-code',code+'\n',mode=0o600)
        subprocess.run(['systemctl','restart','relay-panel'],check=True);show_access()
    elif command=='refresh':refresh()
    else:raise RuntimeError('Команды: status, backup, setup-code. Для обновления повтори команду установки из README.')

if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError) as error:print('Ошибка: '+str(error),file=sys.stderr);sys.exit(1)
