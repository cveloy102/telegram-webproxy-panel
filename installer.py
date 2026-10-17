#!/usr/bin/env python3
"""Interactive installer for a dedicated Ubuntu 24.04 amd64 VPS."""
import argparse
import contextlib
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from units import units, caddyfile, FIREWALL

VERSION='0.4.0-beta.3'
RELAY_COMMIT='c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8'
RELAY_SHA256='a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549'
MTPROXY_COMMIT='f36d8af769ffaeac36978d38c2c0f6d1104c2137'
MTPROXY_SHA256='919795c416b870670841a21d1930ad97a24c7b84b9eb8c6f9e3de32f2fdf4655'
P=pathlib.Path
BASE=P('/opt/relay-panel')
STATE=P('/etc/relay-panel/install.json')
LOG=P('/var/log/relay-panel-install.log')
SERVICES=['relay-panel','relay-helper','tproxy-server','mtproxy','relay-refresh.timer']


def open_install_lock():
    # Reopen without O_CREAT/O_TRUNC: Linux protected_regular rejects root writes
    # to somebody else's file in a sticky directory. Never follow a lock symlink.
    path='/run/lock/relay-panel-install.lock'
    flags=os.O_RDONLY|os.O_NOFOLLOW
    try:descriptor=os.open(path,flags)
    except FileNotFoundError:
        try:descriptor=os.open(path,flags|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError:descriptor=os.open(path,flags)
    info=os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0:
        os.close(descriptor)
        raise RuntimeError('Файл блокировки установщика должен быть обычным файлом root: '+path+'. Данные сервера не изменены.')
    return os.fdopen(descriptor,'r')

def domain_name(value):
    value=value.strip().lower().rstrip('.')
    try:value=value.encode('idna').decode('ascii')
    except UnicodeError:raise ValueError('Не удалось прочитать домен.') from None
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.')):
        raise ValueError('Нужен домен вроде tg.example.com, без https://, порта и пути.')
    try:ipaddress.ip_address(value)
    except ValueError:return value
    raise ValueError('Введи домен, а не IP-адрес.')

def site_options(title,contact,theme):
    title=title.strip()
    if not 1<=len(title)<=60 or any(ord(c)<32 for c in title):raise ValueError('Название: от 1 до 60 символов, без переносов строк.')
    contact=contact.strip().removeprefix('@')
    if contact and not re.fullmatch('[A-Za-z][A-Za-z0-9_]{3,31}',contact):raise ValueError('Контакт: Telegram username без ссылки, например @example_user, либо пустая строка.')
    if theme not in ('pixel','minimal'):raise ValueError('Неизвестная тема.')
    return dict(title=title,contact=contact,theme=theme)

def render_site(options):
    title=html.escape(options['title']); contact=options['contact']
    button=f'<a class="button" href="https://t.me/{html.escape(contact,quote=True)}" rel="noreferrer noopener">Написать в Telegram ↗</a>' if contact else ''
    pixel=options['theme']=='pixel'
    color='#f44b50' if pixel else '#70bbff'
    background='#101112' if pixel else '#111827'
    style='font-family:ui-monospace,monospace' if pixel else 'font-family:system-ui,sans-serif'
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>{title}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;background:{background};color:#eee;{style}}}main{{max-width:850px;margin:12vh auto;padding:32px}}.mark{{color:{color};font-size:40px;letter-spacing:6px}}small{{color:#999}}h1{{font-size:clamp(32px,7vw,64px);overflow-wrap:anywhere;font-weight:600}}p{{color:#aaa;line-height:1.7}}.button{{display:inline-block;margin-top:24px;padding:18px 24px;background:{color};color:#101112;text-decoration:none;font-weight:700}}.button:focus-visible{{outline:3px solid white;outline-offset:5px}}footer{{margin-top:80px;padding-top:20px;border-top:1px solid #333;color:#888;font-size:12px}}</style>
<main><div class="mark" aria-hidden="true">▪ ▪ ▪<br>▪ ▪ ▪</div><small>PERSONAL SPACE</small><h1>{title}</h1><p>На связи.</p>{button}<footer>Своя маленькая часть интернета.</footer></main></html>'''

def ask(prompt,default=None,validate=None):
    while True:
        try:value=input(prompt+(f' [{default}]' if default is not None else '')+': ').strip()
        except EOFError:raise RuntimeError('Нужна интерактивная консоль. Открой терминал VPS и повтори команду.') from None
        except UnicodeDecodeError:
            print('  Не удалось прочитать ввод в UTF-8. Выбери кодировку UTF-8 в терминале и введи значение заново. Попробуй набрать его вручную вместо вставки.')
            continue
        if not value and default is not None:value=default
        try:return validate(value) if validate else value
        except ValueError as error:print('  '+str(error))

def download(url,path,checksum=None):
    error=None
    for attempt in range(3):
        try:
            request=urllib.request.Request(url,headers={'User-Agent':'RelayPanelInstaller/'+VERSION})
            with urllib.request.urlopen(request,timeout=40) as response,open(path,'wb') as output:shutil.copyfileobj(response,output)
            if checksum and hashlib.sha256(P(path).read_bytes()).hexdigest()!=checksum:
                raise RuntimeError('Контрольная сумма исходников не совпала. Архив не будет запущен.')
            return
        except (OSError,RuntimeError) as caught:
            error=caught
            if isinstance(caught,RuntimeError):break
            time.sleep(attempt+1)
    raise RuntimeError(f'Не удалось скачать {url.split("/")[2]}. Проверь интернет на VPS. {error}') from None

def extract(archive,destination):
    destination=P(destination);destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive) as source:
        for item in source.getmembers():
            parts=P(item.name).parts
            if item.name.startswith('/') or '..' in parts or not(item.isdir() or item.isfile()):raise RuntimeError('Небезопасный путь в исходниках.')
        # Only directories and regular relative files were accepted above.
        source.extractall(destination)
    directories=list(destination.iterdir())
    if len(directories)!=1 or not directories[0].is_dir():raise RuntimeError('Неожиданный формат исходников.')
    return directories[0]

def run(*args,cwd=None,env=None):
    LOG.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(LOG,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    with os.fdopen(descriptor,'ab') as output:
        result=subprocess.run(args,cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError(f'Не выполнено: {args[0]} (код {result.returncode}). Подробности: {LOG}')

def write(path,text,mode=0o644,user='root',group='root'):
    import pwd,grp
    path=P(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.new')
    with open(temp,'w',encoding='utf-8') as file:
        file.write(text);file.flush();os.fsync(file.fileno())
    os.chown(temp,pwd.getpwnam(user).pw_uid,grp.getgrnam(group).gr_gid);temp.chmod(mode);temp.replace(path)

def json_write(path,value,**kwargs):write(path,json.dumps(value,ensure_ascii=False,indent=2)+'\n',**kwargs)

def directory(path,user='root',group='root',mode=0o755):
    import pwd,grp
    path=P(path);path.mkdir(parents=True,exist_ok=True);os.chown(path,pwd.getpwnam(user).pw_uid,grp.getgrnam(group).gr_gid);path.chmod(mode)

def public_ipv4():
    for url in ('https://api.ipify.org','https://icanhazip.com'):
        try:
            with urllib.request.urlopen(url,timeout=8) as response:value=response.read(128).decode().strip()
            if ipaddress.IPv4Address(value).is_global:return value
        except (OSError,ValueError):pass
    return ''

def check_dns(domain,address):
    try:
        records=socket.getaddrinfo(domain,443,type=socket.SOCK_STREAM)
    except socket.gaierror:raise RuntimeError('Домен пока не найден. Создай A-запись с IP сервера и дождись обновления DNS.') from None
    v4={item[4][0] for item in records if item[0]==socket.AF_INET}
    v6={item[4][0] for item in records if item[0]==socket.AF_INET6}
    if v4!={address}:raise RuntimeError('A-запись домена должна указывать только на IP этого VPS: '+address+'. Если используешь Cloudflare, выбери DNS only (серое облако). Сейчас: '+', '.join(sorted(v4)))
    if v6:raise RuntimeError('У домена есть AAAA-запись. Первая версия установщика работает через IPv4: убери AAAA у выбранного поддомена и повтори проверку.')


def check_tcp_port(port):
    for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
        try:
            with socket.socket(family,socket.SOCK_STREAM) as sock:
                # Closed connections in TIME_WAIT are not a running service.
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                sock.bind((address,port))
        except OSError as error:
            if error.errno in (97,99):continue
            raise RuntimeError(f'Порт {port} уже занят. Нужен чистый VPS; чужие службы не будут остановлены.') from None

def preflight(existing):
    if os.name!='posix' or os.geteuid()!=0:raise RuntimeError('Запусти в консоли VPS под root: сначала sudo -i, затем команду установки.')
    release=dict(line.split('=',1) for line in P('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID','').strip('"')!='ubuntu' or release.get('VERSION_ID','').strip('"')!='24.04':raise RuntimeError('Эта версия поддерживает только Ubuntu 24.04 LTS. Нужен отдельный чистый VPS.')
    if platform.machine()!='x86_64':raise RuntimeError('Нужен VPS amd64/x86_64. ARM пока не поддерживается.')
    if not P('/run/systemd/system').exists():raise RuntimeError('Нужен VPS с systemd; обычный Docker-контейнер не подходит.')
    if shutil.disk_usage('/').free<2*1024**3:raise RuntimeError('Для сборки нужно хотя бы 2 ГБ свободного места.')
    total=int(re.search(r'MemTotal:\s+(\d+)',P('/proc/meminfo').read_text()).group(1))
    if total<900000:raise RuntimeError('Нужно минимум 1 ГБ RAM; рекомендуется 2 ГБ.')
    if not existing:
        for path in ('/etc/caddy/Caddyfile','/etc/tproxy-server','/etc/mtproxy','/opt/MTProxy','/var/lib/relay-panel'):
            if P(path).exists():raise RuntimeError('Найдена существующая конфигурация '+path+'. Установщик предназначен для чистого VPS и не будет её перезаписывать.')
        for port in (80,443,2398,8888,8080,8081,8082):
            check_tcp_port(port)

def packages():
    print('Устанавливаю системные пакеты. Подробности: '+str(LOG))
    env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'}
    run('apt-get','update',env=env)
    run('apt-get','-o','Dpkg::Options::=--force-confold','install','-y','--no-install-recommends','ca-certificates','curl','build-essential','golang-go','libssl-dev','zlib1g-dev','nftables','iproute2','patch','caddy','python3-flask','python3-qrcode','python3-pil','gunicorn','python3-yaml','age','rclone',env=env)

def users():
    import pwd
    for name,home in [('relayadmin','/var/lib/relay-panel'),('tproxy','/nonexistent'),('mtproxy','/nonexistent'),('hysteria','/var/lib/hysteria')]:
        try:pwd.getpwnam(name)
        except KeyError:run('useradd','--system','--home-dir',home,'--shell','/usr/sbin/nologin',name)

def build(source,work):
    print('Собираю официальный релей и MTProxy. Это может занять несколько минут…')
    archive=work/'relay.tar.gz';download(f'https://codeload.github.com/telegramdesktop/tproxy-server/tar.gz/{RELAY_COMMIT}',archive,RELAY_SHA256)
    relay=extract(archive,work/'relay')
    run('patch','--batch','--forward','-p1','-i',str(source/'relay/accounting.patch'),cwd=relay)
    for name in ('accounting.go','accounting_test.go'):shutil.copyfile(source/'relay'/name,relay/'internal/session'/name)
    run('gofmt','-w','internal/session/accounting.go','internal/session/accounting_test.go','internal/session/manager.go','internal/session/session.go','internal/server/server.go',cwd=relay)
    run('go','test','./...',cwd=relay)
    run('go','build','-trimpath','-o',str(work/'tproxy-server'),'./cmd/tproxy-server',cwd=relay)
    archive=work/'mtproxy.tar.gz';download(f'https://codeload.github.com/TelegramMessenger/MTProxy/tar.gz/{MTPROXY_COMMIT}',archive,MTPROXY_SHA256)
    mtproxy=extract(archive,work/'mtproxy')
    run('make','-j2',cwd=mtproxy)
    run('/usr/bin/python3',str(source/'tests/test_panel.py'))
    return work/'tproxy-server',mtproxy

def install_files(source,options,work,candidate,mtproxy):
    directory(BASE);directory(BASE/'releases')
    release=BASE/'releases'/(VERSION+'-'+str(int(time.time())))
    shutil.copytree(source,release,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
    for folder,dirs,files in os.walk(release):
        P(folder).chmod(0o755)
        for name in files:(P(folder)/name).chmod(0o644)
    directory('/etc/relay-panel',mode=0o700)
    directory('/var/lib/relay-panel','relayadmin','relayadmin',0o700)
    directory('/var/lib/tproxy-accounting','tproxy','relayadmin',0o2750)
    directory('/etc/tproxy-server','root','tproxy',0o750)
    directory('/etc/mtproxy','root','mtproxy',0o750)
    directory('/srv/relay-site')
    if not P('/etc/relay-panel/users.json').exists():
        state={'host':options['domain'],'paused':False,'users':[{'id':'default','name':'Мой ключ','group':'Личное','secret':secrets.token_hex(16),'enabled':True,'created':int(time.time())}],'events':[]}
        json_write('/etc/relay-panel/users.json',state,mode=0o600)
    if not P('/var/lib/relay-panel/auth.json').exists():
        code=secrets.token_urlsafe(24)
        json_write('/var/lib/relay-panel/auth.json',{'host':options['domain'],'session_key':secrets.token_hex(32),'setup_hash':hashlib.sha256(code.encode()).hexdigest(),'setup_expires':int(time.time())+86400},mode=0o600,user='relayadmin',group='relayadmin')
        write('/etc/relay-panel/setup-code',code+'\n',mode=0o600)
    state=json.loads(P('/etc/relay-panel/users.json').read_text())
    active=[u for u in state['users'] if u['enabled'] and not state['paused']]
    profiles=[dict(name=u['id'],secret=u['secret'],backend='127.0.0.1:2398',carrier_mode='https') for u in active]
    if not profiles:profiles=[dict(name='suspended',secret=secrets.token_hex(16),backend='127.0.0.1:2398')]
    json_write('/etc/tproxy-server/profiles.json',{'profiles':profiles},mode=0o400,group='tproxy')
    json_write('/etc/mtproxy/managed-secrets.json',{'secrets':[p['secret'] for p in profiles]},mode=0o640,group='mtproxy')
    key=P('/etc/tproxy-server/token.key')
    if not key.exists():
        key.write_bytes(secrets.token_bytes(32));shutil.chown(key,'tproxy','tproxy');key.chmod(0o400)
    elif len(key.read_bytes())!=32:raise RuntimeError('Повреждён ключ релея. Он не будет перезаписан.')
    json_write('/etc/tproxy-server/config.json',dict(public_hostname=options['domain'],base_path='',listen='127.0.0.1:8080',admin_listen='127.0.0.1:8081',public_dir='/srv/relay-site',static_routes='exact',profiles_file='/run/credentials/tproxy-server.service/profiles.json'),mode=0o640,group='tproxy')
    write('/etc/tproxy-server/firewall.nft',FIREWALL)
    if not P('/srv/relay-site/index.html').exists():write('/srv/relay-site/index.html',render_site(options))
    for name,url in [('proxy-secret','https://core.telegram.org/getProxySecret'),('proxy-multi.conf','https://core.telegram.org/getProxyConfig')]:
        temp=work/name;download(url,temp)
        content=temp.read_bytes()
        if (name=='proxy-secret' and len(content)!=128) or (name=='proxy-multi.conf' and (b'default ' not in content or b'proxy_for ' not in content or len(content)<100)):
            raise RuntimeError('Telegram вернул неожиданный формат конфигурации.')
        shutil.copyfile(temp,P('/etc/mtproxy')/name);shutil.chown(P('/etc/mtproxy')/name,'root','mtproxy');(P('/etc/mtproxy')/name).chmod(0o640)
    route=json.loads(subprocess.check_output(['ip','-j','-4','route','get','149.154.175.50']))[0]
    local=route.get('prefsrc') or route.get('src')
    if not local:raise RuntimeError('Не удалось определить исходящий IPv4 сервера.')
    nat=f'--nat-info {ipaddress.IPv4Address(local)}:{options["ip"]}' if local!=options['ip'] else ''
    write('/etc/mtproxy/mtproxy.env',f'MTPROXY_WORKERS=1\nMTPROXY_MAX_CONNECTIONS=4096\nMTPROXY_NAT_ARGS="{nat}"\n',mode=0o640,group='mtproxy')
    # Both old binaries must be stopped before replacing their files/directories.
    for name in ('mtproxy','tproxy-server'):
        if P('/etc/systemd/system/'+name+'.service').exists():run('systemctl','stop',name)
    target=P('/opt/MTProxy')
    if target.exists():shutil.move(str(target),str(work/'previous-mtproxy'))
    shutil.copytree(mtproxy,target)
    for folder,dirs,files in os.walk(target):
        P(folder).chmod(0o755)
        for name in files:(P(folder)/name).chmod(0o644)
    (target/'objs/bin/mtproto-proxy').chmod(0o755)
    shutil.copyfile(candidate,'/usr/local/bin/tproxy-server.new');P('/usr/local/bin/tproxy-server.new').chmod(0o755);os.replace('/usr/local/bin/tproxy-server.new','/usr/local/bin/tproxy-server')
    current=BASE/'current';new=BASE/'next';new.unlink(missing_ok=True);new.symlink_to(release,target_is_directory=True);new.replace(current)
    for name,contents in units().items():write(P('/etc/systemd/system')/name,contents)
    write('/usr/local/sbin/relay-panel','#!/bin/sh\nexec /usr/bin/python3 /opt/relay-panel/current/manage.py "$@"\n',mode=0o755)
    from backup_install import install as install_backup
    from hysteria_install import install as install_hysteria,caddy as hy2_caddy
    install_backup(sys.modules[__name__])
    install_hysteria(sys.modules[__name__],options,work)
    write('/etc/caddy/Caddyfile',caddyfile(options['domain'],options['email'])+(hy2_caddy(options['hy2_domain']) if options.get('hy2_domain') else ''))
    run('caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile')
    run('/usr/local/bin/tproxy-server','-config','/etc/tproxy-server/config.json','-profiles-file','/etc/tproxy-server/profiles.json','-check')
    run('systemd-analyze','verify',*[str(P('/etc/systemd/system')/name) for name in units()])

def activate(standby=False):
    run('systemctl','daemon-reload')
    run('systemctl','enable','--now','tproxy-firewall')
    run('systemctl','enable','mtproxy','tproxy-server','relay-helper','relay-panel','relay-refresh.timer')
    run('systemctl','reset-failed','mtproxy','tproxy-server','relay-helper','relay-panel')
    run('systemctl','restart',*(['relay-helper','relay-panel'] if standby else ['mtproxy','tproxy-server','relay-helper','relay-panel']))
    if not standby:run('systemctl','start','relay-refresh.timer')
    run('systemctl','enable','--now','caddy')
    run('systemctl','restart','caddy')
    run('systemctl','enable','--now','relay-backup')
    from hysteria_install import activate as activate_hysteria
    activate_hysteria(sys.modules[__name__],json.loads(STATE.read_text()),standby=standby)

def health(domain,public=True):
    for _ in range(25):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8081/readyz',timeout=3) as result:assert result.status==200
            request=urllib.request.Request('http://127.0.0.1:8082/control/',headers={'Host':domain})
            with urllib.request.urlopen(request,timeout=3) as result:assert result.status==200
            break
        except (OSError,AssertionError):time.sleep(1)
    else:raise RuntimeError('Службы не стали готовы. Выполни relay-panel status; журнал: '+str(LOG))
    if public:
        print('Получаю HTTPS-сертификат и проверяю доступность сайта…')
        for _ in range(24):
            try:
                with urllib.request.urlopen('https://'+domain+'/control/',timeout=6) as result:
                    if result.status==200:return
            except OSError:pass
            time.sleep(2)
        raise RuntimeError('Службы запущены, но HTTPS пока недоступен. Проверь DNS и входящие TCP 80/443 у хостера. После исправления повтори установку → «Проверить». Ключи сохранены.')

def main():
    parser=argparse.ArgumentParser(description='Telegram WEB Proxy + панель: интерактивная установка')
    parser.add_argument('--source',type=P,default=P(__file__).resolve().parent)
    parser.add_argument('--revision',default='local')
    parser.add_argument('--recover',action='store_true',help='Открыть мастер восстановления из зашифрованной копии')
    args=parser.parse_args()
    os.umask(0o077)
    existing=json.loads(STATE.read_text()) if STATE.exists() else None
    from recovery_wizard import pending, run_wizard
    if args.recover or pending():
        run_wizard(args.source.resolve(),args.revision,setup=sys.modules[__name__]);return
    preflight(existing)
    sys.path.insert(0,str(P(__file__).parent/'panel'))
    from migration_state import blocked, mutation
    if blocked():raise RuntimeError('Сервер остановлен для переноса. Обновление не запустит службы. Сначала проверь relay-panel migration status; для возврата используй migration resume.')
    migration_guard=mutation()
    migration_guard.__enter__()
    import fcntl
    lock=open_install_lock()
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise RuntimeError('Другой установщик уже работает.') from None
    print('\nTelegram WEB Proxy + Relay Panel · '+VERSION+'\n')
    if existing:
        print('Найдена установка для '+existing['domain']+'. Ключи и пароль будут сохранены.')
        choice=ask('1 — проверить, 2 — резервная копия, 3 — обновить / продолжить установку, 0 — выход','1')
        if choice=='0':return
        from manage import backup,show_access
        if choice=='2':print('Резервная копия: '+str(backup()));return
        if choice=='1':
            health(existing['domain']);existing['phase']='complete';json_write(STATE,existing,mode=0o600);show_access();return
        if choice!='3':raise RuntimeError('Неизвестный пункт меню.')
        options=existing
    else:
        choice=ask('1 — новая установка, 2 — восстановить из резервной копии, 0 — выход','1')
        if choice=='0':return
        if choice=='2':
            migration_guard.__exit__(None,None,None)
            lock.close()
            run_wizard(args.source.resolve(),args.revision,setup=sys.modules[__name__]);return
        if choice!='1':raise RuntimeError('Неизвестный пункт меню.')
        domain=ask('Адрес прокси (например tg.example.com)',validate=domain_name)
        detected=public_ipv4()
        def valid_ip(value):
            if not ipaddress.IPv4Address(value).is_global:raise ValueError('Нужен публичный IPv4 этого VPS.')
            return value
        address=ask('Публичный IPv4 этого VPS',detected or None,valid_ip)
        print('Проверяю DNS…');check_dns(domain,address)
        title=ask('Название страницы','Свои люди')
        contact=ask('Telegram для кнопки связи (Enter — без кнопки)','')
        theme=ask('Тема страницы: 1 — тёмная пиксельная, 2 — нейтральная','1')
        if theme not in ('1','2'):raise RuntimeError('Выбери тему 1 или 2.')
        options=site_options(title,contact,'pixel' if theme=='1' else 'minimal')
        email=ask('Email для сертификата (необязательно)','')
        if email and not re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',email):raise RuntimeError('Некорректный email.')
        options.update(domain=domain,ip=address,email=email,phase='preparing')
        if ask('Установить также Hysteria 2? да / нет','да').lower() in ('да','yes','y'):
            hy2_domain=ask('Отдельный домен Hysteria (например hy2.example.com)',validate=domain_name)
            if hy2_domain==domain:raise RuntimeError('Для Hysteria нужен отдельный поддомен.')
            check_dns(hy2_domain,address)
            port=int(ask('UDP-порт Hysteria','24443'))
            if not 1024<=port<=65535:raise RuntimeError('Нужен UDP-порт от 1024 до 65535.')
            options.update(hy2_domain=hy2_domain,hy2_port=port)
    print('\nПрокси: '+options['domain']+'\nПанель: https://'+options['domain']+'/control/')
    print('Будут установлены MTProxy, релей, Caddy, панель и автозапуск. Настройка займёт несколько минут.')
    if ask('Начать? да / нет','нет').lower() not in ('да','yes','y'):print('Отменено.');return
    directory('/etc/relay-panel',mode=0o700);json_write(STATE,options,mode=0o600)
    packages();users()
    with tempfile.TemporaryDirectory(prefix='relay-panel-build-',dir='/var/tmp') as folder:
        work=P(folder);candidate,mtproxy=build(args.source.resolve(),work)
        # Keep the previous config, binary and source tree before any activation change.
        snapshot=None
        if existing:
            run('systemctl','stop','relay-panel','relay-helper')
            from manage import backup
            snapshot=backup(include_programs=True)
            print('Резервная копия: '+str(snapshot))
        try:
            install_files(args.source.resolve(),options,work,candidate,mtproxy)
            activate()
            health(options['domain'],public=False)
        except Exception:
            if snapshot:
                from manage import restore_internal
                restore_internal(snapshot)
                print('Предыдущая версия восстановлена.')
            else:
                subprocess.run(['systemctl','stop',*SERVICES],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            raise
    options.update(version=VERSION,revision=args.revision,phase='https-pending');json_write(STATE,options,mode=0o600)
    health(options['domain'])
    options['phase']='complete';json_write(STATE,options,mode=0o600)
    from manage import show_access
    print('\nГОТОВО. Прокси и панель установлены.\n');show_access()

if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError) as error:
        print('\nОШИБКА: '+str(error),file=sys.stderr);sys.exit(1)
    except KeyboardInterrupt:print('\nПрервано. Повтори ту же команду установки: сохранённые ключи и прогресс восстановления останутся на VPS.',file=sys.stderr);sys.exit(130)
