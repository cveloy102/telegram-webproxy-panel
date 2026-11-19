"""Optional СВАЛКА sync server (PocketBase) for the СВАЛКА reminder apps.

The layout matches the project's standalone installer (/opt/svalka-sync, service svalka-sync), so a server
that already runs СВАЛКА keeps its accounts and records when the panel takes it over.
"""
import json
import os
import secrets
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path
from units import HARDEN

VERSION='0.40.6'
SHA256='0e1f609158ed945f809f8a02ae012aa0427129c66ebb63c1aee76f2c0309373f'
ROOT=Path('/opt/svalka-sync')
DATA=ROOT/'pb_data'
PORT=8090
# Superuser the panel uses for its СВАЛКА page; readable only by the panel's own account.
CREDENTIALS=Path('/var/lib/relay-panel/svalka.json')
PANEL_ACCOUNT='panel@svalka.internal'


def suggested_domain(domain):
    labels=domain.split('.')
    return 'sync.'+'.'.join(labels[1:] if len(labels)>2 else labels)


def ask_options(setup,options):
    if options.get('svalka_domain'):return
    if setup.ask('Установить сервер синхронизации СВАЛКИ (дела и напоминания: телефон ↔ компьютер)? да / нет','нет',setup.yes_no)!='да':return
    taken={options.get('domain'),options.get('hy2_domain'),options.get('awg_domain')}
    def host(value):
        value=setup.domain_name(value)
        if value in taken:raise ValueError('Для СВАЛКИ нужен свой поддомен, например sync.example.com.')
        return value
    domain=setup.ask('Домен сервера СВАЛКИ (без https:// и пути)',suggested_domain(options['domain']),host)
    setup.check_dns(domain,options['ip'])
    options.update(svalka_domain=domain)


# PocketBase administration is never needed from the internet: the panel talks to it over 127.0.0.1 and the
# apps use only the users/items API. Closing these paths removes the admin UI and superuser sign-in from
# the public attack surface (they stay reachable locally, e.g. through an SSH tunnel).
ADMIN_PATHS=('/_','/_/*','/api/collections/_superusers/*','/api/settings','/api/settings/*','/api/logs','/api/logs/*',
             '/api/backups','/api/backups/*','/api/crons','/api/crons/*','/api/collections','/api/collections/import')


def caddy(domain):
    # No compression here: the apps keep a live event stream (text/event-stream) open.
    return '\n'+domain+''' {
 header -Via
 @admin path '''+' '.join(ADMIN_PATHS)+'''
 respond @admin 404
 reverse_proxy 127.0.0.1:'''+str(PORT)+'''
}
'''


# Brute-force protection. Caddy sets X-Forwarded-For to the real client address (it does not trust an
# incoming one), so PocketBase must read it to tell clients apart; the rightmost value is Caddy's.
# Only sign-in and self-registration are limited: a first sync may create hundreds of records quickly.
# The panel signs in over 127.0.0.1 on every page load, so local addresses are not limited.
SECURITY_SETTINGS={
    'trustedProxy':{'headers':['X-Forwarded-For'],'useLeftmostIP':False},
    'rateLimits':{'enabled':True,'excludedIPs':['127.0.0.1','::1'],'rules':[
        {'label':'*:auth','audience':'','duration':60,'maxRequests':10},
        {'label':'users:create','audience':'@guest','duration':300,'maxRequests':5},
    ]},
}


def local_api(method,path,body=None,token=None):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']=token
    data=None if body is None else json.dumps(body).encode()
    request=urllib.request.Request('http://127.0.0.1:'+str(PORT)+path,data=data,method=method,headers=headers)
    with urllib.request.urlopen(request,timeout=10) as response:
        raw=response.read()
        return json.loads(raw) if raw else {}


def secure_settings():
    """Apply SECURITY_SETTINGS through the panel's superuser. Settings live in the database, so this also
    runs after a restore brought an older one. A failure is reported but does not stop the server."""
    try:
        value=json.loads(CREDENTIALS.read_text())
        token=local_api('POST','/api/collections/_superusers/auth-with-password',{'identity':value['email'],'password':value['password']})['token']
        local_api('PATCH','/api/settings',SECURITY_SETTINGS,token)
    except (OSError,ValueError,KeyError) as error:
        print('Внимание: не удалось включить защиту от перебора паролей СВАЛКИ ('+type(error).__name__+'). Сервер работает; повтори обновление позже.')
        return False
    return True


def service():
    return f'''[Unit]
Description=СВАЛКА sync server (PocketBase)
After=network-online.target
Wants=network-online.target
[Service]
User=svalka
Group=svalka
WorkingDirectory={ROOT}
Environment=SVALKA_ALLOW_SIGNUP=false
# Optional local settings of a standalone installation (TZ, for example) keep working.
EnvironmentFile=-{ROOT}/.env
ExecStart={ROOT}/pocketbase serve --http=127.0.0.1:{PORT} --dir={DATA} --migrationsDir={ROOT}/pb_migrations --hooksDir={ROOT}/pb_hooks
Restart=always
RestartSec=3
UMask=0077
{HARDEN}ReadWritePaths={DATA}
IPAddressDeny=any
IPAddressAllow=localhost
MemoryMax=256M
TasksMax=64
[Install]
WantedBy=multi-user.target
'''


def install(setup,options,work,source):
    if not options.get('svalka_domain'):return
    import pwd
    try:pwd.getpwnam('svalka')
    except KeyError:setup.run('useradd','--system','--home-dir',str(ROOT),'--shell','/usr/sbin/nologin','svalka')
    setup.directory(ROOT,mode=0o755)
    if DATA.exists():
        # Adopted from the standalone installer: keep the data, only make sure of its owner.
        for path in [DATA,*DATA.rglob('*')]:
            if not path.is_symlink():shutil.chown(path,'svalka','svalka')
        DATA.chmod(0o700)
    else:setup.directory(DATA,'svalka','svalka',0o700)
    for folder in ('pb_hooks','pb_migrations'):
        target=ROOT/folder;setup.directory(target,mode=0o755)
        for item in sorted((Path(source)/'svalka'/folder).glob('*.js')):setup.write(target/item.name,item.read_text(encoding='utf-8'))
    archive=work/'pocketbase.zip'
    setup.download('https://github.com/pocketbase/pocketbase/releases/download/v'+VERSION+'/pocketbase_'+VERSION+'_linux_amd64.zip',archive,SHA256)
    with zipfile.ZipFile(archive) as bundle:binary=bundle.read('pocketbase')
    pending=ROOT/'pocketbase.new';pending.write_bytes(binary);pending.chmod(0o755)
    # Replace by rename; a running old process keeps its inode until restart.
    os.replace(pending,ROOT/'pocketbase')
    setup.write('/etc/systemd/system/svalka-sync.service',service())
    value=json.loads(CREDENTIALS.read_text()) if CREDENTIALS.exists() else {'email':PANEL_ACCOUNT,'password':secrets.token_urlsafe(24)}
    value['domain']=options['svalka_domain']
    setup.json_write(CREDENTIALS,value,mode=0o600,user='relayadmin',group='relayadmin')


def upsert_panel_account(setup):
    """The panel's own superuser; called after install and after a restore brought another database."""
    value=json.loads(CREDENTIALS.read_text())
    setup.run('runuser','-u','svalka','--',str(ROOT/'pocketbase'),'superuser','upsert',value['email'],value['password'],'--dir='+str(DATA))


def wait_ready(timeout=60):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:'+str(PORT)+'/api/svalka/info',timeout=3) as response:
                if json.load(response).get('app')=='svalka-sync':return
        except (OSError,ValueError):pass
        time.sleep(1)
    raise RuntimeError('Сервер СВАЛКИ не запустился. Журнал: journalctl -u svalka-sync')


def activate(setup,options,standby=False):
    if not options.get('svalka_domain'):return
    setup.run('systemctl','enable','svalka-sync')
    # It serves no one until DNS points here, so it runs in standby too; a restore stops it first.
    setup.run('systemctl','restart','svalka-sync')
    wait_ready()
    upsert_panel_account(setup)
    secure_settings()
