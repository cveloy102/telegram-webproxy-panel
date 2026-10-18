"""Resumable recovery on a fresh VPS. Private identities are never checkpointed."""
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import urllib.request

ROOT=Path('/var/lib/relay-recovery')
STEPS=(('archive','Архив проверен и расшифрован'),
       ('installed','Компоненты установлены, подключения выключены'),
       ('imported','Пользователи, ключи и вход владельца восстановлены'),
       ('dns','Домены указывают на новый VPS'),
       ('https','HTTPS и сертификаты проверены'),
       ('complete','Службы включены и проверены'))


def read_state(root=ROOT):
    path=Path(root)/'state.json'
    if not path.exists():return None
    data=json.loads(path.read_text())
    if data.get('schema')!=1:raise RuntimeError('Неизвестный формат прогресса восстановления. Данные не изменены.')
    return data


def pending(root=ROOT):
    data=read_state(root)
    return bool(data and not data.get('complete'))


def save(data,root=ROOT):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
    temp=root/'state.new'
    with temp.open('w',encoding='utf-8') as output:
        json.dump(data,output,ensure_ascii=False,indent=2)
        output.flush();os.fsync(output.fileno())
    temp.chmod(0o600);temp.replace(root/'state.json')


def digest(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):result.update(block)
    return result.hexdigest()


def options_from_manifest(manifest,address):
    from installer import domain_name
    if not ipaddress.IPv4Address(address).is_global:raise ValueError('Нужен публичный IPv4 нового VPS.')
    options={'domain':domain_name(manifest['telegram_domain']),'ip':address,'email':'',
             'title':'Свои люди','contact':'','theme':'pixel','phase':'recovery'}
    if manifest['hysteria']:
        host=domain_name(manifest['hysteria_domain']);port=manifest['hysteria_port']
        if host==options['domain'] or type(port) is not int or not 1024<=port<=65535:
            raise ValueError('Некорректный домен или UDP-порт Hysteria в архиве.')
        options.update(hy2_domain=host,hy2_port=port)
    if manifest.get('amnezia'):
        host=domain_name(manifest['amnezia_domain']);port=manifest['amnezia_port']
        if type(port) is not int or not 1024<=port<=65535 or port==options.get('hy2_port'):raise ValueError('Некорректный UDP-порт AmneziaWG в архиве')
        options.update(awg_domain=host,awg_port=port)
    # Validate redirect domains before any system configuration is installed.
    from restore import merge_redirects
    merge_redirects('',manifest.get('redirects',[]),options['domain'])
    return options


def domains(data):
    values=[data['options']['domain']]
    if data['options'].get('hy2_domain'):values.append(data['options']['hy2_domain'])
    if data['options'].get('awg_domain'):values.append(data['options']['awg_domain'])
    values.extend(item['host'] for item in data.get('redirects',[]))
    return list(dict.fromkeys(values))


def dashboard(data):
    print('\nМастер восстановления — прогресс сохранён на этом VPS')
    for key,label in STEPS:print(mark('✓' if data.get(key) else '○',label))


def mark(symbol,label):
    if sys.stdout.isatty() and 'NO_COLOR' not in os.environ:
        color='32' if symbol=='✓' else '33' if symbol=='⏳' else '90'
        return '\033['+color+'m'+symbol+'\033[0m '+label
    return symbol+' '+label


def wait_check(label,check,interval=10,sleep=time.sleep):
    """No timeout masquerades as success; Ctrl+C leaves the checkpoint intact."""
    previous=None
    while True:
        try:
            check()
            print(mark('✓',label),flush=True)
            return
        except (OSError,RuntimeError,ValueError) as error:
            message=str(error)
            if message!=previous:
                print(mark('⏳',label+': '+message),flush=True);previous=message
            print('  Проверю снова через '+str(interval)+' с. Ctrl+C — выйти и продолжить позже.',flush=True)
            sleep(interval)


def check_https(domain,panel=False):
    # Normal CA and hostname validation, with no insecure fallback.
    try:
        with urllib.request.urlopen('https://'+domain+('/control/' if panel else '/'),timeout=8) as response:
            if response.status!=200:raise RuntimeError('HTTPS пока не готов. Проверь входящие TCP 80/443 у хостера.')
    except OSError as error:
        raise RuntimeError('HTTPS или сертификат пока не готовы. Проверь DNS и входящие TCP 80/443 у хостера. '+str(error)) from None


def backup_api(payload):
    from backup_routes import helper
    return helper(payload)


def inspect_archive(archive,identity):
    from backup_archive import decrypt
    # Decrypted databases and the short-lived copy of the identity stay in tmpfs.
    with tempfile.TemporaryDirectory(prefix='relay-wizard-check-',dir='/run') as temp:
        manifest=decrypt(archive,Path(identity).read_text(),Path(temp))
        files=Path(temp)/'files'
        users=json.loads((files/'telegram/users.json').read_text())
        import sqlite3
        counts={'telegram':len(users['users']),'hysteria':0}
        counts['amnezia']=0
        if (files/'amnezia/awg.sqlite3').exists():
            with contextlib.closing(sqlite3.connect(files/'amnezia/awg.sqlite3')) as db:counts['amnezia']=db.execute('SELECT count(*) FROM users').fetchone()[0]
        database=files/'hysteria/hy2.sqlite3'
        if database.exists():
            with contextlib.closing(sqlite3.connect(database)) as db:
                counts['hysteria']=db.execute('SELECT count(*) FROM users').fetchone()[0]
        return manifest,counts


def choose_file(setup,prompt,patterns,limit,*,folder=Path('/root')):
    """Offer local filenames without exposing archive or identity contents."""
    candidates=sorted({path for pattern in patterns for path in folder.glob(pattern) if path.is_file()})
    if candidates:
        print('\nНайдены файлы на новом VPS:')
        for number,path in enumerate(candidates,1):print('  '+str(number)+' — '+str(path))
        print('Введи номер файла или полный путь. Enter выбирает файл в квадратных скобках.')
    else:
        print('\nФайлы в '+str(folder)+' пока не найдены. Загрузи их через WinSCP/SFTP и введи полный путь.')
    def valid(value):
        value=value.strip()
        if value.isdecimal():
            number=int(value)
            if not 1<=number<=len(candidates):raise ValueError('Нет такого номера. Выбери номер из списка или введи полный путь к файлу.')
            path=candidates[number-1]
        else:
            if len(value)>=2 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
            path=Path(value).expanduser()
        if not path.is_file():raise ValueError('Файл не найден на новом VPS. Проверь папку и настоящее имя, включая расширение .txt у ключа, которое Windows может скрывать.')
        if not 0<path.stat().st_size<=limit:raise ValueError('Файл пуст или слишком большой для этого шага.')
        return path
    default=str(candidates[0]) if len(candidates)==1 else None
    return setup.ask(prompt,default,validate=valid)


def identity_file(setup):
    print('\nНужен сохранённый приватный ключ age: relay-recovery-key.txt (или relay-recovery-key без расширения). Это не SSH-ключ; содержимое в чат не отправляй.')
    return choose_file(setup,'Путь к сохранённому relay-recovery-key.txt или номер файла',
                       ('relay-recovery-key.txt','relay-recovery-key'),16384)


def prepare(source,revision,data,setup,root=ROOT):
    """Install known programs without ever publishing temporary client profiles."""
    from migration_state import ROOT as migration_root
    setup.directory('/etc/relay-panel',mode=0o700)
    options={**data['options'],'recovery_session':data['session']}
    setup.json_write(setup.STATE,options,mode=0o600)
    # Set the persistent boot gate before installing/enabling any project unit.
    migration_root.mkdir(parents=True,exist_ok=True)
    (migration_root/'blocked').touch(mode=0o640)
    setup.json_write(migration_root/'state.json',{'phase':'standby','error':'','step':'Мастер восстанавливает данные','previous':{}},mode=0o640)
    print('\nСейчас устанавливаю компоненты. DNS пока менять не нужно — мастер отдельно покажет записи после восстановления данных.')
    setup.packages();setup.users()
    setup.directory(migration_root,'root','relayadmin',0o750)
    setup.json_write(migration_root/'state.json',{'phase':'standby','error':'','step':'Мастер восстанавливает данные','previous':{}},mode=0o640,group='relayadmin')
    with tempfile.TemporaryDirectory(prefix='relay-recovery-build-',dir='/var/tmp') as temp:
        work=Path(temp);candidate,mtproxy=setup.build(source,work)
        setup.install_files(source,options,work,candidate,mtproxy)
        setup.activate(standby=True)
    options.update(version=setup.VERSION,revision=revision,phase='recovery')
    setup.json_write(setup.STATE,options,mode=0o600)
    data['installed']=True;save(data,root)


def enable_services(data,setup,root=ROOT):
    state=backup_api({'op':'migration_status'})
    if state['phase']!='running' or state['busy']:
        print('\nПеред включением останови старую панель через «Перенос», либо выключи старый VPS у хостера.')
        print('Недоступность старого сайта сама по себе не доказывает, что он выключен.')
        if setup.ask('Старый сервер выключен или его Telegram/Hysteria/AmneziaWG остановлены? да / нет','нет').lower() not in ('да','yes','y'):
            print('Оставляю новый VPS в режиме ожидания. Повтори команду установки, когда будешь готов.');return False
        # Recheck after human confirmation: DNS may have changed while waiting.
        for domain in domains(data):
            setup.check_dns(domain,data['options']['ip'])
            if domain!=data['options'].get('awg_domain') or domain==data['options']['domain'] or domain==data['options'].get('hy2_domain'):
                check_https(domain,panel=domain==data['options']['domain'])
        if not state['busy']:backup_api({'op':'migration_resume','confirm':data['options']['domain']})
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            state=backup_api({'op':'migration_status'})
            if not state['busy']:break
            time.sleep(1)
        else:raise RuntimeError('Включение ещё выполняется. Повтори установку для проверки состояния.')
        if state['phase']!='running':raise RuntimeError(state.get('error') or 'Службы пока не готовы. Проверь DNS, TCP 80/443 и UDP-порт Hysteria; затем повтори установку.')
    setup.health(data['options']['domain'],public=False)
    if data['options'].get('hy2_domain'):
        from hy2_routes import helper
        helper({'op':'migration_ready'})
    if data['options'].get('awg_domain'):
        from awg_routes import helper
        helper({'op':'migration_ready'})
    data['complete']=True;save(data,root)
    current=json.loads(setup.STATE.read_text());current['phase']='complete'
    setup.json_write(setup.STATE,current,mode=0o600)
    return True


def run_wizard(source,revision,*,setup=None,root=ROOT):
    if setup is None:import installer as setup
    if os.name!='posix' or os.geteuid()!=0:raise RuntimeError('Мастер запускается на новом VPS под root.')
    sys.path.insert(0,str(Path(source)/'panel'))
    os.umask(0o077)
    import fcntl
    with setup.open_install_lock() as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Другой установщик уже работает.') from None
        data=read_state(root)
        identity=None
        if data and data.get('complete'):
            dashboard(data);print('Восстановление уже завершено. Панель: https://'+data['options']['domain']+'/control/');return
        existing=json.loads(setup.STATE.read_text()) if setup.STATE.exists() else None
        if existing and (not data or existing.get('recovery_session')!=data['session']):
            raise RuntimeError('На VPS уже есть другая установка. Мастер предназначен для нового сервера; существующие данные не изменены. Для осознанной замены есть relay-panel restore.')
        setup.preflight(existing)
        if data:
            print('Найдено незавершённое восстановление. Продолжаю с сохранённого шага.')
            if digest(Path(root)/'archive.tar.gz.age')!=data['sha256']:raise RuntimeError('Сохранённый архив изменился. Восстановление остановлено.')
        else:
            print('\nПОДГОТОВЬ КОПИЮ\nЕсли старая панель доступна: «Перенос» → «Остановить и создать финальную копию». Дождись подтверждения Google Диска.')
            print('Если старый VPS потерян — скачай последнюю успешную .tar.gz.age с Диска.')
            print('\nЗАГРУЗИ ДВА ФАЙЛА В /root/ НОВОГО VPS\n1. Архив .tar.gz.age с Google Диска. Распаковывать его не нужно.\n2. Сохранённый relay-recovery-key.txt. Без него архив не восстановить.')
            print('В WinSCP выбери SFTP, IP нового VPS, порт SSH (обычно 22), пользователя root и пароль или SSH-ключ.\nСправа открой /root/ и перетащи туда оба файла с компьютера. Консоль установщика закрывать не нужно.')
            print('Здесь указывается путь на новом VPS, например /root/relay-backup.tar.gz.age, а не путь на компьютере.\nПорядок: файлы → восстановление → смена DNS → проверка HTTPS → включение подключений. DNS пока не меняй.')
            archive=choose_file(setup,'Путь к архиву .tar.gz.age или номер файла',('*.tar.gz.age',),600*1024*1024)
            identity=identity_file(setup)
            if not shutil.which('age'):
                setup.run('apt-get','update');setup.run('apt-get','install','-y','--no-install-recommends','age')
            original_digest=digest(archive)
            manifest,counts=inspect_archive(archive,identity)
            def address(value):
                if not ipaddress.IPv4Address(value).is_global:raise ValueError('Нужен публичный IPv4 нового VPS.')
                return value
            print('\nНужен IP нового VPS из кабинета хостинга. Адрес в квадратных скобках определён автоматически.\nЕсли он правильный — просто нажми Enter. Если другой — введи правильный IPv4 и нажми Enter.\nНе указывай IP старого сервера или домашнего интернета.')
            ip=setup.ask('Публичный IPv4 НОВОГО VPS',setup.public_ipv4() or None,address)
            options=options_from_manifest(manifest,ip)
            created=dt.datetime.fromtimestamp(manifest['created'],dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
            print('Копия: '+created+'\nTelegram: '+options['domain']+' — профилей: '+str(counts['telegram']))
            if options.get('hy2_domain'):print('Hysteria: '+options['hy2_domain']+' / UDP '+str(options['hy2_port'])+' — профилей: '+str(counts['hysteria']))
            if options.get('awg_domain'):print('AmneziaWG: '+options['awg_domain']+' / UDP '+str(options['awg_port'])+' — профилей: '+str(counts['amnezia']))
            print('Вернутся прежние пароль и 2FA владельца. Клиентские подключения останутся выключены до отдельного подтверждения.')
            if setup.ask('Восстановить эту копию на этом новом VPS? да / нет','нет').lower() not in ('да','yes','y'):return
            root=Path(root);root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
            staged=root/'archive.pending';shutil.copyfile(archive,staged);staged.chmod(0o600);staged.replace(root/'archive.tar.gz.age')
            if digest(root/'archive.tar.gz.age')!=original_digest:raise RuntimeError('Архив изменился во время проверки. Повтори восстановление.')
            data={'schema':1,'session':secrets.token_hex(16),'archive':True,'sha256':digest(root/'archive.tar.gz.age'),
                  'options':options,'created':manifest['created'],'counts':counts,'redirects':manifest.get('redirects',[])}
            save(data,root)
        dashboard(data)
        if not data.get('imported'):
            if identity is None:identity=identity_file(setup)
            # Validate the identity again before packages/build or replacement on resume.
            inspect_archive(Path(root)/'archive.tar.gz.age',identity)
            if not data.get('installed'):prepare(source,revision,data,setup,root)
            from restore import restore_main
            restore_main([str(Path(root)/'archive.tar.gz.age'),'--identity',str(identity),'--standby'],confirmed=True)
            data['imported']=True;save(data,root);dashboard(data)
        print('\nТЕПЕРЬ ПЕРЕКЛЮЧИ DNS\nВ панели управления доменом замени старый IP в A-записях на '+data['options']['ip']+'. Имена доменов оставь прежними. Удали AAAA у этих имён; эта версия использует IPv4. В Cloudflare выбери DNS only (серое облако).')
        for domain in domains(data):print('  A  '+domain+' → '+data['options']['ip'])
        print('Открой у хостера входящие TCP 80/443'+''.join(' и UDP '+str(data['options'][k]) for k in ('hy2_port','awg_port') if k in data['options'])+'.')
        print('Мастер дождётся обновления DNS и проверит HTTPS. Начинать установку заново не нужно.\nЕсли DNS уже переключён, проверка пройдёт автоматически. Кэши у клиентов могут обновиться позже.')
        # Never trust an old green checkpoint for an external, changeable condition.
        data['dns']=False;data['https']=False;save(data,root)
        for domain in domains(data):
            wait_check('DNS '+domain,lambda domain=domain:setup.check_dns(domain,data['options']['ip']))
        data['dns']=True;save(data,root)
        for domain in domains(data):
            if domain==data['options'].get('awg_domain') and domain not in (data['options']['domain'],data['options'].get('hy2_domain')):continue
            wait_check('HTTPS '+domain,lambda domain=domain:check_https(domain,panel=domain==data['options']['domain']))
        data['https']=True;save(data,root);dashboard(data)
        if enable_services(data,setup,root):
            dashboard(data)
            print('\nГОТОВО. Панель: https://'+data['options']['domain']+'/control/\nВойди с прежними паролем и 2FA. Клиентам с доменами перевыдавать ключи не нужно; старый IP в профилях потребуется заменить.')
            print('Ключ восстановления мастер не сохранял. Когда убедишься в результате, удали переданный файл ключа с VPS; свою внешнюю копию сохрани.')


if __name__=='__main__':
    raise SystemExit('Запусти обычную команду установки и выбери восстановление либо добавь --recover.')
