"""Explicit, portable disaster recovery into an already installed fresh VPS."""
import argparse
import contextlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

def merge_redirects(config,redirects,target):
    from installer import domain_name
    target=domain_name(target)
    if not isinstance(redirects,list) or len(redirects)>20:raise ValueError('Некорректные перенаправления в копии.')
    for entry in redirects:
        host=domain_name(entry['host']);code=entry['code']
        if host==target or code not in ('permanent','temporary','301','302','307','308'):raise ValueError('Некорректное перенаправление.')
        block=host+' {\n redir https://'+target+'{uri} '+code+'\n}\n'
        pattern=r'(?m)^'+re.escape(host)+r'\s*\{\s*redir\s+https://'+re.escape(target)+r'\{uri\}\s+(?:permanent|temporary|301|302|307|308)\s*\}\s*'
        if re.search(pattern,config):config=re.sub(pattern,lambda m:block,config)
        elif re.search(r'(?m)^'+re.escape(host)+r'\s*\{',config):raise ValueError('Домен перенаправления уже используется другой настройкой Caddy: '+host)
        else:config+='\n'+block
    return config

def restore_files(files,paths):
    """Only logical data files are copied, never programs or executable config."""
    mappings=[('telegram/users.json',paths['users'],'root','root',0o600),('telegram/usage.json',paths['usage'],'tproxy','relayadmin',0o640),('owner/auth.json',paths['owner']/'auth.json','relayadmin','relayadmin',0o600),('owner/panel.sqlite3',paths['owner']/'panel.sqlite3','relayadmin','relayadmin',0o600),('hysteria/hy2.sqlite3',paths['hy2']/'hy2.sqlite3','root','root',0o600)]
    for name,target,user,group,mode in mappings:
        source=files/name
        if not source.exists():continue
        target.parent.mkdir(parents=True,exist_ok=True)
        for suffix in ('-wal','-shm','-journal'):
            if target.name.endswith('.sqlite3'):Path(str(target)+suffix).unlink(missing_ok=True)
        pending=target.with_name(target.name+'.restore');shutil.copyfile(source,pending);shutil.chown(pending,user,group);pending.chmod(mode);pending.replace(target)
    for name,target in [('site',paths['site']),('hysteria/cover',paths['hy2cover'])]:
        source=files/name
        if source.exists():
            if target.exists():shutil.rmtree(target)
            shutil.copytree(source,target)
            for p in [target,*target.rglob('*')]:
                p.chmod(0o755 if p.is_dir() else 0o644)
                if name.startswith('hysteria'):shutil.chown(p,'hysteria','hysteria')

def main(argv=None):
    if os.geteuid()!=0:raise ValueError('Восстановление запускается от root.')
    parser=argparse.ArgumentParser(description='Восстановить зашифрованную копию Relay Panel')
    parser.add_argument('archive',type=Path);parser.add_argument('--identity',type=Path,required=True);parser.add_argument('--inspect',action='store_true');args=parser.parse_args(argv)
    sys.path.insert(0,str(Path(__file__).parent/'panel'))
    from backup_archive import decrypt,layout
    from installer import domain_name
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='relay-restore-',dir='/run') as tmp:
        temp=Path(tmp);manifest=decrypt(args.archive,args.identity.read_text(),temp)
        domain=domain_name(manifest['telegram_domain']);hy2=domain_name(manifest['hysteria_domain']) if manifest['hysteria'] else None
        redirects=manifest.get('redirects',[])
        caddy=Path('/etc/caddy/Caddyfile')
        restored_caddy=merge_redirects(caddy.read_text(),redirects,domain)
        print('Дата копии (Unix):',manifest['created']);print('Telegram:',domain);print('Hysteria:',hy2 or 'нет')
        if args.inspect:print('Копия расшифрована, манифест и базы проверены. Данные сервера не изменены.');return
        current=json.loads(Path('/etc/relay-panel/install.json').read_text())
        if current['domain']!=domain or hy2 and current.get('hy2_domain')!=hy2:raise ValueError('Установи панель с прежними доменами из копии. Новые IP допустимы, домены должны совпадать.')
        if input('Будут заменены все ключи, история и вход владельца. Введи ВОССТАНОВИТЬ: ').strip()!='ВОССТАНОВИТЬ':print('Отменено.');return
        import manage
        services=['relay-backup','relay-panel','relay-helper','relay-hy2','hysteria-server','tproxy-server','mtproxy']
        subprocess.run(['systemctl','stop',*services],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        before=manage.backup(include_programs=True);print('Копия состояния до восстановления:',before)
        try:
            paths=layout();restore_files(temp/'files',paths)
            if redirects:
                pending=caddy.with_suffix('.restore');pending.write_text(restored_caddy);pending.chmod(0o644)
                try:
                    subprocess.run(['caddy','validate','--adapter','caddyfile','--config',str(pending)],check=True,capture_output=True)
                    pending.replace(caddy);subprocess.run(['systemctl','reload','caddy'],check=True)
                finally:pending.unlink(missing_ok=True)
            from helper import Controller
            controller=Controller();controller.apply(controller.read())
            if hy2:
                from hy2_control import Controller as Hysteria
                controller=Hysteria()
                with controller.db() as c:
                    c.execute('DELETE FROM samples');c.execute("UPDATE settings SET v=? WHERE k='epoch'",(json.dumps(''),))
                    settings=controller.settings(c)
                controller.apply_settings(settings)
                current['hy2_port']=settings['port']
                Path('/etc/relay-panel/install.json').write_text(json.dumps(current))
            backup_source=temp/'files/backup';target=Path('/var/lib/relay-backup')
            target.mkdir(mode=0o700,exist_ok=True)
            for name in ('config.json','rclone.conf'):
                source=backup_source/name
                if source.exists():shutil.copyfile(source,target/name);(target/name).chmod(0o600)
            # State is fresh: force an off-site snapshot of the restored data after restart.
            (target/'state.json').unlink(missing_ok=True)
            subprocess.run(['systemctl','restart','relay-helper','relay-panel','relay-backup'],check=True)
            if hy2:subprocess.run(['systemctl','restart','relay-hy2','hysteria-server'],check=True)
            from installer import health
            health(current['domain'],public=False)
            from backup_routes import helper as backup_ready
            from hy2_routes import helper as hy2_ready
            for attempt in range(30):
                try:
                    backup_ready({'op':'status'})
                    if hy2:hy2_ready({'op':'status'});controller.stats_api('online')
                    break
                except (OSError,ValueError):time.sleep(1)
            else:raise ValueError('Службы управления не стали готовы после восстановления.')
            print('Готово. Используй прежние пароль, 2FA и ключи. Проверь DNS обоих доменов и доступность UDP-порта',current.get('hy2_port','—'))
        except Exception:
            manage.restore_internal(before)
            raise ValueError('Восстановление не завершено. Предыдущее состояние возвращено; проверь службы через relay-panel status.') from None

if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:print('Ошибка:',error,file=sys.stderr);sys.exit(1)
