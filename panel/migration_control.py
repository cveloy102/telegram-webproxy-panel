"""Fixed, reversible service operations, executed by the root backup worker."""
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from migration_state import ROOT, boot_id

SERVICES = ('relay-refresh.timer', 'relay-refresh.service', 'relay-awg', 'amneziawg-server', 'hysteria-server',
            'relay-hy2', 'tproxy-server', 'mtproxy')


class Migration:
    def __init__(self, backup, root=ROOT, group='relayadmin'):
        self.backup = backup
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o750)
        if os.name == 'posix' and group:
            import grp
            self.gid = grp.getgrnam(group).gr_gid
            os.chown(self.root, 0, self.gid)
        else:
            self.gid = None
        self.lock = threading.Lock()
        self.busy = False
        self.data = json.loads((self.root/'state.json').read_text()) if (self.root/'state.json').exists() else {'phase':'running','error':'','file':'','uploaded':0}
        self.write('mutations.lock', b'', 0o640, replace=False)
        if self.data['phase'] in ('freezing', 'resuming'):
            self.data.update(phase='error', error='Операция прервана перезапуском. Повтори остановку или возобнови работу.')
            self.write('blocked', b'')
            self.save()
            for name in SERVICES:
                try:self.systemctl('stop', name, check=False)
                except (OSError,subprocess.SubprocessError):pass

    def write(self, name, content, mode=0o640, replace=True):
        target = self.root/name
        if not replace and target.exists():
            return
        pending = target.with_name(target.name+'.new')
        with pending.open('wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        pending.chmod(mode)
        if self.gid is not None:
            os.chown(pending, 0, self.gid)
        pending.replace(target)

    def save(self):
        self.write('state.json', json.dumps(self.data, ensure_ascii=False).encode())

    def status(self):
        with self.lock:
            return {**self.data, 'busy':self.busy, 'services':list(SERVICES),
                    'backup':self.backup.status()}

    def systemctl(self, *args, check=True):
        return subprocess.run(['systemctl', *args], check=check, capture_output=True, text=True, timeout=90)

    def inventory(self):
        result = {}
        for name in SERVICES:
            load = self.systemctl('show', name, '-p', 'LoadState', '--value', check=False)
            if load.returncode:raise ValueError('Не удалось проверить службы systemd.')
            if load.stdout.strip() in ('', 'not-found'):
                continue
            result[name] = self.systemctl('is-active', name, check=False).returncode == 0
        return result

    def call(self, op, confirm):
        import fcntl
        host = json.loads(self.backup.paths['users'].read_text())['host']
        if confirm != host:
            raise ValueError('Для подтверждения введи домен сервера: '+host)
        if op not in ('stop', 'resume'):
            raise ValueError('Неизвестная операция переноса.')
        with self.lock, self.backup.lock:
            if self.busy:
                raise ValueError('Дождись завершения текущей операции переноса.')
            if self.backup.running:
                raise ValueError('Дождись завершения текущей резервной копии.')
            if op == 'stop' and not self.backup.ready():
                raise ValueError('Сначала настрой Google Диск и ключ шифрования в разделе «Копии».')
            if op == 'resume' and self.data['phase'] == 'running':
                raise ValueError('Сервер уже работает.')
            if op == 'stop' and self.data['phase'] == 'stopped':
                raise ValueError('Сервер уже остановлен; финальная копия сохранена.')
            guard=(self.root/'mutations.lock').open('rb')
            try:
                fcntl.flock(guard,fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                guard.close()
                raise ValueError('Другой запрос или обновление ещё выполняется. Повтори через несколько секунд.') from None
            # Persist the gate BEFORE returning an asynchronous acknowledgement.
            try:
                if op=='stop' and 'previous' not in self.data:
                    self.data['previous']=self.inventory()
                self.data.update(phase='freezing' if op == 'stop' else 'resuming', error='', step='Изменения закрыты')
                self.data['boot_id']=boot_id()
                self.save()
                self.write('blocked', b'')
                self.busy = True
            except Exception:
                guard.close()
                raise
        threading.Thread(target=self.work, args=(op,guard), daemon=True).start()
        return self.status()

    def step(self, text):
        with self.lock:
            self.data['step'] = text
            self.save()

    def work(self, op, guard):
        try:
            with guard:
                if op == 'stop':
                    self.stop()
                else:
                    self.resume()
        except Exception as error:
            self.write('blocked', b'')
            # Stop any services that may have started during a partial resume.
            if op == 'resume':
                for name in self.data.get('previous',{}):
                    try:self.systemctl('stop', name, check=False)
                    except (OSError,subprocess.SubprocessError):pass
            with self.lock:
                self.data.update(phase='error', error=str(error) if isinstance(error, ValueError) else 'Операция не завершена. Проверь службы через relay-panel status; повтори остановку или возобновление.', step='Требуется действие')
                self.save()
        finally:
            with self.lock:
                self.busy = False

    def stop(self):
        self.step('Остановка прокси, VPN и фоновых задач')
        if 'previous' not in self.data:
            self.data['previous'] = self.inventory()
            self.save()
        # Last available Hysteria sample before its statistics endpoint disappears.
        if self.data['previous'].get('hysteria-server'):
            from hy2_routes import helper
            try:
                helper({'op':'migration_sample'})
            except (OSError, ValueError):
                self.data['warning'] = 'Последний опрос Hysteria недоступен; сохранён ранее учтённый трафик.'
        if self.data['previous'].get('amneziawg-server'):
            from awg_routes import helper
            try:helper({'op':'migration_sample'})
            except (OSError,ValueError):self.data['warning']='Последний опрос AmneziaWG недоступен; сохранён ранее учтённый трафик.'
        for name in self.data['previous']:
            self.systemctl('stop', name)
        active = [name for name in self.data['previous'] if self.systemctl('is-active', name, check=False).returncode == 0]
        if active:
            raise ValueError('Не удалось остановить службы: '+', '.join(active))
        self.step('Шифрование и загрузка финальной копии на Google Диск')
        self.backup.dirty()
        self.backup.snapshot(final=True)
        result = self.backup.status()
        if result['error'] or result['pending'] or not result['file']:
            raise ValueError(result['error'] or 'Финальная копия не подтверждена. Службы остановлены; повтори загрузку или возобнови работу.')
        with self.lock:
            self.data.update(phase='stopped', step='Сервер остановлен, финальная копия подтверждена', file=result['file'], uploaded=result['uploaded'])
            self.save()

    def resume(self):
        self.step('Возобновление прежних служб')
        previous = self.data['previous'] if 'previous' in self.data else self.inventory()
        self.root.joinpath('blocked').unlink(missing_ok=True)
        # State continues to reject mutations until all requested services start.
        for name in ('mtproxy', 'tproxy-server', 'relay-hy2', 'hysteria-server', 'amneziawg-server', 'relay-awg', 'relay-refresh.timer'):
            if previous.get(name):
                self.systemctl('start', name)
                if self.systemctl('is-active', name, check=False).returncode:
                    raise ValueError('Служба не запустилась: '+name)
        if previous.get('tproxy-server'):
            import urllib.request
            for attempt in range(30):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:8081/readyz',timeout=2) as response:
                        if response.status==200:break
                except OSError:pass
                time.sleep(.3)
            else:raise ValueError('Telegram backend не стал готов после запуска.')
        if previous.get('hysteria-server'):
            from hy2_routes import helper
            for attempt in range(30):
                try:
                    helper({'op':'migration_ready'})
                    break
                except (OSError,ValueError):time.sleep(.5)
            else:raise ValueError('Hysteria не стала готова. Проверь DNS и сертификат.')
        if previous.get('amneziawg-server'):
            from awg_routes import helper
            for attempt in range(30):
                try:helper({'op':'migration_ready'});break
                except (OSError,ValueError):time.sleep(.5)
            else:raise ValueError('AmneziaWG не стала готова после запуска')
        with self.lock:
            self.data.update(phase='running', step='Работа возобновлена', error='')
            self.data.pop('previous', None)
            self.save()

    def standby(self):
        """Called by root restore after data import, without requiring a cloud backup."""
        self.data.update(phase='standby', step='Данные восстановлены. Переключи DNS и включи новый сервер.', error='', previous={name:True for name in self.inventory() if name != 'relay-refresh.service'})
        self.save()
        self.write('blocked', b'')
