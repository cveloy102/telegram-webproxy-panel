"""Local host state; never included in portable recovery archives."""
import contextlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.getenv('RELAY_MIGRATION_DATA', '/var/lib/relay-migration'))


def state():
    try:
        return json.loads((ROOT / 'state.json').read_text())
    except FileNotFoundError:
        return {'phase': 'running'}


def blocked():
    return (ROOT / 'blocked').exists() or state().get('phase') != 'running'


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def can_start():
    if (ROOT/'blocked').exists():return False
    current=state()
    return current.get('phase')=='running' or (current.get('phase')=='resuming' and current.get('boot_id')==boot_id())


@contextlib.contextmanager
def exclusive():
    """Serialize root recovery with HTTP writes, updates and migration jobs."""
    lock=ROOT/'mutations.lock'
    if not lock.exists():
        if blocked():raise ValueError('Сервер остановлен для переноса.')
        yield
        return
    import fcntl
    with lock.open('rb') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Другая операция ещё выполняется. Повтори позже.') from None
        try:
            if blocked():raise ValueError('Сначала возобнови работу сервера через migration resume.')
            yield
        finally:fcntl.flock(handle,fcntl.LOCK_UN)


@contextlib.contextmanager
def mutation(allow_error=False):
    """Drain in-flight writes before a snapshot, reject new writes during migration."""
    lock = ROOT / 'mutations.lock'
    if not lock.exists():
        if blocked() and not (allow_error and state().get('phase')=='error'):
            raise ValueError('Сервер остановлен для переноса. Открой раздел «Перенос».')
        yield
        return
    import fcntl
    with lock.open('rb') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Выполняется перенос сервера. Изменения временно закрыты.') from None
        try:
            if blocked() and not (allow_error and state().get('phase')=='error'):
                raise ValueError('Сервер остановлен для переноса. Открой раздел «Перенос».')
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


if __name__=='__main__':
    try:sys.exit(0 if sys.argv[1:]==['--can-start'] and can_start() else 1)
    except (OSError,ValueError):sys.exit(1)
