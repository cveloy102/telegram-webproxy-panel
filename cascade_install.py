"""Entry service and minimal dedicated exit installation using the same installer."""
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'panel'))
from cascade_network import ROOT, INTERFACE, run, preflight, public_key, exit_firewall, replace_table, setup_interface


def prepare_entry(setup):
    """Optional bootstrap when RU cannot fetch Telegram data before the panel exists."""
    existing = json.loads(setup.STATE.read_text()) if setup.STATE.exists() else None
    if existing and existing.get('phase') == 'complete': raise RuntimeError('Панель уже установлена. Настрой выход в разделе «Каскад».')
    setup.preflight(existing)
    if (ROOT / 'exit.json').exists(): raise RuntimeError('Этот сервер уже является выходным узлом.')
    from cascade_control import Controller, atomic
    from cascade_network import endpoint, validate_state
    state = json.loads((ROOT / 'state.json').read_text()) if (ROOT / 'state.json').exists() else {'schema': 1, 'enabled': False}
    validate_state(state)
    if state['enabled']: raise RuntimeError('Каскад уже включён. Используй панель для изменения выхода.')
    name = setup.ask('Название выхода', state.get('name', 'Норвегия'))
    if not 1 <= len(name) <= 60 or any(ord(c) < 32 for c in name): raise ValueError('Некорректное название.')
    host = setup.ask('Публичный IPv4 выхода', state.get('host'), endpoint)
    def valid_port(value):
        if not value.isascii() or not value.isdecimal() or not 1024 <= int(value) <= 65535: raise ValueError('UDP-порт от 1024 до 65535.')
        return int(value)
    port = setup.ask('UDP-порт выхода', str(state.get('port', 51821)), valid_port)
    if setup.ask('Подготовить туннель до установки панели? да / нет', 'нет', setup.yes_no) != 'да': return
    setup.run('apt-get', 'update')
    setup.run('apt-get', 'install', '-y', '--no-install-recommends', 'wireguard-tools', 'iproute2', 'nftables', 'curl', 'ca-certificates')
    with setup.open_install_lock() as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (ROOT / 'state.json').exists() and json.loads((ROOT / 'state.json').read_text()).get('enabled'):
            raise RuntimeError('Каскад уже включён; конфигурация не изменена.')
        if not ROOT.exists(): preflight()
        setup.directory(ROOT, mode=0o700)
        if not (ROOT / 'private.key').exists():
            private = run('wg', 'genkey').stdout.strip()
            setup.write(ROOT / 'private.key', private + '\n', mode=0o600)
            setup.write(ROOT / 'public.key', run('wg', 'pubkey', input=private + '\n').stdout, mode=0o600)
        state = {'schema': 1, 'enabled': False, 'name': name, 'host': host, 'port': port}
        atomic(ROOT / 'state.json', state)
        print('На зарубежном VPS запусти тот же установщик с --exit-node. Передай ему эту строку:')
        print(json.dumps({'schema': 1, 'ru_public_key': (ROOT / 'public.key').read_text().strip(), 'port': port}))
        def reply(value):
            try:
                data = json.loads(value)
                if not isinstance(data, dict) or data.get('schema') != 1: raise ValueError()
                key = public_key(data.get('exit_public_key'))
                if key == (ROOT / 'public.key').read_text().strip(): raise ValueError()
                return key
            except (ValueError, TypeError): raise ValueError('Нужен JSON-ответ зарубежного установщика с его публичным ключом.') from None
        state['exit_public_key'] = setup.ask('Вставь ответ зарубежного узла', validate=reply)
        atomic(ROOT / 'state.json', validate_state(state))
        controller = Controller(uids=[])
        controller.probe(state)
        print('Канал проверен. Запусти обычную установку или --recover. Пользовательский каскад пока выключен; включи его в панели после восстановления.')


def install_entry(setup):
    if (ROOT / 'exit.json').exists(): raise RuntimeError('Этот VPS уже является выходным узлом каскада.')
    if ROOT.exists() and not (ROOT / 'state.json').exists():
        raise RuntimeError('Неполная установка /etc/relay-cascade: сначала проверь сохранённые ключи.')
    if not ROOT.exists():
        preflight()
        setup.directory(ROOT, mode=0o700)
        setup.json_write(ROOT / 'state.json', {'schema': 1, 'enabled': False}, mode=0o600)
    unit = '''[Unit]
Description=Relay cascade tunnel and egress guard
ConditionPathExists=!/var/lib/relay-migration/blocked
After=network-online.target nftables.service
PartOf=nftables.service
Wants=network-online.target
Before=mtproxy.service hysteria-server.service amneziawg-server.service
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=45
ExecCondition=+/usr/bin/python3 /opt/relay-panel/current/panel/migration_state.py --can-start
ExecStart=/usr/bin/python3 /opt/relay-panel/current/panel/cascade_control.py
ExecStopPost=-/usr/sbin/ip link delete dev wg-cascade
Restart=on-failure
RestartSec=3
RuntimeDirectory=relay-cascade
RuntimeDirectoryMode=0750
Group=relayadmin
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/relay-cascade /run/relay-cascade
ReadOnlyPaths=/var/lib/relay-migration
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
[Install]
WantedBy=multi-user.target
'''
    # sysctl on the owned interface requires /proc/sys; no host-wide sysctl is written by this daemon.
    setup.write('/etc/systemd/system/relay-cascade.service', unit)
    from cascade_network import install_transport_runtime
    install_transport_runtime()
    for name in ('mtproxy', 'hysteria-server', 'amneziawg-server'):
        folder = Path('/etc/systemd/system') / (name + '.service.d')
        setup.directory(folder)
        setup.write(folder / 'cascade.conf', '''[Unit]
Requires=relay-cascade.service
BindsTo=relay-cascade.service
After=relay-cascade.service
''')
    # Forwarding is also needed when AWG is added later. Do not replace host routing.
    setup.write('/etc/sysctl.d/81-relay-cascade.conf', 'net.ipv4.ip_forward=1\n')
    setup.run('sysctl', '-w', 'net.ipv4.ip_forward=1')


def install_exit(setup, source):
    """No panel, DNS, user databases, SSH credentials or root password on the exit."""
    import platform
    if os.name != 'posix' or os.geteuid() != 0: raise RuntimeError('Запусти установщик на VPS под root.')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04' or platform.machine() != 'x86_64':
        raise RuntimeError('Выходной узел: нужен Ubuntu 24.04 amd64 с systemd.')
    if not Path('/run/systemd/system').exists(): raise RuntimeError('Нужен systemd.')
    if Path('/etc/relay-panel/install.json').exists(): raise RuntimeError('На этом VPS уже стоит основная панель. Выходной узел ставится отдельно.')
    if ROOT.exists(): raise RuntimeError('Каскад уже установлен. Для смены ключей используй сохранённую конфигурацию; повторная установка не перезаписывает узел.')
    print('Выходной узел: только WireGuard, firewall и NAT. Домен не требуется.')
    raw = setup.ask('Вставь данные RU из раздела «Каскад» (одна строка JSON)')
    try:
        pairing = json.loads(raw)
        if not isinstance(pairing, dict) or pairing.get('schema') != 1: raise ValueError()
        peer = public_key(pairing.get('ru_public_key'))
        port = pairing.get('port')
        if type(port) is not int or not 1024 <= port <= 65535: raise ValueError()
    except (ValueError, TypeError): raise ValueError('Некорректные данные RU. Скопируй строку из панели целиком.') from None
    setup.check_udp_port(port)
    if setup.ask('Установить выходной узел? да / нет', 'нет', setup.yes_no) != 'да': return
    setup.run('apt-get', 'update')
    setup.run('apt-get', 'install', '-y', '--no-install-recommends', 'wireguard-tools', 'iproute2', 'nftables', 'ca-certificates')
    preflight()
    with setup.open_install_lock() as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        setup.directory(ROOT, mode=0o700)
        private = run('wg', 'genkey').stdout.strip()
        public = run('wg', 'pubkey', input=private + '\n').stdout.strip()
        setup.write(ROOT / 'private.key', private + '\n', mode=0o600)
        setup.json_write(ROOT / 'exit.json', {'schema': 1, 'ru_public_key': peer, 'port': port}, mode=0o600)
        setup.directory('/opt/relay-cascade', mode=0o755)
        for name in ('cascade_network.py',):
            shutil.copyfile(source / 'panel' / name, Path('/opt/relay-cascade') / name)
        shutil.copyfile(source / 'cascade_install.py', '/opt/relay-cascade/cascade_install.py')
        setup.write('/etc/sysctl.d/81-relay-cascade.conf', 'net.ipv4.ip_forward=1\n')
        setup.run('sysctl', '-w', 'net.ipv4.ip_forward=1')
        setup.write('/etc/systemd/system/relay-cascade-exit.service', '''[Unit]
Description=Relay cascade exit WireGuard and NAT
After=network-online.target nftables.service
PartOf=nftables.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/usr/bin/python3 /opt/relay-cascade/cascade_install.py --apply-exit
ExecStopPost=-/usr/sbin/ip link delete dev wg-cascade
UMask=0077
[Install]
WantedBy=multi-user.target
''')
        setup.run('systemctl', 'daemon-reload')
        setup.run('systemctl', 'enable', '--now', 'relay-cascade-exit')
        print('\nОткрой входящий UDP ' + str(port) + ' в firewall хостера.')
        print('Вставь этот ответ в панель RU:')
        print(json.dumps({'schema': 1, 'exit_public_key': public}))
        print('Сохрани /etc/relay-cascade отдельно и безопасно: там приватный ключ выходного узла.')


def apply_exit():
    config = json.loads((ROOT / 'exit.json').read_text())
    replace_table('relay_cascade_exit', exit_firewall())
    setup_interface(ROOT / 'private.key', config['ru_public_key'], entry=False, port=config['port'])


if __name__ == '__main__' and sys.argv[1:] == ['--apply-exit']: apply_exit()
