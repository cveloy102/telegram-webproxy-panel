"""Owned WireGuard interface and policy routes; never change the host default route."""
import base64
import ipaddress
import json
from pathlib import Path
import subprocess
import time

INTERFACE = 'wg-cascade'
NETWORK = '10.78.254.0/30'
ENTRY = '10.78.254.1'
EXIT = '10.78.254.2'
TABLE = '20781'
MARK = '0x20781'
OUTER_MARK = '0x20782'
AWG_RU_MARK = '0x20783'
PRIORITIES = ('10781', '10782')
ROOT = Path('/etc/relay-cascade')
PRIVATE = '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4'


def validate_transport(value):
    """Root-only optional transport; missing file preserves legacy WireGuard."""
    if not isinstance(value, dict) or not {'schema', 'type', 'parameters'} <= set(value) or set(value) - {'schema', 'type', 'parameters', 'entry_host', 'entry_port'} or value['schema'] != 1 or value['type'] != 'amneziawg-3.1':
        raise ValueError('Некорректный транспорт каскада.')
    if 'entry_host' in value or 'entry_port' in value:
        endpoint(value.get('entry_host'))
        if type(value.get('entry_port')) is not int or not 1024 <= value['entry_port'] <= 65535: raise ValueError('Некорректный порт входного узла.')
    p = value['parameters']
    required = {'HeaderProtectionKey', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'}
    optional = {'Jc', 'Jmin', 'Jmax', 'ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'KeepaliveTimeout', 'RandomTrailers', 'DisableCookies'}
    if not isinstance(p, dict) or not required <= set(p) or set(p) - required - optional:
        raise ValueError('Некорректные параметры транспорта каскада.')
    public_key(p['HeaderProtectionKey'])
    for k in ('S1', 'S2', 'S3', 'S4'):
        if type(p[k]) is not int or not 12 <= p[k] <= 128: raise ValueError('Некорректный padding каскада.')
    for i in range(1, 5):
        if p['H'+str(i)] != i: raise ValueError('Header Protection требует совместимых H1-H4.')
    for k in ('Jc', 'Jmin', 'Jmax'):
        if k in p and (type(p[k]) is not int or not 0 <= p[k] <= 1000): raise ValueError('Некорректный junk каскада.')
    if p.get('Jmin', 0) > p.get('Jmax', 0): raise ValueError('Некорректный диапазон junk.')
    for k in ('ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'KeepaliveTimeout'):
        if k not in p: continue
        pieces = str(p[k]).split('-')
        if not 1 <= len(pieces) <= 2 or any(not x.isascii() or not x.isdecimal() for x in pieces): raise ValueError('Некорректный диапазон каскада.')
        nums = list(map(int, pieces))
        if not 0 <= nums[0] <= nums[-1] <= (128 if k == 'ContentPaddingAddition' else 180): raise ValueError('Диапазон каскада слишком велик.')
    for k in ('RandomTrailers', 'DisableCookies'):
        if k in p and p[k] not in ('on', 'off'): raise ValueError('Некорректный флаг каскада.')
    if p.get('RandomTrailers') == 'on' and len({p[k] for k in ('S1','S2','S3','S4')}) != 1:
        raise ValueError('RandomTrailers требует одинаковые S1-S4.')
    return value


def transport_config(root=ROOT):
    path = Path(root) / 'transport.json'
    return validate_transport(json.loads(path.read_text())) if path.exists() else None


def tunnel_tool(root=ROOT):
    return '/usr/local/bin/awg' if transport_config(root) else 'wg'


def install_transport_runtime():
    """Install only the optional cascade engine, independent of client AWG."""
    if not transport_config(): return
    if not all(Path(p).is_file() for p in ('/usr/local/bin/awg', '/usr/local/bin/amneziawg-go')):
        raise RuntimeError('Для восстановления AWG каскада нужны проверенные бинарные файлы AmneziaWG 3.1.')
    Path('/run/amneziawg').mkdir(mode=0o700, exist_ok=True)
    Path('/run/relay-cascade').mkdir(mode=0o750, exist_ok=True)
    Path('/etc/tmpfiles.d/relay-cascade-awg.conf').write_text('d /run/amneziawg 0700 root root -\nd /run/relay-cascade 0750 root root -\n')
    service = 'relay-cascade.service' if (ROOT / 'state.json').exists() else 'relay-cascade-exit.service'
    unit = '''[Unit]
Description=AmneziaWG 3.1 inter-server cascade engine
After=network-online.target nftables.service
Wants=network-online.target
ConditionPathExists=/etc/relay-cascade/transport.json
ConditionPathExists=!/var/lib/relay-migration/blocked
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30
ExecStart=ENGINE_COMMAND
Restart=always
RestartSec=2
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/amneziawg /run/relay-cascade
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
TimeoutStopSec=10
[Install]
WantedBy=multi-user.target
'''
    unit = unit.replace('[Service]', 'PartOf=' + service + '\n[Service]')
    module = str(Path(__file__).resolve())
    unit = unit.replace('ENGINE_COMMAND', '/usr/bin/python3 ' + module + ' --engine')
    Path('/etc/systemd/system/relay-cascade-engine.service').write_text(unit)
    folder = Path('/etc/systemd/system') / (service + '.d')
    folder.mkdir(exist_ok=True)
    folder.joinpath('awg-transport.conf').write_text('[Unit]\nWants=relay-cascade-engine.service\nAfter=relay-cascade-engine.service\n[Service]\nRuntimeDirectory=relay-cascade\nReadWritePaths=/run/amneziawg /run/relay-cascade\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'relay-cascade-engine.service')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20, **kwargs)


def public_key(value):
    try:
        if not isinstance(value, str) or len(value) != 44: raise ValueError()
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value: raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Некорректный публичный ключ WireGuard.') from None
    return value


def endpoint(value):
    try:
        address = ipaddress.IPv4Address(value)
        if not address.is_global: raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Нужен публичный IPv4 выходного сервера.') from None
    return str(address)


def validate_state(value):
    if not isinstance(value, dict) or value.get('schema') != 1 or type(value.get('enabled')) is not bool:
        raise ValueError('Некорректное состояние каскада.')
    if 'host' in value:
        endpoint(value['host'])
        if type(value.get('port')) is not int or not 1024 <= value['port'] <= 65535:
            raise ValueError('Некорректный порт каскада.')
        if not isinstance(value.get('name'), str) or not 1 <= len(value['name']) <= 60 or any(ord(c) < 32 for c in value['name']):
            raise ValueError('Некорректное название каскада.')
    if value.get('exit_public_key'):
        public_key(value['exit_public_key'])
        if 'host' not in value: raise ValueError('Отсутствует адрес выходного узла.')
    if value['enabled'] and not value.get('exit_public_key'):
        raise ValueError('У включённого каскада отсутствует выходной узел.')
    return value


def replace_table(name, body):
    exists = subprocess.run(['nft', 'list', 'table', 'inet', name], capture_output=True).returncode == 0
    script = (f'delete table inet {name}\n' if exists else '') + body
    # Validation and replacement both use atomic nft transactions. No flush ruleset.
    run('nft', '--check', '-f', '-', input=script)
    run('nft', '-f', '-', input=script)


def entry_firewall(uids, enabled):
    if not enabled:
        return f'''table inet relay_cascade {{
 chain input_guard {{
  type filter hook input priority -5; policy accept;
  iifname "{INTERFACE}" ct state {{ established, related }} accept
  iifname "{INTERFACE}" ip saddr {EXIT} icmp type echo-request accept
  iifname "{INTERFACE}" drop
 }}
 chain forward_guard {{
  type filter hook forward priority -5; policy accept;
  iifname "{INTERFACE}" drop
 }}
}}
'''
    ids = ', '.join(str(int(uid)) for uid in uids)
    return f'''table inet relay_cascade {{
 chain mark_forward {{
  type filter hook prerouting priority -150; policy accept;
  iifname "awg-relay" meta mark {AWG_RU_MARK} return
  iifname "awg-relay" meta nfproto ipv4 meta mark set {MARK}
 }}
 chain mark_output {{
  type route hook output priority -150; policy accept;
  meta mark {OUTER_MARK} return
  ct direction reply return
  oifname "lo" return
  fib daddr type local return
  meta skuid {{ {ids} }} meta nfproto ipv4 meta mark set {MARK}
 }}
 chain output_guard {{
  type filter hook postrouting priority -5; policy accept;
  meta mark {OUTER_MARK} return
  ct direction reply return
  oifname "lo" return
  meta skuid {{ {ids} }} meta nfproto ipv6 drop
  meta skuid {{ {ids} }} oifname != "{INTERFACE}" drop
  oifname "{INTERFACE}" tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240
 }}
 chain forward_guard {{
  type filter hook forward priority -5; policy accept;
  iifname "awg-relay" meta nfproto ipv6 drop
  iifname "awg-relay" meta mark {AWG_RU_MARK} oifname "{INTERFACE}" drop
  iifname "awg-relay" meta mark {AWG_RU_MARK} return
  iifname "awg-relay" oifname != "{INTERFACE}" drop
  iifname "{INTERFACE}" oifname != "awg-relay" drop
  iifname "{INTERFACE}" ct state != {{ established, related }} drop
 }}
 chain input_guard {{
  type filter hook input priority -5; policy accept;
  iifname "{INTERFACE}" ct state {{ established, related }} accept
  iifname "{INTERFACE}" ip saddr {EXIT} icmp type echo-request accept
  iifname "{INTERFACE}" drop
 }}
 chain nat {{
  type nat hook postrouting priority 90; policy accept;
  oifname "{INTERFACE}" masquerade
 }}
}}
'''


def exit_firewall():
    return f'''table inet relay_cascade_exit {{
 chain input_guard {{
  type filter hook input priority -5; policy accept;
  iifname "{INTERFACE}" ct state {{ established, related }} accept
  iifname "{INTERFACE}" ip saddr {ENTRY} ip daddr {EXIT} icmp type echo-request accept
  iifname "{INTERFACE}" drop
 }}
 chain forward_guard {{
  type filter hook forward priority -5; policy accept;
  iifname "{INTERFACE}" ip saddr != {ENTRY} drop
  iifname "{INTERFACE}" tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240
  oifname "{INTERFACE}" tcp flags & syn == syn tcp option maxseg size > 1240 tcp option maxseg size set 1240
  iifname "{INTERFACE}" ip daddr {{ {PRIVATE} }} drop
  iifname "{INTERFACE}" oifname "{INTERFACE}" drop
  iifname "{INTERFACE}" meta nfproto ipv6 drop
  oifname "{INTERFACE}" ct state != {{ established, related }} drop
 }}
 chain nat {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {ENTRY} oifname != "{INTERFACE}" masquerade
 }}
}}
'''


def preflight():
    """Reject reserved network/table/rule ownership conflicts before touching anything."""
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout)
    network = ipaddress.ip_network(NETWORK)
    for route in routes:
        dst = route.get('dst', 'default')
        if dst != 'default' and route.get('dev') != INTERFACE and ipaddress.ip_network(dst, strict=False).overlaps(network):
            raise ValueError('Подсеть каскада ' + NETWORK + ' уже используется.')
    rules = json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
    if any(str(rule.get('priority')) in PRIORITIES for rule in rules):
        raise ValueError('Приоритеты маршрутизации 10781/10782 уже заняты.')
    if any(str(route.get('table')) == TABLE for route in routes):
        raise ValueError('Таблица маршрутизации ' + TABLE + ' уже занята.')
    if subprocess.run(['ip', 'link', 'show', 'dev', INTERFACE], capture_output=True).returncode == 0:
        raise ValueError('Интерфейс wg-cascade уже занят.')
    for name in ('relay_cascade', 'relay_cascade_exit'):
        if subprocess.run(['nft', 'list', 'table', 'inet', name], capture_output=True).returncode == 0:
            raise ValueError('Таблица firewall каскада уже существует: ' + name)


def setup_interface(private_path, peer, entry=True, host=None, port=51821):
    transport = transport_config(Path(private_path).parent)
    if subprocess.run(['ip', 'link', 'show', 'dev', INTERFACE], capture_output=True).returncode:
        if transport:
            run('systemctl', 'start', 'relay-cascade-engine.service')
            for _ in range(50):
                if Path('/run/amneziawg/' + INTERFACE + '.sock').exists(): break
                time.sleep(.1)
            else: raise RuntimeError('AmneziaWG каскада не запустилась.')
        else:
            run('ip', 'link', 'add', 'dev', INTERFACE, 'type', 'wireguard')
    tool = '/usr/local/bin/awg' if transport else 'wg'
    if transport:
        # The shared protection key never appears in argv, logs or status responses.
        import os, tempfile
        pending = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir='/run/relay-cascade', prefix='transport-', delete=False) as f:
                pending = Path(f.name)
                os.chmod(pending, 0o600)
                f.write('[Interface]\nPrivateKey = ' + Path(private_path).read_text().strip() + '\n')
                f.write('FwMark = ' + OUTER_MARK + '\n')
                if not entry: f.write('ListenPort = ' + str(port) + '\n')
                elif 'entry_port' in transport: f.write('ListenPort = ' + str(transport['entry_port']) + '\n')
                for k, v in transport['parameters'].items(): f.write(k + ' = ' + str(v) + '\n')
                f.write('\n[Peer]\nPublicKey = ' + public_key(peer) + '\nAllowedIPs = ' + ('0.0.0.0/0' if entry else ENTRY + '/32') + '\n')
                if entry: f.write('Endpoint = ' + endpoint(host) + ':' + str(port) + '\nPersistentKeepalive = 25\n')
                elif 'entry_host' in transport: f.write('Endpoint = ' + transport['entry_host'] + ':' + str(transport['entry_port']) + '\nPersistentKeepalive = 25\n')
                f.flush()
            run(tool, 'syncconf', INTERFACE, str(pending))
        finally:
            if pending is not None: pending.unlink(missing_ok=True)
    command = [tool, 'set', INTERFACE, 'fwmark', OUTER_MARK, 'private-key', str(private_path), 'peer', public_key(peer),
               'allowed-ips', '0.0.0.0/0' if entry else ENTRY + '/32']
    if entry: command += ['endpoint', endpoint(host) + ':' + str(port), 'persistent-keepalive', '25']
    else: command[3:3] = ['listen-port', str(port)]
    if transport and 'entry_host' in transport:
        if entry: command[3:3] = ['listen-port', str(transport['entry_port'])]
        else: command += ['endpoint', transport['entry_host'] + ':' + str(transport['entry_port']), 'persistent-keepalive', '25']
    # wg set is incremental: remove a previous exit peer when re-pairing.
    for previous in run(tool, 'show', INTERFACE, 'peers').stdout.split():
        if previous != peer: run(tool, 'set', INTERFACE, 'peer', previous, 'remove')
    run(*command)
    run('ip', 'address', 'replace', (ENTRY if entry else EXIT) + '/30', 'dev', INTERFACE)
    run('ip', 'link', 'set', 'dev', INTERFACE, 'mtu', '1280', 'up')
    # Loose mode also works when the provider sets conf.all.rp_filter=1.
    run('sysctl', '-w', 'net.ipv4.conf.' + INTERFACE + '.rp_filter=2')


def policy_routes():
    # A terminal route remains if the device disappears; lookup cannot fall back to RU.
    run('ip', '-4', 'route', 'replace', 'prohibit', 'default', 'metric', '32760', 'table', TABLE)
    run('ip', '-4', 'route', 'replace', 'default', 'dev', INTERFACE, 'metric', '10', 'table', TABLE)
    rules = json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
    for priority, selector in ((PRIORITIES[0], ['fwmark', MARK]), (PRIORITIES[1], ['from', ENTRY + '/32'])):
        if not any(str(rule.get('priority')) == priority for rule in rules):
            run('ip', '-4', 'rule', 'add', 'priority', priority, *selector, 'lookup', TABLE)


def remove_runtime():
    # Called only on explicit disable, after removing the marking/guard transaction.
    for priority in PRIORITIES:
        subprocess.run(['ip', '-4', 'rule', 'del', 'priority', priority], capture_output=True)
    subprocess.run(['ip', '-4', 'route', 'flush', 'table', TABLE], capture_output=True)
    subprocess.run(['ip', 'link', 'delete', 'dev', INTERFACE], capture_output=True)


def serve_engine():
    """Reapply peer configuration on every engine restart, also on the oneshot exit."""
    import os, socket
    transport_config()
    process = subprocess.Popen(['/usr/local/bin/amneziawg-go', '-f', INTERFACE])
    try:
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('Движок каскада остановился при запуске.')
            if Path('/run/amneziawg/' + INTERFACE + '.sock').exists(): break
            time.sleep(.05)
        else: raise RuntimeError('Не появился сокет каскада.')
        entry = (ROOT / 'state.json').exists()
        state = json.loads((ROOT / ('state.json' if entry else 'exit.json')).read_text())
        setup_interface(ROOT / 'private.key', state['exit_public_key' if entry else 'ru_public_key'], entry=entry,
                        host=state.get('host'), port=state['port'])
        address = os.getenv('NOTIFY_SOCKET')
        if address:
            if address.startswith('@'): address = '\0' + address[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
                notification.connect(address); notification.sendall(b'READY=1')
        status = process.wait()
        raise RuntimeError('Движок каскада остановился: ' + str(status))
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['--engine']: serve_engine()
