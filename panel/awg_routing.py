"""IPv4-only AWG policies. Geo data is inert JSON in the portable AWG database.

Domain/DNS classification can later feed a separate destination set; it must not
change the existing cascade/ru_split policy identifiers or client credentials.
"""
import hashlib
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

from cascade_network import AWG_RU_MARK as RU_MARK, ENTRY, ROOT as CASCADE_ROOT, replace_table

SOURCE = 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt'
POLICIES = ('cascade', 'ru_split')
MAX_BYTES = 2 * 1024 * 1024
DAY = 86400
FORBIDDEN = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'))


def policy(value):
    if not isinstance(value, str) or value not in POLICIES:
        raise ValueError('Неизвестный режим маршрутизации AWG.')
    return value


def networks(text):
    if not isinstance(text, str) or len(text.encode()) > MAX_BYTES:
        raise ValueError('Слишком большая база RU.')
    result = []
    lines = text.splitlines()
    if len(lines) > 50000:
        raise ValueError('Слишком много сетей RU.')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'): continue
        net = ipaddress.ip_network(line, strict=True)
        if net.version == 6: continue  # IPv6 never acquires direct egress.
        if net.prefixlen < 8 or any(net.overlaps(x) for x in FORBIDDEN):
            raise ValueError('В базе RU обнаружена недопустимая сеть.')
        result.append(net)
    result = list(ipaddress.collapse_addresses(result))
    coverage = sum(x.num_addresses for x in result)
    if not 1000 <= len(result) <= 50000 or not 5000000 <= coverage <= 150000000:
        raise ValueError('Неожиданный размер базы RU; сохранена прежняя версия.')
    return [str(x) for x in result]


def snapshot(text, fetched=None):
    nets = networks(text)
    digest = hashlib.sha256(('\n'.join(nets) + '\n').encode()).hexdigest()
    return {'schema': 1, 'source': SOURCE, 'fetched': int(time.time() if fetched is None else fetched),
            'sha256': digest, 'networks': nets}


def validate_geo(value):
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('source') != SOURCE:
        raise ValueError('Некорректная база RU.')
    if type(value.get('fetched')) is not int or not 0<=value['fetched']<=253402300799:
        raise ValueError('Некорректная дата базы RU.')
    nets = value.get('networks')
    if not isinstance(nets, list) or len(nets)>50000 or not all(isinstance(x, str) for x in nets):
        raise ValueError('Некорректные сети RU.')
    checked = snapshot('\n'.join(nets), value['fetched'])
    if checked != value:
        raise ValueError('Контрольная сумма базы RU не совпала.')
    return value


def check_change(old, new):
    before, after = set(old['networks']), set(new['networks'])
    coverage = lambda rows: sum(ipaddress.ip_network(x).num_addresses for x in rows)
    if (not .75 <= len(after) / len(before) <= 1.25 or
            not .85 <= coverage(after) / coverage(before) <= 1.15 or
            len(before ^ after) > len(before) * .3):
        raise ValueError('RU-список резко изменился; обновление отклонено, действует прежняя база.')


def fetch():
    # Fixed URL, no proxy environment/curlrc, HTTPS only and bounded response.
    state_path=CASCADE_ROOT/'state.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else {}
    through_cascade=['--interface',ENTRY] if state.get('enabled') is True else []
    result = subprocess.run(['curl', '-q', '--noproxy', '*', '--ipv4', '--fail',
                             '--silent', '--show-error', '--proto', '=https',
                             '--connect-timeout', '5', '--max-time', '20',
                             '--max-filesize', str(MAX_BYTES), *through_cascade, SOURCE],
                            check=True, capture_output=True, timeout=25)
    if len(result.stdout) > MAX_BYTES: raise ValueError('Слишком большая база RU.')
    return snapshot(result.stdout.decode('ascii'))


@lru_cache(maxsize=1)
def seed():
    path = Path(__file__).with_name('data') / 'ru-ipv4.txt'
    return snapshot(path.read_text(encoding='ascii'), 1793836800)  # 2026-11-05 UTC


def load(c, key='routing_geo'):
    row = c.execute('SELECT v FROM settings WHERE k=?', (key,)).fetchone()
    if not row: return None
    return decoded(row[0])


@lru_cache(maxsize=4)
def decoded(raw):
    return validate_geo(json.loads(raw))


def put(c, key, value):
    c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', (key, json.dumps(value)))


def firewall(split, nets, blocked=()):
    # All addresses are parsed, even those read from a restored SQLite database.
    peers = ', '.join(str(ipaddress.IPv4Address(x)) for x in split)
    pending = ', '.join(str(ipaddress.IPv4Address(x)) for x in blocked)
    destinations = ', '.join(str(ipaddress.IPv4Network(x)) for x in nets)
    elements = lambda values: 'elements = { '+values+' };' if values else ''
    missing = '  iifname "awg-relay" ip saddr @split_peers drop\n' if not nets else ''
    return f'''table inet relay_awg_routing {{
 set split_peers {{ type ipv4_addr; {elements(peers)} }}
 set blocked_peers {{ type ipv4_addr; {elements(pending)} }}
 set ru_ipv4 {{ type ipv4_addr; flags interval; {elements(destinations)} }}
 chain classify {{
  type filter hook prerouting priority -160; policy accept;
  iifname "awg-relay" meta mark set 0
  iifname "awg-relay" ip saddr @blocked_peers drop
{missing}  iifname "awg-relay" ip saddr @split_peers ip daddr @ru_ipv4 meta mark set {RU_MARK}
 }}
}}
'''


def clear_connections(address):
    address = str(ipaddress.IPv4Address(address))
    result = subprocess.run(['conntrack', '-D', '-f', 'ipv4', '-s', address],
                            capture_output=True, text=True, timeout=2, env=os.environ | {'LC_ALL': 'C'})
    # conntrack returns 1 when there were zero matching flows. Other failures,
    # including missing capabilities, must leave the profile blocked for retry.
    if result.returncode != 0 and not (result.returncode == 1 and
            result.stderr.strip().endswith('0 flow entries have been deleted.')):
        raise OSError('Не удалось сбросить прежние соединения профиля AWG.')


class Runtime:
    def __init__(self): self.digest = None

    def install(self, split, nets, blocked):
        body = firewall(split, nets, blocked)
        digest = hashlib.sha256(body.encode()).hexdigest()
        if digest == self.digest:
            tables = subprocess.run(['nft', 'list', 'tables'], check=True, capture_output=True,
                                    text=True, timeout=5).stdout
            if 'table inet relay_awg_routing\n' in tables: return
        replace_table('relay_awg_routing', body)
        self.digest = digest
