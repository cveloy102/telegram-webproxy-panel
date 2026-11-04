"""Fetch only Telegram's public backend data, using a prepared cascade on RU."""
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path('/etc/relay-cascade')
URLS = {'https://core.telegram.org/getProxySecret', 'https://core.telegram.org/getProxyConfig'}


def fetch_telegram(url):
    if url not in URLS: raise ValueError('Неизвестный адрес конфигурации Telegram.')
    state = json.loads((ROOT / 'state.json').read_text()) if (ROOT / 'state.json').exists() else {}
    if state.get('exit_public_key'):
        # This also works during standby provisioning, before client egress is enabled.
        result = subprocess.run(['curl', '-q', '--noproxy', '*', '--ipv4', '--fail', '--silent', '--show-error',
                                 '--proto', '=https', '--max-time', '30', '--max-filesize', '1048576',
                                 '--interface', '10.78.254.1', url],
                                check=True, capture_output=True, timeout=35)
        content = result.stdout
    else:
        with urllib.request.urlopen(url, timeout=30) as response: content = response.read(1048576)
    if not 16 <= len(content) < 1048576:
        raise RuntimeError('Некорректный размер публичной конфигурации Telegram.')
    if url.endswith('getProxyConfig') and (len(content) < 100 or b'default ' not in content or b'proxy_for ' not in content):
        raise RuntimeError('Неожиданный формат Telegram config.')
    return content
