import json
import os
import pathlib
import shlex
import socket

secrets = json.loads(pathlib.Path('/etc/mtproxy/managed-secrets.json').read_text())['secrets']
args = ['/opt/MTProxy/objs/bin/mtproto-proxy', '-u', 'mtproxy', '-p', '8888', '-H', '2398']
for secret in secrets:
    args.extend(['-S', secret])
nat = shlex.split(os.getenv('MTPROXY_NAT_ARGS', ''))
credentials = os.getenv('CREDENTIALS_DIRECTORY')
if credentials and (pathlib.Path(credentials) / 'cascade.json').exists():
    cascade = json.loads((pathlib.Path(credentials) / 'cascade.json').read_text())
    if cascade.get('enabled'):
        # Telegram's backend handshake must advertise the actual public egress,
        # while the WEB listener still lives on the RU server.
        import ipaddress
        host = str(ipaddress.IPv4Address(cascade['host']))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('1.1.1.1', 53))
            local = probe.getsockname()[0]
        nat = ['--nat-info', local + ':' + host]
args.extend(nat)
args.extend(['--aes-pwd', '/etc/mtproxy/proxy-secret', '/etc/mtproxy/proxy-multi.conf',
             '-M', os.getenv('MTPROXY_WORKERS', '1'), '-C', os.getenv('MTPROXY_MAX_CONNECTIONS', '4096')])
os.execv(args[0], args)
