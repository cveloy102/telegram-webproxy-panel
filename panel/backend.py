import json
import os
import pathlib
import shlex
import signal
import socket


def active_users(state):
    return [u for u in state['users'] if u['enabled'] and not state.get('paused', False)]


def health_url(state):
    # With every WEB profile suspended MTProxy is not started, so only the relay's liveness is checked.
    endpoint = 'readyz' if active_users(state) else 'healthz'
    return 'http://127.0.0.1:8081/' + endpoint


def wait_for_restart():
    # Keep the systemd unit healthy without starting MTProxy's upstream pool: a paused proxy used to keep
    # thousands of outgoing connections alive and filled the kernel's conntrack table, which froze the VPNs.
    # Profile changes and routing refreshes restart this launcher normally.
    print('All WEB profiles suspended; MTProxy upstream connections disabled.', flush=True)
    while True:
        signal.pause()


def nat_args():
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
    return nat


def main():
    config = json.loads(pathlib.Path('/etc/mtproxy/managed-secrets.json').read_text())
    # Files written before this version have no "enabled" key: they always had an active profile.
    if config.get('enabled', True) is False:
        wait_for_restart()
        return
    args = ['/opt/MTProxy/objs/bin/mtproto-proxy', '-u', 'mtproxy', '-p', '8888', '-H', '2398']
    for secret in config['secrets']:
        args.extend(['-S', secret])
    args.extend(nat_args())
    args.extend(['--aes-pwd', '/etc/mtproxy/proxy-secret', '/etc/mtproxy/proxy-multi.conf',
                 '-M', os.getenv('MTPROXY_WORKERS', '1'), '-C', os.getenv('MTPROXY_MAX_CONNECTIONS', '4096')])
    os.execv(args[0], args)


if __name__ == '__main__':
    main()
