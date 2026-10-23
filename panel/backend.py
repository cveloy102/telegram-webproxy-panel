import json
import os
import pathlib
import shlex
import signal


def active_users(state):
    return [u for u in state['users'] if u['enabled'] and not state.get('paused', False)]


def health_url(state):
    endpoint = 'readyz' if active_users(state) else 'healthz'
    return 'http://127.0.0.1:8081/' + endpoint


def wait_for_restart():
    # Keep the systemd unit healthy without starting MTProxy's upstream pool.
    # Profile changes and routing refreshes restart this launcher normally.
    print('All WEB profiles suspended; MTProxy upstream connections disabled.', flush=True)
    while True:
        signal.pause()


def main():
    config = json.loads(pathlib.Path('/etc/mtproxy/managed-secrets.json').read_text())
    if config.get('enabled', True) is False:
        wait_for_restart()
        return
    args = ['/opt/MTProxy/objs/bin/mtproto-proxy', '-u', 'mtproxy', '-p', '8888', '-H', '2398']
    for secret in config['secrets']:
        args.extend(['-S', secret])
    args.extend(shlex.split(os.getenv('MTPROXY_NAT_ARGS', '')))
    args.extend(['--aes-pwd', '/etc/mtproxy/proxy-secret', '/etc/mtproxy/proxy-multi.conf',
                 '-M', os.getenv('MTPROXY_WORKERS', '1'), '-C', os.getenv('MTPROXY_MAX_CONNECTIONS', '4096')])
    os.execv(args[0], args)


if __name__ == '__main__':
    main()
