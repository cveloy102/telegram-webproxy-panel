import json
import os
import pathlib
import shlex

secrets = json.loads(pathlib.Path('/etc/mtproxy/managed-secrets.json').read_text())['secrets']
args = ['/opt/MTProxy/objs/bin/mtproto-proxy', '-u', 'mtproxy', '-p', '8888', '-H', '2398']
for secret in secrets:
    args.extend(['-S', secret])
args.extend(shlex.split(os.getenv('MTPROXY_NAT_ARGS', '')))
args.extend(['--aes-pwd', '/etc/mtproxy/proxy-secret', '/etc/mtproxy/proxy-multi.conf',
             '-M', os.getenv('MTPROXY_WORKERS', '1'), '-C', os.getenv('MTPROXY_MAX_CONNECTIONS', '4096')])
os.execv(args[0], args)
