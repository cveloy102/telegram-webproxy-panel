"""Optional Hysteria 2 server, using its official pinned Linux release."""
import secrets
from pathlib import Path
from units import HARDEN,CURRENT

VERSION='2.13.0'
SHA256='907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691'

def caddy(domain):
    return '\nhttp://'+domain+''' {
 handle /.well-known/acme-challenge/* {
  reverse_proxy 127.0.0.1:8084
 }
 handle {
  redir https://{host}{uri} permanent
 }
}
'''+domain+''' {
 root * /var/lib/hysteria/cover
 file_server
}
'''

def install(setup,options,work):
    import yaml
    if not options.get('hy2_domain'):return
    setup.directory('/etc/hysteria','root','hysteria',0o750)
    setup.directory('/var/lib/hysteria','hysteria','hysteria',0o751)
    setup.directory('/var/lib/hysteria/cover','hysteria','hysteria',0o755)
    setup.directory('/var/lib/relay-hy2',mode=0o700)
    config=Path('/etc/hysteria/config.yaml')
    if not config.exists():
        value={'listen':':'+str(options.get('hy2_port',24443)), 'acme':{'domains':[options['hy2_domain']],'email':options.get('email',''),'dir':'/var/lib/hysteria/acme','listenHost':'127.0.0.1','type':'http','http':{'altPort':8084}},'auth':{'type':'password','password':secrets.token_urlsafe(24)}}
        setup.write(config,yaml.safe_dump(value),mode=0o640,group='hysteria')
    cover=Path('/var/lib/hysteria/cover/index.html')
    if not cover.exists():setup.write(cover,setup.render_site(options))
    binary=work/'hysteria';setup.download('https://github.com/HyNetworks/hysteria/releases/download/app/v'+VERSION+'/hysteria-linux-amd64',binary,SHA256)
    # Replace by rename; a running old process keeps its inode until restart.
    import shutil,os
    shutil.copyfile(binary,'/usr/local/bin/hysteria.new');Path('/usr/local/bin/hysteria.new').chmod(0o755);os.replace('/usr/local/bin/hysteria.new','/usr/local/bin/hysteria')
    setup.write('/etc/systemd/system/relay-hy2.service',f'''[Unit]
Description=Hysteria authentication and accounting controller
After=network.target
[Service]
Group=relayadmin
ExecStart=/usr/bin/python3 {CURRENT}/panel/hy2_control.py
Restart=on-failure
RuntimeDirectory=relay-hy2
RuntimeDirectoryMode=0750
UMask=0077
{HARDEN}ReadWritePaths=/var/lib/relay-hy2 /etc/hysteria /run/relay-hy2
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH
IPAddressDeny=any
IPAddressAllow=localhost
MemoryMax=128M
TasksMax=64
[Install]
WantedBy=multi-user.target
''')
    setup.write('/etc/systemd/system/hysteria-server.service',f'''[Unit]
Description=Hysteria 2 server
After=network-online.target relay-hy2.service caddy.service
Requires=relay-hy2.service
Wants=network-online.target
[Service]
User=hysteria
Group=hysteria
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5
WorkingDirectory=/var/lib/hysteria
UMask=0027
{HARDEN}ReadWritePaths=/var/lib/hysteria
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
''')

def activate(setup,options):
    if not options.get('hy2_domain'):return
    import sys
    sys.path.insert(0,str(Path('/opt/relay-panel/current/panel')))
    from hy2_control import Controller
    controller=Controller()
    with controller.db() as c:settings=controller.settings(c)
    # Start and certificate issuance can need longer than controller settings readiness.
    # Write config before first startup, then let systemd retry ACME independently.
    import yaml
    cfg=yaml.safe_load(controller.config.read_text())
    cfg.update(auth={'type':'http','http':{'url':'http://127.0.0.1:8083/auth/'+settings['auth_token']}},trafficStats={'listen':'127.0.0.1:9998','secret':settings['api_secret']})
    cfg.setdefault('masquerade',{'type':'file','file':{'dir':'/var/lib/hysteria/cover'}})
    pending=controller.config.with_suffix('.new')
    setup.write(pending,yaml.safe_dump(cfg),mode=0o640,group='hysteria')
    pending.replace(controller.config)
    setup.run('systemctl','enable','relay-hy2')
    setup.run('systemctl','restart','relay-hy2')
    setup.run('systemctl','enable','hysteria-server')
    setup.run('systemctl','restart','hysteria-server')
    import time
    for attempt in range(60):
        try:controller.stats_api('online');return
        except OSError:time.sleep(1)
    raise RuntimeError('Hysteria пока не готова. Проверь DNS её домена и доступность TCP 80 для получения сертификата; ключи сохранены.')
