"""Pinned official AmneziaWG 3.1 userspace implementation; no DKMS or Docker."""
import os
from pathlib import Path
import shutil
import tarfile
from units import CURRENT,HARDEN

GO_VERSION='1.25.14'
GO_SHA256='a21ae5633a269bcd7e90cf767e48225633795e99d831742cbf3397064fee7712'
ENGINE_VERSION='v3.1.20260828'
ENGINE_COMMIT='b5928efb6ca19f0153958460c3d141f04abc5c2e'
ENGINE_SHA256='10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4'
TOOLS_VERSION='v3.1.20260812'
TOOLS_COMMIT='ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
TOOLS_SHA256='22438f231d39ea27e4bdc69707ec3103357f3cecc9ad3eecba18a61e5b39c9b9'


def extract_tools(setup,archive,work):
    # Upstream's wg-quick directory contains a convenience symlink to ../wg.
    # We do not install wg-quick. Omit exactly that link; keep the general
    # source extractor's rejection of all other links and unsafe paths intact.
    regular=work/'tools-regular.tar'
    allowed=f'amneziawg-tools-{TOOLS_COMMIT}/src/wg-quick/awg'
    with tarfile.open(archive) as source,tarfile.open(regular,'w') as target:
        for item in source:
            if item.issym() and item.name==allowed and item.linkname=='../wg':continue
            if not (item.isdir() or item.isfile()):raise RuntimeError('Неожиданная ссылка в исходниках AmneziaWG Tools')
            target.addfile(item,source.extractfile(item) if item.isfile() else None)
    return setup.extract(regular,work/'awg-tools')


def ask_options(setup,options):
    if options.get('awg_domain'):return
    if setup.ask('Установить также AmneziaWG 3.1? да / нет','нет',setup.yes_no)!='да':return
    host=setup.ask('Домен AmneziaWG (например vpn.example.com)',validate=setup.domain_name)
    setup.check_dns(host,options['ip'])
    def port(value):
        if not value.isascii() or not value.isdecimal() or not 1024<=int(value)<=65535:raise ValueError('UDP-порт: от 1024 до 65535')
        value=int(value)
        if value==options.get('hy2_port'):raise ValueError('Порт уже выбран для Hysteria')
        setup.check_udp_port(value)
        return value
    number=setup.ask('UDP-порт AmneziaWG','51820',port)
    options.update(awg_domain=host,awg_port=number)


def units():
    harden=HARDEN.replace('AF_UNIX AF_INET AF_INET6','AF_UNIX AF_INET AF_INET6 AF_NETLINK')
    gate=f'ExecCondition=+/usr/bin/python3 {CURRENT}/panel/migration_state.py --can-start\n'
    return {
      'amneziawg-server.service':f'''[Unit]
Description=AmneziaWG 3.1 userspace VPN
ConditionPathExists=!/var/lib/relay-migration/blocked
After=network-online.target
Wants=network-online.target
[Service]
{gate}ExecStart=/usr/bin/python3 {CURRENT}/panel/awg_network.py
Restart=on-failure
RestartSec=5
RuntimeDirectory=relay-awg
RuntimeDirectoryMode=0700
UMask=0077
{harden}ReadWritePaths=/var/lib/relay-awg /run/relay-awg /run/amneziawg
CapabilityBoundingSet=CAP_NET_ADMIN
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
''',
      'relay-awg.service':f'''[Unit]
Description=AmneziaWG peers and traffic accounting
ConditionPathExists=!/var/lib/relay-migration/blocked
After=amneziawg-server.service
Requires=amneziawg-server.service
[Service]
{gate}Group=relayadmin
ExecStart=/usr/bin/python3 {CURRENT}/panel/awg_control.py
Restart=on-failure
RestartSec=5
RuntimeDirectory=relay-awg-control
RuntimeDirectoryMode=0750
UMask=0077
{harden}ReadWritePaths=/var/lib/relay-awg /run/relay-awg-control /run/amneziawg
CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN
MemoryMax=128M
[Install]
WantedBy=multi-user.target
'''}


def install(setup,options,work):
    if not options.get('awg_domain'):return
    if not Path('/dev/net/tun').exists():raise RuntimeError('Для AmneziaWG нужен доступный /dev/net/tun. Проверь поддержку TUN у хостера.')
    if options.get('hy2_port')==options['awg_port']:raise ValueError('AmneziaWG и Hysteria нужны разные UDP-порты')
    print('Собираю официальную AmneziaWG 3.1…')
    for name,repo,commit,checksum in [('engine','amneziawg-go',ENGINE_COMMIT,ENGINE_SHA256),('tools','amneziawg-tools',TOOLS_COMMIT,TOOLS_SHA256)]:
        archive=work/(name+'.tar.gz');setup.download(f'https://codeload.github.com/amnezia-vpn/{repo}/tar.gz/{commit}',archive,checksum)
        source=extract_tools(setup,archive,work) if name=='tools' else setup.extract(archive,work/('awg-'+name))
        if name=='engine':
            archive=work/'go.tar.gz';setup.download(f'https://go.dev/dl/go{GO_VERSION}.linux-amd64.tar.gz',archive,GO_SHA256)
            toolchain=setup.extract(archive,work/'awg-toolchain')
            env={**os.environ,'GOTOOLCHAIN':'local','GOSUMDB':'sum.golang.org','GOPROXY':'https://proxy.golang.org',
                 'GOROOT':str(toolchain),'GOENV':'off','GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0',
                 'GOCACHE':str(work/'go-cache'),'GOPATH':str(work/'go-path')}
            setup.run(str(toolchain/'bin/go'),'build','-mod=readonly','-trimpath','-o',str(work/'amneziawg-go'),'.',cwd=source,env=env)
        else:
            setup.run('make','-C',str(source/'src'),'-j2')
            # Upstream builds `wg`; its install target renames it to `awg`.
            shutil.copyfile(source/'src/wg',work/'awg')
    for name in ('amneziawg-go','awg'):
        target=Path('/usr/local/bin')/name;pending=target.with_suffix('.new')
        shutil.copyfile(work/name,pending);pending.chmod(0o755);pending.replace(target)
    setup.directory('/var/lib/relay-awg',mode=0o700)
    previous=Path('/var/lib/relay-awg/previous-forwarding')
    if not previous.exists():setup.write(previous,Path('/proc/sys/net/ipv4/ip_forward').read_text(),mode=0o600)
    setup.directory('/run/amneziawg',mode=0o700)
    # Runtime directory for the engine must exist again after a reboot.
    setup.write('/etc/tmpfiles.d/relay-awg.conf','d /run/amneziawg 0700 root root -\n')
    setup.write('/etc/sysctl.d/80-relay-awg.conf','net.ipv4.ip_forward=1\n')
    setup.run('sysctl','-w','net.ipv4.ip_forward=1')
    import sys
    sys.path.insert(0,str(Path(CURRENT)/'panel'))
    from awg_control import Controller
    Controller(initial=options)
    for name,body in units().items():setup.write('/etc/systemd/system/'+name,body)


def activate(setup,options,standby=False):
    if not options.get('awg_domain'):return
    setup.run('systemctl','enable','amneziawg-server','relay-awg')
    if standby:return
    setup.run('systemctl','restart','amneziawg-server','relay-awg')
    import time
    from awg_routes import helper
    for attempt in range(30):
        try:helper({'op':'migration_ready'});return
        except (OSError,ValueError):time.sleep(1)
    raise RuntimeError('AmneziaWG не стала готова. Проверь relay-panel status; ключи сохранены.')
