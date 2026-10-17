"""Fixed service templates. User input never becomes shell commands."""

CURRENT='/opt/relay-panel/current'
HARDEN='''NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
'''
MTPROXY_HARDEN=HARDEN.replace('AF_UNIX AF_INET AF_INET6','AF_UNIX AF_INET AF_INET6 AF_NETLINK')

def units():
    result = {
'relay-helper.service':f'''[Unit]
Description=Relay Panel local key controller
After=network.target
[Service]
ExecStart=/usr/bin/python3 {CURRENT}/panel/helper.py
Restart=on-failure
RuntimeDirectory=relay-helper
RuntimeDirectoryMode=0750
Group=relayadmin
UMask=0077
{HARDEN}ReadWritePaths=/etc/relay-panel /etc/tproxy-server /etc/mtproxy /run/relay-helper
[Install]
WantedBy=multi-user.target
''',
'relay-panel.service':f'''[Unit]
Description=Telegram WEB proxy control panel
After=relay-helper.service
Requires=relay-helper.service
[Service]
User=relayadmin
Group=relayadmin
WorkingDirectory={CURRENT}/panel
ExecStart=/usr/bin/gunicorn --bind 127.0.0.1:8082 --workers 1 --threads 4 --timeout 90 app:app
Restart=on-failure
UMask=0077
{HARDEN}ReadWritePaths=/var/lib/relay-panel
CapabilityBoundingSet=
IPAddressDeny=any
IPAddressAllow=localhost
[Install]
WantedBy=multi-user.target
''',
'tproxy-server.service':f'''[Unit]
Description=Telegram WEB transport relay
After=network-online.target mtproxy.service tproxy-firewall.service
Wants=network-online.target mtproxy.service
Requires=tproxy-firewall.service
[Service]
User=tproxy
Group=tproxy
LoadCredential=profiles.json:/etc/tproxy-server/profiles.json
ExecStart=/usr/local/bin/tproxy-server -config /etc/tproxy-server/config.json
Environment=TPROXY_ACCOUNTING_FILE=/var/lib/tproxy-accounting/usage.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
LimitNOFILE=1048576
UMask=0027
{HARDEN}ReadWritePaths=/var/lib/tproxy-accounting
PrivateDevices=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
IPAddressDeny=any
IPAddressAllow=localhost
[Install]
WantedBy=multi-user.target
''',
'mtproxy.service':f'''[Unit]
Description=Official Telegram MTProxy backend
After=network-online.target tproxy-firewall.service
Wants=network-online.target
Requires=tproxy-firewall.service
[Service]
User=mtproxy
Group=mtproxy
WorkingDirectory=/opt/MTProxy
EnvironmentFile=/etc/mtproxy/mtproxy.env
ExecStart=/usr/bin/python3 {CURRENT}/panel/backend.py
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
{MTPROXY_HARDEN}PrivateDevices=true
[Install]
WantedBy=multi-user.target
''',
'tproxy-firewall.service':'''[Unit]
Description=Keep Telegram backend ports local
After=nftables.service
PartOf=nftables.service
Before=mtproxy.service tproxy-server.service
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=-/usr/sbin/nft delete table inet tproxy_backend
ExecStart=/usr/sbin/nft -f /etc/tproxy-server/firewall.nft
ExecReload=-/usr/sbin/nft delete table inet tproxy_backend
ExecReload=/usr/sbin/nft -f /etc/tproxy-server/firewall.nft
[Install]
WantedBy=multi-user.target
''',
'relay-refresh.service':f'''[Unit]
Description=Refresh official Telegram routing configuration
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {CURRENT}/manage.py refresh
{HARDEN}ReadWritePaths=/etc/mtproxy
''',
'relay-refresh.timer':'''[Unit]
Description=Daily Telegram routing refresh
[Timer]
OnBootSec=15min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
Persistent=true
[Install]
WantedBy=timers.target
'''}
    for name in ('mtproxy.service','tproxy-server.service','relay-refresh.service','relay-refresh.timer'):
        result[name]=result[name].replace('[Unit]\n','[Unit]\nConditionPathExists=!/var/lib/relay-migration/blocked\n',1)
        if name.endswith('.service'):
            result[name]=result[name].replace('[Service]\n',f'[Service]\nExecCondition=+/usr/bin/python3 {CURRENT}/panel/migration_state.py --can-start\n',1)
    return result

FIREWALL='''table inet tproxy_backend {
 chain local_backend {
  type filter hook input priority -10; policy accept;
  iifname != "lo" tcp dport { 2398, 8888 } drop
 }
}
'''

def caddyfile(domain,email=''):
    email_line=f' email {email}\n' if email else ''
    return '''{\n'''+email_line+''' servers {
  protocols h1 h2
  timeouts {
   read_header 10s
   read_body 60s
  }
 }
}
'''+domain+''' {
 encode gzip
 header -Via
 @panel path /control /control/*
 handle @panel {
  reverse_proxy 127.0.0.1:8082
 }
 handle {
  reverse_proxy 127.0.0.1:8080 {
   transport http {
    response_header_timeout 40s
   }
  }
 }
 handle_errors {
  @proxy_error expression {http.error.status_code} == 502 || {http.error.status_code} == 503
  handle @proxy_error {
   rewrite * /maintenance
   reverse_proxy 127.0.0.1:8082
  }
 }
}
'''
