"""Install the fixed backup daemon, independent of optional Hysteria."""
from pathlib import Path
from units import HARDEN,CURRENT

def service():
    return f'''[Unit]
Description=Encrypted Relay backups to Google Drive
After=network-online.target relay-helper.service
Wants=network-online.target
[Service]
Group=relayadmin
ExecStart=/usr/bin/python3 {CURRENT}/panel/backup_control.py
Restart=on-failure
RuntimeDirectory=relay-backup
RuntimeDirectoryMode=0750
Environment=RELAY_BACKUP_TMP=/run/relay-backup
UMask=0077
{HARDEN}ReadWritePaths=/var/lib/relay-backup /run/relay-backup /var/lib/relay-migration
MemoryMax=768M
TasksMax=64
[Install]
WantedBy=multi-user.target
'''

def install(setup):
    setup.directory('/var/lib/relay-backup',mode=0o700)
    setup.directory('/var/lib/relay-migration','root','relayadmin',0o750)
    setup.write('/etc/systemd/system/relay-backup.service',service())
