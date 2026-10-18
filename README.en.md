# AmneziaWG 3.1 support

Optional AmneziaWG 3.1 installation, per-user QR and `.conf` export, traffic accounting, quotas and expiry. Encrypted backups preserve server and peer keys so existing configs work after recovery to a new IP with the same domain and UDP port. See [AmneziaWG operations and recovery](docs/AMNEZIA.md) (Russian).

**New:** optional Hysteria 2 with individual users, traffic accounting, and age-encrypted Google Drive backups for both panels. Manual, change-triggered and daily snapshots are supported. Keep the downloaded recovery key separately. See [backup and migration instructions (Russian)](docs/backups.md). The installer asks for a separate Hysteria domain and UDP port (default 24443); both domains must resolve to the server.

# Telegram WEB Proxy + Relay Panel

The **Перенос** (Migration) page creates a verified final encrypted backup, stops managed Telegram/Hysteria services, keeps the control panel available, and prevents accidental service startup after reboot. Use `relay-panel migration status|stop|resume` over SSH. Recovery supports `--standby` to import data without enabling client traffic or automatic backups. Separately installed Amnezia is not managed. See [migration and rollback instructions (Russian)](docs/backups.md).

[Русский](README.md) · English

Self-hosted Telegram WEB proxy with an interactive installer and a private browser control panel. Designed for a small circle of family and friends.

**Release 0.5.0. Requires a Telegram client that supports the WEB proxy type.** This is not an MTProto/SOCKS5 configuration and is not an official Telegram product. It uses the official proof-of-concept [tproxy-server](https://github.com/telegramdesktop/tproxy-server). Connectivity depends on the client and network.

## Install

On a **dedicated, clean Ubuntu 24.04 LTS amd64 VPS**, open a root shell and run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cveloy102/telegram-webproxy-panel/main/install.sh)
```

For a non-root account, run `sudo -i` first. If curl is missing, install it with `apt-get update && apt-get install -y curl python3`.

For disaster recovery, choose **2 — восстановить из резервной копии**. Supply a downloaded `.tar.gz.age` archive and your private `relay-recovery-key.txt`. The wizard imports data with traffic disabled, waits for DNS and validated HTTPS, and requires confirmation that the old server is stopped before enabling clients. Re-run the installer after an interruption to resume; the private identity is not saved by the wizard. See [recovery instructions](docs/backups.md#мастер-восстановления-на-новом-vps).

Requirements: systemd, public IPv4, 1 GB RAM minimum (2 GB recommended), 2 GB free disk space, reachable/free TCP ports 80 and 443, and a domain with exactly one A record pointing to the VPS. Remove AAAA records for that hostname; use DNS-only mode if using Cloudflare. The installer does not modify provider DNS or firewall rules.

The wizard asks for the hostname, public IPv4, landing-page title, optional Telegram contact, landing-page theme and optional certificate email. It installs the relay, MTProxy, Caddy HTTPS, panel and systemd services. Secrets are generated on the server.

Open the printed panel URL, enter the one-time owner code, choose a password, enroll TOTP and save the recovery codes. Create a key and share its link or QR. A first personal key is created automatically. The interface and wizard are currently in Russian.

## Features

- Individual keys, labels and groups; Telegram links and locally generated QR codes.
- Manual pause/resume, secret rotation, profile deletion and global pause.
- Last connection/activity, traffic and IP history grouped by subnet.
- Configurable warnings about concurrent subnets and traffic, without automatic sanctions.
- Password + TOTP, one-use recovery codes, secure cookies, CSRF/Origin checks.
- Two landing-page themes and an optional Telegram contact button.
- Re-run installer for health checks, backups or updates that retain keys and settings.

There is **no notification bot**. Alerts are stored in the panel; no off-panel notifications are sent.

## Limits

Up to 16 active MTProxy secrets. Key-list changes briefly restart the proxy. Online means session activity within 90 seconds; refreshes happen roughly every five seconds. Traffic is relay payload accounting, not VPS billing. Session traffic follows its most recently authenticated source IP. Daily counters retain 90 days, hourly 48 hours, alert events 180 days; known IPs and cumulative counters persist. Times are UTC. Profile deletion revokes access but is not a complete erasure of historical accounting.

## Operations

```bash
relay-panel status
relay-panel backup
relay-panel setup-code
```

The last command only works before an owner account exists. Repeat the install command to update. Updates create root-only backups and attempt rollback if activation fails. A later public HTTPS failure leaves working services and data intact for repair.

Backups contain secrets. Do not post databases, QR codes, credentials, backups or IP lists in Issues. See [SECURITY.md](SECURITY.md), [operations](docs/OPERATIONS.md) and [troubleshooting](docs/TROUBLESHOOTING.md).

Dependencies are pinned where built from source; their SHA-256 values are checked. Ubuntu packages, GitHub, Telegram routing endpoints, certificate authorities and public IP lookup services are contacted during installation/maintenance. No built-in analytics or reporting to the project author.

## License

Installer, panel and added accounting code: [MIT](LICENSE). Dependencies have separate licenses: [THIRD_PARTY.md](THIRD_PARTY.md).
