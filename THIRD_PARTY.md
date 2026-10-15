# Components and attribution

This repository contains its own installer, control panel, and optional relay accounting additions. It does not bundle the upstream relay or MTProxy repositories or redistribute them under the project's MIT license.

| Component | Source | Handling |
|---|---|---|
| Telegram WEB relay | https://github.com/telegramdesktop/tproxy-server | Downloaded at the commit in `installer.py`, verified by SHA-256, then patched locally for accounting. Consult upstream for its terms. |
| MTProxy | https://github.com/TelegramMessenger/MTProxy | Downloaded at a fixed commit and built locally. GNU GPL v2 terms apply to that component; see upstream license. |
| Caddy | https://github.com/caddyserver/caddy | Ubuntu package; upstream Apache-2.0. |
| Hysteria 2 | https://github.com/HyNetworks/hysteria | Optional official binary pinned with SHA-256 in `hysteria_install.py`; upstream MIT. |
| age | https://github.com/FiloSottile/age | Ubuntu package for X25519 encrypted snapshots; upstream BSD-3-Clause. |
| rclone | https://rclone.org/ | Ubuntu package for Google Drive uploads; upstream MIT. |
| Flask / Werkzeug | https://palletsprojects.com/ | Ubuntu packages; upstream BSD licenses. |
| Gunicorn | https://github.com/benoitc/gunicorn | Ubuntu package; upstream MIT license. |
| python-qrcode / Pillow | https://github.com/lincolnloop/python-qrcode / https://python-pillow.org/ | Ubuntu packages; see respective upstream licenses. |
| Go / gorilla/websocket | https://go.dev/ / https://github.com/gorilla/websocket | Build tool and relay dependency; see respective upstream licenses. |

Service definitions in `units.py` are project-specific. The accounting patch is maintained against one upstream commit; upstream updates require a reviewed patch and new checksums, not an unreviewed download of the latest branch.

Telegram is a trademark of its respective owner. This independent project does not imply affiliation or endorsement.
