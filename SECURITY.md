# Security

Do not disclose live proxy secrets, owner setup codes, TOTP seeds, recovery codes, cookies, private keys, databases, backups or client IP histories in public Issues or screenshots.

For a suspected vulnerability, use the repository's **Security → Advisories → Report a vulnerability** if private reporting is enabled. Otherwise open an Issue that only asks for a private contact channel; do not include exploit details or sensitive files in that public request.

## Security boundaries

- Caddy is the public HTTPS endpoint. The panel and relay listeners are loopback-only. MTProxy backend ports have separate nftables ingress restrictions.
- The HTTP panel runs as `relayadmin`. A root helper accepts a fixed set of local Unix-socket operations after checking Linux peer credentials. A compromise of the panel can still expose operator-managed proxy keys and accounting; keep the panel and OS updated.
- The owner code grants initial setup access. Keep it private. It expires after 24 hours and is rejected after an owner exists.
- The landing page has no link to the panel; the panel URL is not a substitute for authentication.
- Login rate limiting affects administrator login only. Suspicion warnings do not automatically sanction proxy users.
- Data is stored on the VPS. Removing a profile revokes its access but does not erase all historical accounting or backups.
- Upstream dependencies and OS security updates remain part of the operator's responsibility.

Only use an expendable GitHub Actions runner for `tests/smoke_ubuntu.py`: it installs software and changes system configuration. Never run it on a personal workstation or production VPS.
