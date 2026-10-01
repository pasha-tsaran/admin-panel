# Domainless single-server VLESS MVP (Debian 13)

As of 2026-09-13 the existing foreign VPS at `88.218.94.3` runs Xray 26.3.27 on TCP/443,
Kenai web/helper on the private WireGuard address `10.66.66.1:8443`, and PostgreSQL 17
on `127.0.0.1:5432`. The public HTTPS origin for the Windows app is
`https://88.218.94.3:9443`. This remains a **direct foreign-server** MVP; it is not the
planned Russian-ingress cascade and cannot guarantee resistance to TSPU throttling or blocking.

Nginx exposes only `POST /api/v1/activate` on 9443. `/login` and the rest of the admin
panel return 404 publicly. TCP/80 serves only `/.well-known/acme-challenge/` for the IP
certificate and returns 404 elsewhere. Xray's TCP/443 listener and old VPN users were not
reconfigured during the API/database migration. Public Nginx verifies the private Kenai CA
when proxying to `10.66.66.1:8443` and supplies a sanitized client IP for the activation
rate limiter.

The IP certificate is a six-day Let's Encrypt certificate, currently renewed by
`kenai-certbot-renew.timer` twice daily. `kenai-vpn-backup.timer` makes a daily encrypted
PostgreSQL/configuration backup; `kenai-vpn-expire-subscriptions.timer` disables expired
credentials. New subscriptions issue only VLESS. Existing WireGuard and AmneziaWG users
remain operational and their files remain in backups through `KENAI_BACKUP_PROTOCOLS`.

## Verification

Run on the server:

```bash
systemctl is-active xray kenai-vpn-helper kenai-vpn-web postgresql nginx
systemctl is-active kenai-certbot-renew.timer kenai-vpn-backup.timer kenai-vpn-expire-subscriptions.timer
nginx -t
xray run -test -config /usr/local/etc/xray/config.json
/opt/kenai-vpn/certbot-venv/bin/certbot certificates --cert-name 88.218.94.3
```

The pip-installed Certbot binary is `/opt/kenai-vpn/certbot-venv/bin/certbot`, not
`/usr/bin/certbot`. Its renewal simulation was verified with:

```bash
/opt/kenai-vpn/certbot-venv/bin/certbot renew --cert-name 88.218.94.3 --dry-run --run-deploy-hooks --no-random-sleep-on-renew
```

The encrypted PostgreSQL backup was restored into a separate temporary PostgreSQL database
and counts for users/devices/administrators were verified. The temporary restore database
and plaintext extraction were removed afterward. An encrypted copy and separate recovery
key are also stored under `C:\backup\Kenai\2026-09-13` on the operator PC; the key's ACL
permits only the operator, Administrators and SYSTEM. Never commit or transmit either file.

## Rollback

Before any rollback, take another encrypted PostgreSQL backup. The old SQLite database and
the final pre-cutover encrypted archive are retained. The old web environment is
`/etc/kenai-vpn/web-sqlite-prepg-20260913.env`. To return to the old web/helper package,
stop the web and helper, move the `10-postgres-mvp.conf` drop-ins from their respective
`kenai-vpn-web.service.d`, `kenai-vpn-helper.service.d`, and
`kenai-vpn-expire-subscriptions.service.d` directories into a protected backup folder,
restore the old environment as `/etc/kenai-vpn/web.env`, run `systemctl daemon-reload`,
then start the helper and web. Do not copy PostgreSQL rows back into SQLite; any changes
after cutover need an explicit reconciliation decision. Reopening the old app while the
new app is still writing would split the source of truth.

The public API can be closed independently by removing only the `kenai-api-ip` Nginx site
and the exact TCP/9443 firewall rule after making a firewall backup. Do not remove or
change TCP/443, the Xray configuration, or the existing WireGuard/AWG rules as part of an
API rollback.

## Still to verify before customer distribution

- Create a real subscription in the authenticated admin panel and test activation with its
  12-digit key from the newly configured Windows build.
- Connect, confirm the foreign exit IP, and test DNS/IPv6 leak behavior and reconnection on
  home broadband and mobile operators.
- Sign the Windows installer; the current local test artifact is unsigned.
- Add a Russian Debian ingress and a second path before claiming the cascade is complete.
