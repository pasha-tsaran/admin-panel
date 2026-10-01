# Threat model

## Protected assets

- administrator credentials and sessions;
- WireGuard private client material;
- VLESS UUIDs and client URIs;
- ability to mutate server VPN state;
- audit integrity and availability of SSH/VPN services.

## Main threats and controls

| Threat | Control |
|---|---|
| URL/IP discovery | Panel is loopback-only and reached through an authenticated SSH port forward |
| Password compromise | Argon2id, TOTP, throttling, session expiry |
| CSRF | Per-session CSRF token and SameSite cookies |
| Web process compromise | Unprivileged process; strict Unix-socket helper protocol |
| Command injection | Typed operation allowlist; no shell strings from HTTP |
| Credential disclosure | Encryption at rest, one-time provisioning, redacted logs |
| Accidental mass revocation | Per-device credentials and confirmation workflow |
| Database corruption | Foreign keys, migrations, transactional updates, backups |
| Firewall lockout | Separate deployment approval and timed rollback |
| Supply-chain compromise | Pinned dependency ranges, lock strategy before deployment, CI checks |
| Exit failure leaks a direct route | Russian ingress uses blackhole as first outbound and every country balancer has a blackhole fallback |
| REALITY fallback abused as a public relay | Target is operator-reviewed; target/SAN/ASN preflight is mandatory before deployment |

## Accepted MVP limitations

- Public recipient download links are not exposed until a trusted HTTPS domain or equivalent delivery mechanism exists.
- VLESS traffic accounting requires a later local Xray statistics integration.
- Production helper is deliberately excluded from the first local implementation.
- A public multi-node management agent is not exposed in the first production deployment. Exit
  changes use reviewed create-only candidates, native Xray validation and automatic rollback.
- REALITY reduces obvious protocol fingerprints but does not guarantee that a provider will treat
  the flow as a visit to a specific domain or that an IP address cannot be blocked.
