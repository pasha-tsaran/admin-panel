# Security design

## Access boundary

The VLESS-only production panel binds to `127.0.0.1:8443` and is reached through an authenticated
SSH port forward. PostgreSQL and the Xray Stats API are loopback-only as well. Authentication
remains mandatory inside the SSH tunnel; port 8443 must not be opened in the public firewall.

## Authentication

- Argon2id password hashing;
- TOTP second factor;
- opaque server-side sessions;
- HttpOnly, Secure, SameSite=Strict cookie in production;
- per-session CSRF token;
- login throttling and temporary lockout;
- session expiry and explicit revocation.
- initial administrator creation is committed only after a live TOTP code verifies the newly
  enrolled secret;

## Secrets

- encryption at rest using a deployment-provided key;
- no credentials in logs, audit metadata, URLs, exceptions, or list pages;
- device-statistics responses exclude public keys, endpoints, UUIDs, and client material;
- provisioning token plaintext is never stored;
- package payload is short-lived and purged after use/expiry;
- production backups must be encrypted separately.
- the backup encryption key must be exported to offline encrypted storage and never included in a
  backup archive;
- restore extraction is restricted to a new staging directory; HTTP handlers cannot overwrite live
  database or VPN files.
- REALITY private keys remain in root-readable node specification/configuration files and are not
  entered into the web panel. Only public inter-server parameters are encrypted in PostgreSQL.

## Administrative actions

Disable and enable are reversible. Revoke invalidates credentials and requires confirmation.
Deletion requires the literal `DELETE` confirmation. Device deletion is allowed only after its
credentials have been revoked. User deletion performs a controlled sequence: each non-revoked
WireGuard/VLESS credential is revoked and committed separately, and the user is deleted only after
all revocations succeed. A partial helper failure leaves the user in place and preserves every
already confirmed revocation in the database, preventing the database from forgetting credentials
that still exist in WireGuard or Xray.

Administrator creation, activation/deactivation, password changes, and TOTP replacement require
an authenticated session, CSRF protection, and password-plus-TOTP reauthentication where the
acting administrator authorizes a sensitive change. A new administrator remains inactive until
the new TOTP enrollment is confirmed. During TOTP replacement the old secret stays active until
the pending secret is confirmed, preventing accidental lockout. An administrator cannot disable
their own account or the last active administrator.

An application user's activation key remains stable when a subscription expires or is renewed.
The activation API rejects expired subscriptions, while the expiry timer disables their three
protocols. An authenticated CSRF-protected renewal assigns a new expiry and restores WireGuard,
AmneziaWG, and VLESS access without replacing the key. Redirect targets derived from browser
navigation headers are accepted only when they belong to the current origin.

Audit CSV exports contain only timestamps, action/outcome, non-secret object labels, administrator,
and correlation identifiers. JSON metadata is intentionally excluded from exports.

## HTTP controls

- strict Content Security Policy;
- frame denial;
- content-type protection;
- referrer suppression;
- CSRF validation;
- bounded form fields;
- generic authentication errors.
