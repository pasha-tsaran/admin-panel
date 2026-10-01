# Deployment plan (production services not yet installed)

> Current target: PostgreSQL. References below to the original SQLite deployment describe historical
> gates only. A new installation must provision PostgreSQL, run Alembic to `head`, and use
> `kenai-admin import-sqlite` only when legacy MVP data must be retained. The local-PC workflow is
> documented in [`local-control-plane.md`](local-control-plane.md).

Create a reviewed source artifact with `deploy/build-staging.ps1`. The builder runs the complete
local quality gate, copies only the explicit source/documentation/deployment allowlist, rejects
secret and runtime extensions, embeds `BUILD-MANIFEST.txt`, and prints the archive SHA256. Never
deploy from `incoming/`, a previous archive, or an unverified working directory.

Production deployment is intentionally deferred until the local MVP and tests pass.

Planned topology:

- unprivileged `vpnadmin` system user;
- application bound only to `127.0.0.1:8443` and reached with an SSH port forward;
- TLS using a locally managed administrative CA until a domain is available;
- nftables exposes no administration port; only the VLESS ingress and SSH recovery path are public;
- root-owned helper socket with a narrow group permission;
- application and helper as separate hardened systemd units;
- database and encrypted backups outside the code directory;
- no Docker requirement on the 2 GiB VPS.

Deployment must include backup, preflight, rollback timer for firewall changes, independent SSH verification, and post-reboot verification. Exact commands will be written only after the production adapter passes review.

## Xray traffic statistics gate

## AmneziaWG 2.0 deployment gate

The application now supports an independent AWG credential per device, but production activation
is a separate reviewed change. Before enabling it, verify the installed `awg` and `awg-quick`
binaries, create `/etc/amneziawg/awg0.conf` with mode `0600`, reserve `10.67.67.0/24`, and permit
only the selected UDP listen port (default `585`) in nftables. The server and every issued client
must use exactly the same Jc/Jmin/Jmax, S1-S4 and H1-H4 values. AWG 2.0 also supports optional
I1-I5 custom signature packets. Keep them empty until a reviewed tag expression is validated by
the exact pinned `awg-quick`/userspace backend and a supported AmneziaVPN client; never insert an
untested signature merely to make the configuration look like AWG 2.0.

Take protected snapshots of the database, helper environment, nftables ruleset and AWG config.
Apply migration `c2a4e6f91b30`, add the `KENAI_HELPER_AMNEZIAWG_*` values from
`deploy/helper.env.example`, validate the helper settings, and test one newly issued device before
bulk issuance. Rollback restores the application/database pair and removes only the separately
created AWG interface and firewall rule; existing WireGuard and Xray configuration must remain
byte-for-byte unchanged.

AWG obfuscates WireGuard packet structure and is intended for networks that suppress recognizable
WireGuard traffic. It is not a guarantee against every DPI system, and ordinary WireGuard remains
available as a separate protocol.

Application deployment does not automatically edit the live Xray configuration. Real VLESS
traffic counters require a separately reviewed operational change that:

- enables Xray `stats`, `policy` user uplink/downlink/online counters, and an API inbound bound only to
  `127.0.0.1` (or `::1`);
- exposes only the StatsService needed by `statsquery` and `statsonline`;
- validates a metadata-preserving candidate with `xray run -test` before replacement;
- backs up the exact live JSON, preserves unmanaged inbounds/clients, and has a tested rollback;
- sets `KENAI_HELPER_XRAY_STATS_SERVER=127.0.0.1:10085` only after local traffic and online queries succeed;
- verifies that nftables and `ss` show no externally reachable Stats API listener.

The policy level used by managed clients must include `statsUserUplink`, `statsUserDownlink`, and
`statsUserOnline` set to `true`. The dashboard uses cumulative counters for traffic and the online
counter for the current VLESS device list. Until this gate is performed, the runtime panel is
unavailable. Never place UUID credentials in a diagnostic command or report.

## Administrator schema migration

Revision `c4f8d2a71e90` adds RBAC metadata, plans/subscriptions and immutable events, server metrics,
database-backed console settings, Telegram recipients/delivery attempts, hashed API tokens, and
staged node-onboarding attempts. Follow the paired application/database upgrade and restore plan in
[`admin-console.md`](admin-console.md). The metrics and notification timers are opt-in deployment
artifacts and must not be enabled before the new application and migration pass local verification.

Revision `8f4c2b91a7de` adds TOTP confirmation and pending-enrollment state. Before upgrading, stop
the web service, take a protected SQLite snapshot, verify `PRAGMA integrity_check` and the current
Alembic revision, then run `alembic upgrade head` as the database owner. Existing administrators
receive `totp_confirmed=true`. Rollback requires restoring the application package and database
snapshot together; do not downgrade a live database while the new package is running.

Encrypted application backups are implemented by the root-only `kenai-backup` command and the
`kenai-vpn-backup.timer` template. Installation must initialize and export the independent backup
key before enabling the timer. See `docs/backups.md`; restore always targets staging first.

## Helper preflight gate

Before installation, collect without changing the VPS:

- numeric UID/GID for the future unprivileged web account;
- exact regular-file paths and permissions for `wg0.conf` and the active Xray JSON;
- the existing Xray inbound tag, REALITY server name, public key, and short ID;
- absolute paths and versions of `wg`, `wg-quick`, `xray`, `systemctl`, and `nft`;
- native validation results for untouched configuration copies;
- confirmation that existing peers/clients have identifiers that will not collide with Kenai
  device references.

The templates under `deploy/` are review artifacts, not an authorization to install or start
services. Deployment requires a fresh backup, separate approval for file installation, a test
request with no mutation, and then one test device before bulk onboarding.

## Verified helper staging dry-run (2026-08-28)

The production adapters were installed into an isolated root-only staging virtual environment on
the VPS and exercised against temporary metadata-preserving copies of the live WireGuard and Xray
configuration files. Native `wg-quick strip` and `xray run -test` validation executed; runtime
`wg syncconf` and Xray service activation were intercepted by the staging executor.

Acceptance results:

- the next WireGuard address was `10.66.66.3/32`;
- the pre-existing Xray client count remained one after the issue/disable/enable/revoke cycle;
- eight runtime mutations were simulated and zero were executed;
- no generated credential was printed;
- SHA-256 hashes of both live source configurations remained unchanged.

This closes the adapter compatibility gate. It does not authorize starting the production helper
or mutating either live VPN configuration. The next gate is a separately reviewed, install-only
deployment of users, groups, directories, code, environment, and systemd unit with the unit left
disabled and inactive.

## Install-only helper gate

`deploy/install/01-install-helper-only.sh` prepares the production helper without starting or
enabling it. The script refuses pre-existing target paths, creates a timestamped root-only backup,
installs the root-owned application environment, creates the unprivileged `vpnadmin` identity and
the `kenai-vpn` socket group, derives only the public REALITY parameter in memory, and writes a
root-only helper environment. It then verifies the settings and systemd unit while requiring the
helper to remain disabled, inactive, and without a socket.

The unit runs as `root:kenai-vpn`: root is required for the narrowly allowlisted VPN mutations,
while the group ownership lets the future `vpnadmin` web process traverse the runtime directory
and connect to the group-owned Unix socket. The source, virtual environment, environment file,
state directory, and systemd unit remain root-owned and non-writable by the web process.

### Verified install-only result (2026-08-28)

The install-only script completed with exit code zero on the VPS. It created the production
environment and a protected backup at
`/var/backups/kenai-vpn/pre-helper-20260827T212248Z`. Post-install assertions confirmed:

- `kenai-vpn-helper.service` remained inactive and disabled;
- no helper socket was created;
- no VPN runtime mutation was executed;
- live WireGuard and Xray configuration hashes were unchanged;
- no private value was printed.

This result authorizes neither service start nor VPN credential mutation. The next gate is a
read-only installation audit followed, with separate approval, by a temporary helper start and a
health-only request from the exact unprivileged `vpnadmin` UID.

### Verified read-only installation audit (2026-08-28)

- `vpnadmin` is UID 987 with primary and only supplementary group `kenai-vpn` (GID 989).
- The systemd unit is loaded as `root:kenai-vpn` and remains inactive and disabled.
- The helper environment is `root:root` 0600; configuration, state, and backup directories are
  root-owned with the intended modes.
- No helper socket exists, settings validation succeeds, and there are no failed units.
- Both live VPN configurations still compare byte-for-byte with the pre-helper backup.

The next approved action must remain a start-only runtime test: no enablement and no mutation
operation. The helper must accept one health request from UID 987, preserve the live configuration
hashes, and then be stopped so its socket disappears.

### Verified helper runtime gate (2026-08-28)

- The helper started successfully and remained disabled.
- `/run/kenai-vpn` was `root:kenai-vpn` 0750 and `helper.sock` was
  `root:kenai-vpn` 0660.
- A health-only request from UID 987 reported WireGuard, Xray, and nftables active, both VPN
  services enabled, and zero failed units.
- No issue, enable, disable, or revoke request was sent.
- Live WireGuard and Xray configurations remained byte-for-byte equal to the pre-helper backup.
- The helper then stopped cleanly, removed its socket, and remained disabled; all existing VPN
  services stayed active and enabled.

The privileged-helper runtime gate is complete. The next phase is an install-only preparation of
the unprivileged web service, relational database, migrations, production secrets, and initial
administrator bootstrap. It must not start either service or change nftables until separately
approved.

## Web install-only gate

`deploy/install/02-install-web-only.sh` is the reviewed preparation step for the unprivileged web
service. It requires the helper to be inactive and performs the following without starting a
service:

- upgrades the installed application package and copies Alembic assets to a root-owned path;
- creates a root-generated application secret and an independent Fernet encryption key in
  `/etc/kenai-vpn/web.env` (`root:kenai-vpn` 0640);
- creates a local administrative CA plus a server certificate whose SAN is `127.0.0.1`, keeping
  the CA key root-only and allowing `vpnadmin` to read only the server key;
- bootstraps PostgreSQL and applies relational migrations as `vpnadmin`;
- installs and verifies `kenai-vpn-web.service`, leaving both web and helper inactive and disabled;
- does not create an administrator, open port 8443, change nftables, or start a listener.

The web unit binds only to `127.0.0.1:8443`, uses HTTPS and Secure cookies, and requires the
helper unit when it is eventually started. Connect from an operator PC with
`ssh -L 8443:127.0.0.1:8443 root@SERVER_IP` and open `https://127.0.0.1:8443`. Rollback before first start consists of quarantining
the web unit, environment, TLS material, Alembic assets, and new empty database, followed by a
daemon reload. Destructive deletion is not required.

### Verified web install-only result (2026-08-28)

- Alembic upgraded the new SQLite database to revision `36368bd3c193` (head).
- Web and helper remained inactive and disabled, and no TCP/8443 listener was created.
- The live WireGuard, Xray, nftables, helper environment, and helper unit hashes stayed unchanged.
- No firewall operation ran, no administrator was created, and no generated secret was printed.
- The install-only script completed with exit code zero.
- The independent database audit found all 11 expected relational tables, revision
  `36368bd3c193`, and zero administrators before bootstrap.

Before first administrator creation, the production CLI was strengthened so that it commits the
administrator row only after the operator enters a valid live six-digit code from the newly
enrolled TOTP secret. A failed verification leaves the database without that administrator.
