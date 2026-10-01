# Administrative console

The console is a server-rendered FastAPI/Jinja interface over the existing application services.
It does not introduce a second source of truth: users, devices, subscriptions, nodes, sessions,
audit events, settings, notification deliveries, API tokens, and metrics are persisted through
SQLAlchemy. Empty states say that data is unavailable instead of inventing chart points or status.

## Sections and permissions

The fixed sidebar exposes only sections granted to the current administrator. The built-in roles
are `super_admin`, `admin`, `moderator`, and `custom`; a custom role stores an explicit subset of
`users`, `issuance`, `servers`, `audit`, `administrators`, `settings`, `backups`, `api_tokens`, and
`billing`. Every request is checked on the server; hiding a link is only a usability feature.

Changing administrator access, revoking a session or API token, confirming a subscription, and
registering a node require the acting administrator's password and current TOTP. Access changes
revoke the target's other active sessions. API-token plaintext is returned once with
`Cache-Control: no-store`; only its SHA-256 hash and a short display prefix remain in the database.

The new issuance form creates a real user, device, AWG/VLESS credentials, and one-time provisioning
package through `AdminService`. It rejects a server selection that the current helper cannot
actually target. Legacy WireGuard records remain readable and revocable, but the new UI never
offers WireGuard issuance.

## Metrics and notifications

`kenai-console-maintenance collect-metrics` records health, connections, traffic, and host CPU,
memory, disk, and load values. The root helper reads bounded Linux `/proc` and filesystem metrics
without accepting paths or commands from HTTP. Missing values remain `NULL`. Retention is 30 days
by default (`KENAI_METRICS_RETENTION_DAYS`) and chart queries are capped at 30 days.

Install and enable `kenai-console-metrics.timer` only as part of a reviewed deployment; it runs the
collector every five minutes. `kenai-console-notifications.timer` retries the delivery queue every
minute. Telegram recipients and categories are stored in PostgreSQL, but the bot token is accepted
only from `KENAI_NOTIFICATION_TELEGRAM_BOT_TOKEN`. Without it, tests and alerts remain visibly
queued. Retry attempts and sanitized error classes are recorded; token values are never logged.

Supported categories are server unavailable, high load, subscription expiring, backup failure,
suspicious login, and critical administrator action. The collector queues the first three with a
cooldown. Critical RBAC, session, API-token, and node-registration actions queue alerts directly.
The root-only backup job can use the same application service/CLI boundary to report a failure; the
web process itself cannot run a backup.

## Subscriptions and payment boundary

Plans and subscriptions form a provider-neutral boundary. No payment provider, webhook, or fake
transaction is included. An administrator can explicitly confirm a subscription after password and
TOTP re-authentication; the immutable subscription event records that this was manual and that no
provider was involved.

## Node onboarding

Onboarding is staged: connectivity and certificate-pin verification, capability preview, explicit
confirmation, registration, post-registration health, then database commit. The HTTPS agent URL
must use a literal IP address and a fixed allowlisted path. The client rejects URL credentials,
queries, fragments, arbitrary hostnames, redirects, and certificate mismatches. If health or the
database step fails after registration, the agent rollback endpoint is called and the attempt is
marked `rolled_back` or `failed`. There is no arbitrary SSH or shell execution path.

## Database upgrade and rollback

Revision `c4f8d2a71e90` adds the console foundation. Before production upgrade, stop the web service
and timers, take and verify an encrypted PostgreSQL backup, record `alembic current`, and deploy the
application and migration as one reviewed artifact. Run `alembic upgrade head`, start the helper and
web service, then the two timers, and verify login, an empty/non-empty dashboard, RBAC denial, metric
collection, and a queued notification without exposing secrets.

Rollback is an application/database pair: stop web and timers, restore the pre-upgrade database and
the previous release, then start the previous units. The migration has a reversible downgrade for a
development database, but an in-place production downgrade is not the recovery mechanism. Node
registration also has its own agent rollback and does not authorize a production deployment.

## Local verification

Use `KENAI_VPN_BACKEND=mock` and a disposable database, then run:

```powershell
alembic upgrade head
kenai-admin create-admin
kenai-console-maintenance collect-metrics
ruff format --check .
ruff check .
mypy src
pytest
```

The responsive views must be checked at desktop and narrow mobile widths, including keyboard focus,
forms, modal/details confirmation controls, empty states, and long tables. Production installation,
service enablement, and VPS mutation require separate explicit authorization.
