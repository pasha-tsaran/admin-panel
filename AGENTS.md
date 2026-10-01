# Kenai VPN Admin — contributor instructions

This file is the durable source of truth for developers and AI assistants working in this repository.

## Engineering baseline

1. Preserve a modular, layered architecture. UI, application use cases, domain models, persistence, and VPN integrations must not be coupled directly.
2. Prefer readable, typed, testable code over clever abstractions.
3. Keep all credentials and generated VPN material out of Git, logs, screenshots, exception messages, and ordinary list views.
4. Never execute arbitrary shell strings from HTTP input. Privileged VPN operations must use a strict operation allowlist and validated typed arguments.
5. The web process must remain unprivileged. Production VPN mutations belong in a separate privileged helper accessed through a protected Unix socket.
6. Database changes require an Alembic migration. Keep foreign keys, uniqueness constraints, indexes, and explicit relationships accurate.
7. Every device has independent WireGuard and VLESS credentials. Revoking one device must not affect another.
8. Existing production VPN configuration must not be modified by local development or automated tests.
9. Add or update tests and documentation with every behavioral change.
10. Before handing off work, run the documented quality checks and report anything that could not be verified.

## Source layout

- `src/kenai_vpn_admin/domain/`: business entities, enums, and domain rules; no FastAPI or SQLAlchemy imports.
- `src/kenai_vpn_admin/application/`: use cases and ports/interfaces.
- `src/kenai_vpn_admin/infrastructure/`: SQLAlchemy, crypto storage, mock and production adapters.
- `src/kenai_vpn_admin/web/`: routes, forms, dependencies, templates, and static assets.
- `src/kenai_vpn_admin/cli/`: administrative bootstrap and maintenance commands.
- `migrations/`: Alembic migrations.
- `tests/`: unit and integration tests; production services are never contacted.
- `docs/`: architecture, security, data model, API, deployment, and threat model.

## Required workflow

1. Read `README.md`, this file, and the relevant document under `docs/`.
2. Inspect existing tests and migrations before modifying behavior or schema.
3. Make the smallest cohesive change.
4. Run formatting, linting, type checks, and tests.
5. Never commit `.env`, databases, private keys, generated profiles, provisioning archives, or runtime logs.

## Definition of done

- Behavior is covered by tests.
- Schema changes include a reversible migration.
- No secrets appear in logs or responses outside explicit one-time provisioning flows.
- Authorization and CSRF boundaries are preserved.
- Documentation explains operational and rollback implications.
- `ruff check .`, `mypy src`, and `pytest` pass.
