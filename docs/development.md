# Development guide

## Safe change sequence

1. Read `AGENTS.md` and the relevant architecture document.
2. Add or update a test that expresses the desired behavior.
3. Change one layer at a time and preserve dependency direction.
4. Add an Alembic migration for schema changes.
5. Run all quality commands from `README.md`.
6. Review generated output for secrets before committing.

## Naming

- Stable user/device slugs use lowercase ASCII letters, digits, and hyphens.
- Human-readable names may use Unicode.
- Domain actions use verbs such as `create_device`, `disable_protocol`, and `issue_package`.
- Adapters are named by capability, not implementation accident.

## Testing boundaries

- Unit tests cover domain and application behavior.
- Integration tests use a temporary SQLite database and mock VPN adapter.
- Web tests verify authentication, CSRF, authorization, and safe output.
- No test may invoke `wg`, `nft`, `systemctl`, or contact the VPS.
