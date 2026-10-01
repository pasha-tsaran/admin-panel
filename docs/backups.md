# Encrypted backups

`KENAI_BACKUP_PROTOCOLS` controls which existing VPN configuration files are included in a
production backup. It is deliberately separate from `KENAI_SUBSCRIPTION_PROTOCOLS`, which
controls credentials issued to new subscribers. On an upgraded server retaining old WireGuard
and AmneziaWG users, keep backup protocols as `wireguard,amneziawg,vless` even when new
subscriptions are VLESS-only.
On Debian 13, PostgreSQL backups invoke `/usr/lib/postgresql/17/bin/pg_dump`; the
`/usr/bin/pg_dump` wrapper is a symlink and is intentionally not used.

`kenai-backup` creates authenticated AES-256-GCM backups for the admin database, the configuration
and helper state files selected by `KENAI_BACKUP_PROTOCOLS`, and production environment
files. The backup key is separate from the archives and is never included in them.

## Production paths

- key: `/etc/kenai-vpn/backup.key` (`root:root`, mode `0600`);
- archives: `/var/backups/kenai-vpn-admin/*.kvbackup` (`root:root`, mode `0600`);
- daily timer: `kenai-vpn-backup.timer`;
- deployed daily retention: 30 successful archives (the CLI default is 14).

Initialize the key exactly once:

```bash
kenai-backup init-key
```

Create and immediately verify a backup:

```bash
kenai-backup create
kenai-backup verify /var/backups/kenai-vpn-admin/kenai-vpn-YYYYMMDDTHHMMSSZ.kvbackup
```

The key must be copied separately to offline encrypted storage. Losing both the server and this key
makes every `.kvbackup` archive intentionally unrecoverable. Never store the key beside exported
archives or commit it to Git.

## Restore workflow

The application deliberately has no command that overwrites live files. First decrypt and verify
into a new root-only staging directory:

```bash
kenai-backup extract BACKUP /root/kenai-restore-YYYYMMDDTHHMMSSZ
```

Review the manifest, restore `database/kenai.dump` into a new empty PostgreSQL database with
`pg_restore`, validate WireGuard/Xray candidates, and make a fresh backup of the current live state.
Applying a staged restore requires a separately reviewed
maintenance procedure with service ordering and rollback. The web process never receives the
backup key or decrypted archive contents.

## Final project gate

Backup integration into the web panel is intentionally deferred until the application, public
website, and deployment workflow are complete. Before the first client-application/site release
and before final project handoff, all of the following are mandatory:

1. create a fresh encrypted production backup;
2. export the archive and its key to separate encrypted locations;
3. verify the archive outside the live VPS;
4. perform a restore drill into a new staging directory;
5. record the verification result and exact rollback procedure without recording secrets.

The project is not considered operationally complete until this final gate passes.

## Security properties

- fixed source allowlist; no path is accepted from HTTP input;
- symlink and non-regular source rejection;
- consistent PostgreSQL custom-format snapshot produced by `pg_dump`;
- PostgreSQL credentials are passed through the process environment, not command arguments;
- authenticated encryption and per-entry SHA256 manifest;
- normalized safe archive paths;
- atomic archive installation followed by immediate verification;
- rotation only after successful creation and verification.
