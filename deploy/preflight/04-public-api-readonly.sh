#!/usr/bin/env bash
# Read-only production inventory for the domainless HTTPS API rollout.
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    printf 'error=run_with_sudo_on_debian\n' >&2
    exit 1
fi

printf 'debian_version='
cat /etc/debian_version
printf 'kernel='
uname -r
printf 'utc_time='
date -u +%Y-%m-%dT%H:%M:%SZ

for unit in xray kenai-vpn-helper kenai-vpn-web postgresql nftables; do
    printf 'unit_%s_active=%s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
    printf 'unit_%s_enabled=%s\n' "$unit" "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
done

printf '\nlistening_tcp:\n'
ss -Hltn
printf '\nfirewall_rules:\n'
nft -nn list ruleset

printf '\npackage_versions:\n'
for name in postgresql postgresql-client nginx certbot python3-venv; do
    dpkg-query -W -f='${binary:Package} ${Version}\n' "$name" 2>/dev/null || true
done

printf '\napplication_paths:\n'
for path in /opt/kenai-vpn/app /opt/kenai-vpn/venv /etc/kenai-vpn/web.env \
    /etc/kenai-vpn/tls /usr/local/etc/xray/config.json \
    /var/lib/kenai-vpn-admin /var/backups/kenai-vpn-admin; do
    if [[ -e "$path" ]]; then
        stat -c '%n %U:%G %a %F' "$path"
    else
        printf '%s missing\n' "$path"
    fi
done

printf '\ndatabase_info:\n'
if [[ -f /etc/kenai-vpn/web.env ]]; then
    # The environment is root-owned. Never print its raw content or the DB password.
    set -a
    # shellcheck disable=SC1091
    . /etc/kenai-vpn/web.env
    set +a
    /opt/kenai-vpn/venv/bin/python - <<'PY'
import os
import sqlite3
from pathlib import Path
from sqlalchemy.engine import make_url

url = make_url(os.environ['KENAI_DATABASE_URL'])
print(f'database_driver={url.drivername}')
if url.get_backend_name() == 'sqlite':
    path = Path(url.database or '').resolve()
    print(f'database_path={path}')
    if path.is_file():
        print(f'database_size_bytes={path.stat().st_size}')
        connection = sqlite3.connect(f'file:{path.as_posix()}?mode=ro', uri=True)
        try:
            print(f'sqlite_integrity={connection.execute("PRAGMA integrity_check").fetchone()[0]}')
            for table in ('administrators', 'users', 'devices', 'subscriptions'):
                found = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchone()
                if found:
                    print(f'{table}_rows={connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]}')
            found = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
            ).fetchone()
            if found:
                print(f'alembic_revision={connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]}')
        finally:
            connection.close()
PY
fi

printf '\npreflight_readonly=complete\n'
