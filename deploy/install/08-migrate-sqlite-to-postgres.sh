#!/usr/bin/env bash
# Stops only the web panel; Xray and the helper keep running.
set -Eeuo pipefail
umask 077

[[ "${EUID}" -eq 0 ]] || { echo 'migration_error=root_required' >&2; exit 1; }
[[ "$(systemctl is-active kenai-vpn-web.service)" == active ]] \
    || { echo 'migration_error=old_web_not_active' >&2; exit 1; }
pg_isready -h 127.0.0.1 -p 5432 >/dev/null \
    || { echo 'migration_error=postgres_not_ready' >&2; exit 1; }
[[ -x /opt/kenai-vpn/venv-20260913/bin/kenai-admin ]] \
    || { echo 'migration_error=new_application_missing' >&2; exit 1; }
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
source_path="/var/lib/kenai-vpn-admin/migration-source-${run_id}.db"
snapshot_dir="/root/kenai-migration-snapshot-${run_id}"
[[ ! -e "$source_path" ]] \
    || { echo 'migration_error=source_snapshot_exists' >&2; exit 1; }
[[ ! -e "$snapshot_dir" ]] \
    || { echo 'migration_error=restore_staging_exists' >&2; exit 1; }

web_stopped=no
restart_old_web_on_error() {
    if [[ "$web_stopped" == yes ]]; then
        systemctl start kenai-vpn-web.service || true
    fi
}
trap restart_old_web_on_error ERR

systemctl stop kenai-vpn-web.service
web_stopped=yes
[[ "$(systemctl is-active kenai-vpn-web.service || true)" == inactive ]]

set -a
# shellcheck disable=SC1091
. /etc/kenai-vpn/web.env
set +a
backup_output="$(/opt/kenai-vpn/venv/bin/kenai-backup --retention 100 create)"
printf '%s\n' "$backup_output"
backup_path="$(printf '%s\n' "$backup_output" | sed -n 's/^backup_created=//p')"
[[ "$backup_path" == /var/backups/kenai-vpn-admin/kenai-vpn-*.kvbackup ]]
/opt/kenai-vpn/venv/bin/kenai-backup extract \
    "$backup_path" "$snapshot_dir" >/dev/null
install -o vpnadmin -g kenai-vpn -m 0600 \
    "$snapshot_dir/database/kenai-admin.db" "$source_path"

set -a
# shellcheck disable=SC1091
. /etc/kenai-vpn/web-postgres.env
set +a
runuser --preserve-environment -u vpnadmin -- /bin/sh -c \
    'cd /opt/kenai-vpn/app-20260913 && exec /opt/kenai-vpn/venv-20260913/bin/kenai-admin import-sqlite --source "$1" --confirm IMPORT' \
    sh "$source_path"

export KENAI_MIGRATION_SOURCE="$source_path"
/opt/kenai-vpn/venv-20260913/bin/python - <<'PY'
import os
import sqlite3
from sqlalchemy import create_engine, text

source = sqlite3.connect(os.environ['KENAI_MIGRATION_SOURCE'])
target = create_engine(os.environ['KENAI_DATABASE_URL'])
try:
    with target.connect() as connection:
        for table in ('administrators', 'users', 'devices', 'subscriptions'):
            found = source.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not found:
                continue
            original = source.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            imported = connection.scalar(text(f'SELECT COUNT(*) FROM {table}'))
            if original != imported:
                raise SystemExit(f'migration_error=count_mismatch_{table}')
            print(f'{table}_rows={imported}')
finally:
    target.dispose()
    source.close()
PY

web_stopped=no
trap - ERR
echo 'sqlite_to_postgres=verified'
echo 'old_web_stopped_for_cutover=yes'
echo 'xray_not_modified=yes'
