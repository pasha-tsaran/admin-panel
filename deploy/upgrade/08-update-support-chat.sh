#!/usr/bin/env bash
# Existing production deployment; changes only the web/support source selection.
set -Eeuo pipefail
umask 077
archive=/home/codexuser/kenai-vpn-staging-20260920T170041Z.tar.gz
digest=2d5ab386f93ffcb7a2efb0b8f5979ec2f8cc9deb39de12f689651e51e3e622d0
release=/opt/kenai-vpn/releases/support-chat-20260920-r1
previous=/opt/kenai-vpn/releases/support-20260920T131025Z-r4
runtime=/opt/kenai-vpn/venv-20260913
backup=/var/backups/kenai-vpn-admin/support-chat-20260920-r1
dropin=/etc/systemd/system/kenai-vpn-web.service.d/30-support.conf
unit=/etc/systemd/system/kenai-vpn-support.service
status=/var/lib/kenai-vpn-support-deploy.status
fail() { printf 'support_update_error=%s\n' "$1" >&2; exit 1; }
[[ $EUID == 0 ]] || fail root_required
[[ ! -e $release && ! -e $backup ]] || fail already_staged
[[ -f $archive && ! -L $archive ]] || fail archive_missing
[[ $(sha256sum "$archive" | cut -d' ' -f1) == "$digest" ]] || fail archive_hash
for service in kenai-vpn-web kenai-vpn-support kenai-vpn-helper xray awg-quick@awg0 wg-quick@wg0 postgresql nginx; do
    systemctl is-active --quiet "$service" || fail "inactive:$service"
done
grep -qx "Environment=PYTHONPATH=$previous/src" "$dropin" || fail unexpected_web_release
grep -qx "Environment=PYTHONPATH=$previous/src" "$unit" || fail unexpected_worker_release
install -d -o root -g root -m 0700 "$backup"
cp -- "$archive" "$backup/source.tar.gz"
[[ $(sha256sum "$backup/source.tar.gz" | cut -d' ' -f1) == "$digest" ]] || fail copied_archive_hash
"$runtime/bin/python" - "$backup/source.tar.gz" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
with tarfile.open(sys.argv[1]) as archive:
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        assert member.isfile() or member.isdir()
PY
install -d -o root -g root -m 0755 "$release"
tar -xzf "$backup/source.tar.gz" -C "$release" --no-same-owner
find "$release" -type d -exec chmod 0755 {} +
find "$release" -type f -exec chmod 0644 {} +
cp -a -- "$dropin" "$backup/web-dropin.conf"
cp -a -- "$unit" "$backup/support.service"
cp -a -- "$status" "$backup/deploy.status"
sha256sum /usr/local/etc/xray/config.json /etc/amneziawg/awg0.conf \
    /etc/wireguard/wg0.conf /etc/nftables.conf /etc/kenai-vpn/helper.env \
    /etc/kenai-vpn/web.env /etc/nginx/sites-available/kenai-api-ip > "$backup/config.sha256"
systemctl show xray awg-quick@awg0 wg-quick@wg0 kenai-vpn-helper \
    -p Id -p MainPID -p ActiveEnterTimestampMonotonic > "$backup/vpn-processes.txt"
cd "$release"
set -a
. /etc/kenai-vpn/web.env
set +a
export PYTHONPATH="$release/src"
export PYTHONDONTWRITEBYTECODE=1
runuser --preserve-environment -u vpnadmin -- "$runtime/bin/python" - <<'PY'
from sqlalchemy import text
from kenai_vpn_admin.config import get_settings
from kenai_vpn_admin.infrastructure.database import build_engine
from kenai_vpn_admin.main import app
s = get_settings()
assert s.env == 'production' and s.support_available
engine = build_engine(s)
with engine.connect() as c:
    assert c.scalar(text('SELECT version_num FROM alembic_version')) == 'f7b2c8d93e10'
for _ in range(3):
    with engine.connect() as c:
        assert c.scalar(text('SHOW TIME ZONE')) == 'UTC'
assert '/api/v1/support/config' in app.openapi()['paths']
engine.dispose()
print('support_chat_preflight=pass; reused_connection_utc=pass')
PY
"$runtime/bin/kenai-backup" --retention 30 create
rollback() {
    failed_line=$1
    trap - ERR
    systemctl stop kenai-vpn-support.service || true
    cp -a -- "$backup/web-dropin.conf" "$dropin"
    cp -a -- "$backup/support.service" "$unit"
    cp -a -- "$backup/deploy.status" "$status"
    systemctl daemon-reload
    systemctl restart kenai-vpn-web kenai-vpn-support
    printf 'support_update=rolled_back; line=%s; backup=%s\n' "$failed_line" "$backup" >&2
    exit 1
}
trap 'rollback "$LINENO"' ERR
systemctl stop kenai-vpn-support
runuser --preserve-environment -u vpnadmin -- "$runtime/bin/alembic" -c alembic.ini upgrade a8c3d9e04f21
printf '[Service]\nEnvironment=PYTHONPATH=%s/src\n' "$release" > "$dropin"
chmod 0644 "$dropin"
"$runtime/bin/python" - "$unit" "$previous" "$release" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text()
old = 'Environment=PYTHONPATH=' + sys.argv[2] + '/src'
assert source.count(old) == 1
path.write_text(source.replace(old, 'Environment=PYTHONPATH=' + sys.argv[3] + '/src'))
PY
systemctl daemon-reload
systemd-analyze verify kenai-vpn-web.service kenai-vpn-support.service
systemctl restart kenai-vpn-web kenai-vpn-support
ready=no
for attempt in {1..20}; do
    if response=$(curl --silent --fail --max-time 3 https://88.218.94.3:9443/api/v1/support/config) \
        && [[ $response == '{"available":true}' ]]; then ready=yes; break; fi
    sleep 1
done
[[ $ready == yes ]]
[[ $(curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' https://88.218.94.3:9443/api/v1/support/tickets) == 401 ]]
sleep 12
systemctl is-active --quiet kenai-vpn-support
runuser --preserve-environment -u vpnadmin -- "$runtime/bin/python" - <<'PY'
from sqlalchemy import text
from kenai_vpn_admin.config import get_settings
from kenai_vpn_admin.infrastructure.database import build_engine
engine = build_engine(get_settings())
with engine.connect() as c:
    assert c.scalar(text('SELECT version_num FROM alembic_version')) == 'a8c3d9e04f21'
    assert c.scalar(text("SELECT to_regclass('public.support_operator_sessions')"))
    # The single bot worker must hold its dedicated advisory lock.
    acquired = c.scalar(text('SELECT pg_try_advisory_lock(726514209)'))
    if acquired:
        c.execute(text('SELECT pg_advisory_unlock(726514209)'))
    assert not acquired, 'Support worker has not acquired its lock'
    print('pending_delivery_count=' + str(c.scalar(text('SELECT count(*) FROM support_outbox WHERE sent_at IS NULL'))))
engine.dispose()
print('support_chat_runtime=pass')
PY
sha256sum --check --status "$backup/config.sha256"
systemctl show xray awg-quick@awg0 wg-quick@wg0 kenai-vpn-helper \
    -p Id -p MainPID -p ActiveEnterTimestampMonotonic > "$backup/vpn-processes-after.txt"
cmp --silent "$backup/vpn-processes.txt" "$backup/vpn-processes-after.txt"
for service in kenai-vpn-web kenai-vpn-support kenai-vpn-helper xray awg-quick@awg0 wg-quick@wg0 postgresql nginx; do
    systemctl is-active --quiet "$service"
done
trap - ERR
printf 'support_deploy=active; plain_replies=enabled; utc_fix=enabled; vpn=unchanged\n' > "$status"
chmod 0644 "$status"
printf '\nSupport chat updated. Plain replies enabled. VPN unchanged.\nBackup: %s\n' "$backup"
