#!/usr/bin/env bash
# Reviewed for the existing 88.218.94.3 deployment on 2026-09-20.
set -Eeuo pipefail
umask 077
archive=/home/codexuser/kenai-vpn-staging-20260920T131025Z.tar.gz
digest=ce98f264f44508e93878bb9c4f6cd4fd63a63717c919ae90fee487ce72bbe5bd
release=/opt/kenai-vpn/releases/support-20260920T131025Z-r4
runtime=/opt/kenai-vpn/venv-20260913
backup=/var/backups/kenai-vpn-admin/support-20260920T131025Z-r4
dropin=/etc/systemd/system/kenai-vpn-web.service.d/30-support.conf
unit=/etc/systemd/system/kenai-vpn-support.service
site=/etc/nginx/sites-available/kenai-api-ip
status=/var/lib/kenai-vpn-support-deploy.status
fail() { printf 'support_deploy_error=%s\n' "$1" >&2; exit 1; }
report() {
    [[ ! -L $status ]] || fail invalid_status_path
    printf '%s\n' "$1" > "$status"
    chmod 0644 "$status"
}
[[ $EUID == 0 ]] || fail root_required
[[ ! -e $release && ! -e $backup && ! -e $dropin && ! -e $unit ]] || fail already_staged
[[ -f $archive && ! -L $archive ]] || fail archive_missing
[[ $(sha256sum "$archive" | cut -d' ' -f1) == "$digest" ]] || fail archive_hash
[[ -f $site && ! -L $site ]] || fail nginx_site_invalid
for service in kenai-vpn-web kenai-vpn-helper xray awg-quick@awg0 wg-quick@wg0 postgresql nginx; do
    systemctl is-active --quiet "$service" || fail "inactive:$service"
done
report 'support_deploy=preparing'
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
cd "$release"

# The public configuration must match the reviewed baseline exactly.
"$runtime/bin/python" - "$release" "$site" <<'PY'
import re, sys
from pathlib import Path
candidate = (Path(sys.argv[1]) / 'deploy/nginx/kenai-api-ip.conf').read_text()
previous, count = re.subn(r'    location \^~ /api/v1/support/ \{.*?\n    \}\n\n', '', candidate, flags=re.S)
assert count == 1 and previous == Path(sys.argv[2]).read_text(), 'Unexpected nginx baseline'
PY
cp -a -- "$site" "$backup/nginx-site.conf"
cp -a -- /etc/kenai-vpn/web.env "$backup/web.env"
systemctl cat kenai-vpn-web.service > "$backup/web-service.txt"
sha256sum /usr/local/etc/xray/config.json /etc/amneziawg/awg0.conf \
    /etc/wireguard/wg0.conf /etc/nftables.conf /etc/kenai-vpn/helper.env \
    > "$backup/vpn-files.sha256"
systemctl show xray awg-quick@awg0 wg-quick@wg0 kenai-vpn-helper \
    -p Id -p MainPID -p ActiveEnterTimestampMonotonic > "$backup/vpn-processes.txt"

set -a
. /etc/kenai-vpn/web.env
set +a
export PYTHONPATH="$release/src"
export PYTHONDONTWRITEBYTECODE=1
# Test configuration and migration baseline without exposing connection strings.
runuser --preserve-environment -u vpnadmin -- "$runtime/bin/python" - <<'PY'
from sqlalchemy import text
from kenai_vpn_admin.config import get_settings
from kenai_vpn_admin.infrastructure.database import build_engine
from kenai_vpn_admin.main import app
s = get_settings()
assert s.env == 'production' and not s.support_available
engine = build_engine(s)
with engine.connect() as connection:
    revision = connection.scalar(text('SELECT version_num FROM alembic_version'))
    assert revision in {'e6a1b7c42d90', 'f7b2c8d93e10'}
    exists = connection.scalar(text("SELECT to_regclass('public.support_tickets')")) is not None
    assert exists == (revision == 'f7b2c8d93e10')
assert '/api/v1/support/config' in app.openapi()['paths']
engine.dispose()
print('support_preflight=pass')
PY
"$runtime/bin/kenai-backup" --retention 30 create

rollback() {
    failed_line=$1
    trap - ERR
    systemctl stop kenai-vpn-support.service 2>/dev/null || true
    if [[ -f $dropin ]]; then mv -- "$dropin" "$backup/failed-support-dropin.conf"; fi
    if [[ -f $unit ]]; then mv -- "$unit" "$backup/failed-support-unit.service"; fi
    cp -a -- "$backup/nginx-site.conf" "$site"
    systemctl daemon-reload
    nginx -t && systemctl reload nginx
    systemctl restart kenai-vpn-web
    report "support_deploy=rolled_back; line=$failed_line"
    printf 'support_deploy=rolled_back; line=%s; backup=%s\n' "$failed_line" "$backup" >&2
    exit 1
}
trap 'rollback "$LINENO"' ERR
report 'support_deploy=migrating'
(
    cd "$release"
    runuser --preserve-environment -u vpnadmin -- "$runtime/bin/alembic" -c alembic.ini upgrade f7b2c8d93e10
)
printf '[Service]\nEnvironment=PYTHONPATH=%s/src\n' "$release" > "$dropin"
chmod 0644 "$dropin"
"$runtime/bin/python" - "$release" "$runtime" "$unit" <<'PY'
import sys
from pathlib import Path
source = (Path(sys.argv[1]) / 'deploy/systemd/kenai-vpn-support.service').read_text()
source = source.replace('/opt/kenai-vpn/venv/bin/python', sys.argv[2] + '/bin/python')
source = source.replace('[Service]\n', '[Service]\nEnvironment=PYTHONPATH=' + sys.argv[1] + '/src\n')
Path(sys.argv[3]).write_text(source)
Path(sys.argv[3]).chmod(0o644)
PY
install -o root -g root -m 0644 "$release/deploy/nginx/kenai-api-ip.conf" "$site"
nginx -t
systemctl daemon-reload
systemd-analyze verify kenai-vpn-web.service kenai-vpn-support.service
systemctl restart kenai-vpn-web
healthy=no
for attempt in {1..15}; do
    if curl --silent --fail --cacert /etc/kenai-vpn/tls/ca.crt --max-time 3 \
        https://10.66.66.1:8443/healthz >/dev/null; then healthy=yes; break; fi
    sleep 1
done
[[ $healthy == yes ]]
report 'support_deploy=checking_private_api'
curl --silent --show-error --fail --cacert /etc/kenai-vpn/tls/ca.crt --max-time 10 \
    https://10.66.66.1:8443/api/v1/support/config \
    | "$runtime/bin/python" -c 'import json,sys; assert json.load(sys.stdin) == {"available":False}'
printf 'private_support_api=pass\n'
systemctl reload nginx
report 'support_deploy=checking_public_api'
public_ready=no
# nginx reload returns before all new workers have taken over the listener.
for attempt in {1..15}; do
    if response=$(curl --silent --fail --max-time 5 https://88.218.94.3:9443/api/v1/support/config) \
        && [[ $response == '{"available":false}' ]]; then public_ready=yes; break; fi
    sleep 1
done
[[ $public_ready == yes ]]
printf 'public_support_api=pass\n'
[[ $(curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' https://88.218.94.3:9443/login) == 404 ]]
[[ $(curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' \
    -H 'Content-Type: application/json' -d '{}' https://88.218.94.3:9443/api/v1/activate) == 422 ]]
sha256sum --check --status "$backup/vpn-files.sha256"
systemctl show xray awg-quick@awg0 wg-quick@wg0 kenai-vpn-helper \
    -p Id -p MainPID -p ActiveEnterTimestampMonotonic > "$backup/vpn-processes-after.txt"
cmp --silent "$backup/vpn-processes.txt" "$backup/vpn-processes-after.txt"
for service in kenai-vpn-web kenai-vpn-helper xray awg-quick@awg0 wg-quick@wg0 postgresql nginx; do
    systemctl is-active --quiet "$service"
done
trap - ERR
report 'support_deploy=installed; bot=awaiting_configuration; vpn=unchanged'
printf '\nSupport installed. VPN services and configuration unchanged.\n'
printf 'Backup: %s\nTelegram configuration is the next step.\n' "$backup"
