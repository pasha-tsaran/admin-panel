#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Retry after the first upgrade rolled back solely because its immediate
# health probe raced the web process startup. The previous release is reused;
# no VPN daemon, route, firewall rule or database schema is changed.
release=/opt/kenai-vpn/releases/dual-20260914T194100Z
venv=/opt/kenai-vpn/venv-20260913
web_env=/etc/kenai-vpn/web.env
dropin=/etc/systemd/system/kenai-vpn-web.service.d/20-dual-protocol.conf
backup_dir=/var/backups/kenai-vpn-admin/dual-protocol-retry-20260914T200000Z
expected_code_sha256=46b952ef9fc6f57c9feadae2b546e1afa7a8f8ff9c031e9e4a77b892a4fb101a

fail() { printf 'dual_protocol_retry=blocked:%s\n' "$1" >&2; exit 1; }
[[ $EUID == 0 ]] || fail root_required
[[ -d $release && ! -L $release ]] || fail release_missing
[[ -f $web_env && ! -L $web_env ]] || fail web_environment_invalid
[[ ! -e $dropin && ! -e $backup_dir ]] || fail retry_already_staged
[[ -x $venv/bin/python && -x $venv/bin/kenai-backup ]] || fail runtime_missing
[[ $(sha256sum "$release/src/kenai_vpn_admin/application/services.py" | cut -d' ' -f1) == "$expected_code_sha256" ]] || fail release_hash_mismatch
[[ $(grep -Ec '^KENAI_SUBSCRIPTION_PROTOCOLS=' "$web_env") == 1 ]] || fail protocol_setting_invalid
current_protocols=$(grep '^KENAI_SUBSCRIPTION_PROTOCOLS=' "$web_env")
[[ $current_protocols == 'KENAI_SUBSCRIPTION_PROTOCOLS=vless' || $current_protocols == "KENAI_SUBSCRIPTION_PROTOCOLS='vless'" ]] || fail unexpected_protocol_setting
for service in xray awg-quick@awg0 kenai-vpn-helper kenai-vpn-web postgresql nginx; do
    systemctl is-active --quiet "$service" || fail "service_inactive:$service"
done
curl --silent --show-error --fail --insecure --max-time 5 \
    https://10.66.66.1:8443/healthz >/dev/null || fail old_web_unhealthy
PYTHONPATH="$release/src" "$venv/bin/python" -c \
    'from kenai_vpn_admin.application.services import AdminService' || fail release_import_failed

set -a
# shellcheck disable=SC1090
. "$web_env"
set +a
"$venv/bin/kenai-backup" create || fail encrypted_backup_failed
install -d -o root -g root -m 0700 "$backup_dir"
cp -a -- "$web_env" "$backup_dir/web.env"
systemctl cat kenai-vpn-web.service > "$backup_dir/kenai-vpn-web.unit.txt"

rollback() {
    trap - ERR
    cp -a -- "$backup_dir/web.env" "$web_env"
    if [[ -e $dropin ]]; then
        mv -- "$dropin" "$backup_dir/20-dual-protocol.conf.failed"
    fi
    systemctl daemon-reload
    systemctl restart kenai-vpn-web.service || true
    fail web_health_check_failed_rolled_back
}

trap rollback ERR
sed -i 's/^KENAI_SUBSCRIPTION_PROTOCOLS=.*/KENAI_SUBSCRIPTION_PROTOCOLS=vless,amneziawg/' "$web_env"
printf '[Service]\nEnvironment=PYTHONPATH=%s/src\n' "$release" > "$dropin"
chmod 0644 "$dropin"
systemctl daemon-reload
systemctl restart kenai-vpn-web.service

ready=no
for attempt in $(seq 1 30); do
    if systemctl is-active --quiet kenai-vpn-web.service && \
        curl --silent --fail --insecure --max-time 2 \
            https://10.66.66.1:8443/healthz >/dev/null; then
        ready=yes
        break
    fi
    sleep 1
done
[[ $ready == yes ]]
systemctl is-active --quiet xray
systemctl is-active --quiet awg-quick@awg0
systemctl is-active --quiet kenai-vpn-helper
trap - ERR
printf 'dual_protocol_retry=pass\nweb_release=%s\nbackup_directory=%s\n' "$release" "$backup_dir"
