#!/usr/bin/env bash
# Activate the separately staged PostgreSQL web/helper build, with automatic service rollback.
set -Eeuo pipefail
umask 077

[[ "${EUID}" -eq 0 ]] || { echo 'cutover_error=root_required' >&2; exit 1; }
[[ "$(systemctl is-active kenai-vpn-web.service || true)" == inactive ]] \
    || { echo 'cutover_error=web_must_be_stopped' >&2; exit 1; }
[[ "$(systemctl is-active kenai-vpn-helper.service)" == active ]] \
    || { echo 'cutover_error=helper_not_active' >&2; exit 1; }
[[ "$(systemctl is-active xray.service)" == active ]] \
    || { echo 'cutover_error=xray_not_active' >&2; exit 1; }
[[ "$(systemctl is-active postgresql.service)" == active ]] \
    || { echo 'cutover_error=postgres_not_active' >&2; exit 1; }
[[ -f /etc/kenai-vpn/web-postgres.env ]] \
    || { echo 'cutover_error=postgres_environment_missing' >&2; exit 1; }
[[ ! -e /etc/kenai-vpn/web-sqlite-prepg-20260913.env ]] \
    || { echo 'cutover_error=old_environment_backup_exists' >&2; exit 1; }
[[ ! -e /etc/systemd/system/kenai-vpn-web.service.d/10-postgres-mvp.conf ]] \
    || { echo 'cutover_error=web_dropin_exists' >&2; exit 1; }
[[ ! -e /etc/systemd/system/kenai-vpn-helper.service.d/10-postgres-mvp.conf ]] \
    || { echo 'cutover_error=helper_dropin_exists' >&2; exit 1; }

env_swapped=no
rollback() {
    echo 'cutover_error=rolling_back_to_sqlite' >&2
    systemctl stop kenai-vpn-web.service || true
    if [[ -f /etc/systemd/system/kenai-vpn-web.service.d/10-postgres-mvp.conf ]]; then
        mv /etc/systemd/system/kenai-vpn-web.service.d/10-postgres-mvp.conf \
            /root/kenai-mvp-20260913-v2/failed-web-dropin.conf || true
    fi
    if [[ -f /etc/systemd/system/kenai-vpn-helper.service.d/10-postgres-mvp.conf ]]; then
        mv /etc/systemd/system/kenai-vpn-helper.service.d/10-postgres-mvp.conf \
            /root/kenai-mvp-20260913-v2/failed-helper-dropin.conf || true
    fi
    if [[ "$env_swapped" == yes ]]; then
        if [[ -f /etc/kenai-vpn/web.env ]]; then
            mv /etc/kenai-vpn/web.env /etc/kenai-vpn/web-postgres-failed.env || true
        fi
        mv /etc/kenai-vpn/web-sqlite-prepg-20260913.env /etc/kenai-vpn/web.env || true
    fi
    systemctl daemon-reload
    systemctl restart kenai-vpn-helper.service || true
    systemctl start kenai-vpn-web.service || true
}
trap rollback ERR

mv /etc/kenai-vpn/web.env /etc/kenai-vpn/web-sqlite-prepg-20260913.env
env_swapped=yes
mv /etc/kenai-vpn/web-postgres.env /etc/kenai-vpn/web.env

install -d -o root -g root -m 0755 /etc/systemd/system/kenai-vpn-web.service.d
install -d -o root -g root -m 0755 /etc/systemd/system/kenai-vpn-helper.service.d
install -o root -g root -m 0644 /home/codexuser/kenai-web-postgres-mvp.conf \
    /etc/systemd/system/kenai-vpn-web.service.d/10-postgres-mvp.conf
install -o root -g root -m 0644 /home/codexuser/kenai-helper-postgres-mvp.conf \
    /etc/systemd/system/kenai-vpn-helper.service.d/10-postgres-mvp.conf

systemctl daemon-reload
systemd-analyze verify kenai-vpn-web.service kenai-vpn-helper.service
systemctl restart kenai-vpn-helper.service
systemctl start kenai-vpn-web.service
[[ "$(systemctl is-active kenai-vpn-web.service)" == active ]]
[[ "$(systemctl is-active kenai-vpn-helper.service)" == active ]]
[[ "$(systemctl is-active xray.service)" == active ]]

status=000
for attempt in 1 2 3 4 5; do
    status="$(curl --silent --cacert /etc/kenai-vpn/tls/ca.crt \
        --output /dev/null --write-out '%{http_code}' \
        https://10.66.66.1:8443/healthz || true)"
    [[ "$status" == 200 ]] && break
    sleep 1
done
[[ "$status" == 200 ]] || { echo "cutover_error=health_http_${status}" >&2; false; }

trap - ERR
echo 'postgres_cutover=active'
echo 'web_health=200'
echo 'xray_active=yes'
