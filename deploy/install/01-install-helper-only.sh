#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_DIRECTORY="${SOURCE_DIRECTORY:-/root/kenai-helper-staging}"
INSTALL_ROOT="/opt/kenai-vpn"
ENV_DIRECTORY="/etc/kenai-vpn"
ENV_FILE="${ENV_DIRECTORY}/helper.env"
STATE_DIRECTORY="/var/lib/kenai-vpn-helper"
WEB_HOME="/var/lib/kenai-vpn-admin"
UNIT_SOURCE="${SOURCE_DIRECTORY}/deploy/systemd/kenai-vpn-helper.service"
UNIT_TARGET="/etc/systemd/system/kenai-vpn-helper.service"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
BACKUP_ROOT="/var/backups/kenai-vpn"
ENDPOINT="${ENDPOINT:-}"

fail() {
    printf 'install_only_error=%s\n' "$1" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "root_required"
[[ -d "${SOURCE_DIRECTORY}" ]] || fail "source_directory_missing"
[[ -f "${SOURCE_DIRECTORY}/pyproject.toml" ]] || fail "project_metadata_missing"
[[ -f "${UNIT_SOURCE}" ]] || fail "unit_template_missing"
[[ -f "${XRAY_CONFIG}" && ! -L "${XRAY_CONFIG}" ]] || fail "xray_config_invalid"
[[ -n "${ENDPOINT}" ]] || fail "endpoint_required"
[[ ! -e "${INSTALL_ROOT}" ]] || fail "install_root_already_exists"
[[ ! -e "${ENV_FILE}" ]] || fail "helper_environment_already_exists"
[[ ! -e "${UNIT_TARGET}" ]] || fail "helper_unit_already_exists"
! systemctl is-active --quiet kenai-vpn-helper.service || fail "helper_already_active"
[[ ! -S /run/kenai-vpn/helper.sock ]] || fail "helper_socket_already_exists"

xray_hash_before="$(sha256sum "${XRAY_CONFIG}" | awk '{print $1}')"
timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
backup_directory="${BACKUP_ROOT}/pre-helper-${timestamp}"

if getent group kenai-vpn >/dev/null; then
    fail "group_kenai_vpn_already_exists"
fi
if getent passwd vpnadmin >/dev/null; then
    fail "user_vpnadmin_already_exists"
fi

install -d -o root -g root -m 0700 "${backup_directory}"
cp --preserve=mode,ownership,timestamps -- "${XRAY_CONFIG}" "${backup_directory}/xray-config.json"

groupadd --system kenai-vpn
useradd --system --gid kenai-vpn --home-dir "${WEB_HOME}" --create-home \
    --shell /usr/sbin/nologin vpnadmin
chown vpnadmin:kenai-vpn "${WEB_HOME}"
chmod 0750 "${WEB_HOME}"

install -d -o root -g root -m 0755 "${INSTALL_ROOT}"
umask 022
python3 -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/python" -m pip install --no-cache-dir "${SOURCE_DIRECTORY}"
umask 077

install -d -o root -g root -m 0700 "${ENV_DIRECTORY}"
install -d -o root -g root -m 0700 "${STATE_DIRECTORY}"

vpnadmin_uid="$(id -u vpnadmin)"
socket_gid="$(getent group kenai-vpn | cut -d: -f3)"
"${INSTALL_ROOT}/venv/bin/python" -m kenai_vpn_admin.helper.env_renderer \
    --output "${ENV_FILE}" \
    --allowed-uid "${vpnadmin_uid}" \
    --socket-gid "${socket_gid}" \
    --endpoint "${ENDPOINT}" \
    --xray-config "${XRAY_CONFIG}" \
    --xray-port 443
chown root:root "${ENV_FILE}"
chmod 0600 "${ENV_FILE}"

install -o root -g root -m 0644 "${UNIT_SOURCE}" "${UNIT_TARGET}"
systemctl daemon-reload

set -a
# shellcheck disable=SC1090
. "${ENV_FILE}"
set +a
"${INSTALL_ROOT}/venv/bin/python" -c \
    'from kenai_vpn_admin.helper.main import HelperSettings; HelperSettings()'
systemd-analyze verify "${UNIT_TARGET}"

[[ "$(systemctl is-active kenai-vpn-helper.service || true)" == "inactive" ]] \
    || fail "helper_not_inactive"
[[ "$(systemctl is-enabled kenai-vpn-helper.service || true)" == "disabled" ]] \
    || fail "helper_not_disabled"
[[ ! -S /run/kenai-vpn/helper.sock ]] || fail "unexpected_helper_socket"
[[ "$(sha256sum "${XRAY_CONFIG}" | awk '{print $1}')" == "${xray_hash_before}" ]] \
    || fail "xray_source_changed"

printf 'install_only=pass\n'
printf 'helper_active=no\n'
printf 'helper_enabled=no\n'
printf 'helper_socket_created=no\n'
printf 'vpn_runtime_mutations=0\n'
printf 'live_source_hashes_unchanged=yes\n'
printf 'private_values_printed=0\n'
printf 'backup_directory=%s\n' "${backup_directory}"
