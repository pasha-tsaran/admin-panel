#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_DIRECTORY="${SOURCE_DIRECTORY:-/root/kenai-helper-production}"
INSTALL_ROOT="/opt/kenai-vpn"
APP_ROOT="${INSTALL_ROOT}/app"
VENV="${INSTALL_ROOT}/venv"
ENV_DIRECTORY="/etc/kenai-vpn"
WEB_ENV="${ENV_DIRECTORY}/web.env"
TLS_DIRECTORY="${ENV_DIRECTORY}/tls"
WEB_STATE="/var/lib/kenai-vpn-admin"
WEB_UNIT_SOURCE="${SOURCE_DIRECTORY}/deploy/systemd/kenai-vpn-web.service"
WEB_UNIT_TARGET="/etc/systemd/system/kenai-vpn-web.service"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
NFT_CONFIG="/etc/nftables.conf"
HELPER_ENV="${ENV_DIRECTORY}/helper.env"
HELPER_UNIT="/etc/systemd/system/kenai-vpn-helper.service"

fail() {
    printf 'web_install_only_error=%s\n' "$1" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "root_required"
[[ -d "${SOURCE_DIRECTORY}" ]] || fail "source_directory_missing"
[[ -x "${VENV}/bin/python" ]] || fail "production_venv_missing"
[[ -f "${SOURCE_DIRECTORY}/alembic.ini" ]] || fail "alembic_config_missing"
[[ -d "${SOURCE_DIRECTORY}/migrations" ]] || fail "migrations_missing"
[[ -f "${WEB_UNIT_SOURCE}" ]] || fail "web_unit_template_missing"
[[ -f "${XRAY_CONFIG}" && ! -L "${XRAY_CONFIG}" ]] || fail "xray_config_invalid"
[[ -f "${NFT_CONFIG}" && ! -L "${NFT_CONFIG}" ]] || fail "nftables_config_invalid"
[[ -f "${HELPER_ENV}" && ! -L "${HELPER_ENV}" ]] || fail "helper_environment_invalid"
[[ -f "${HELPER_UNIT}" && ! -L "${HELPER_UNIT}" ]] || fail "helper_unit_invalid"
command -v pg_isready >/dev/null 2>&1 || fail "postgresql_client_missing"
id postgres >/dev/null 2>&1 || fail "postgresql_server_missing"
pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1 || fail "postgresql_not_ready"
id vpnadmin >/dev/null 2>&1 || fail "vpnadmin_missing"
getent group kenai-vpn >/dev/null || fail "socket_group_missing"
[[ "$(systemctl is-active kenai-vpn-helper.service || true)" == "inactive" ]] \
    || fail "helper_must_be_inactive"
[[ ! -e "${APP_ROOT}" ]] || fail "app_root_already_exists"
[[ ! -e "${WEB_ENV}" ]] || fail "web_environment_already_exists"
[[ ! -e "${TLS_DIRECTORY}" ]] || fail "tls_directory_already_exists"
[[ ! -e "${WEB_UNIT_TARGET}" ]] || fail "web_unit_already_exists"
[[ -z "$(ss -Hltn '( sport = :8443 )')" ]] || fail "tcp_8443_already_in_use"

xray_hash_before="$(sha256sum "${XRAY_CONFIG}" | awk '{print $1}')"
nft_config_hash_before="$(sha256sum "${NFT_CONFIG}" | awk '{print $1}')"
nft_runtime_hash_before="$(nft -nn list ruleset | sha256sum | awk '{print $1}')"
helper_env_hash_before="$(sha256sum "${HELPER_ENV}" | awk '{print $1}')"
helper_unit_hash_before="$(sha256sum "${HELPER_UNIT}" | awk '{print $1}')"

umask 022
"${VENV}/bin/python" -m pip install --no-cache-dir --upgrade "${SOURCE_DIRECTORY}"
umask 077

(
    set -a
    # shellcheck disable=SC1090
    . "${HELPER_ENV}"
    set +a
    "${VENV}/bin/python" -c \
        'from kenai_vpn_admin.helper.main import HelperSettings; HelperSettings()'
)

install -d -o root -g root -m 0755 "${APP_ROOT}"
cp -a -- "${SOURCE_DIRECTORY}/alembic.ini" "${APP_ROOT}/alembic.ini"
cp -a -- "${SOURCE_DIRECTORY}/migrations" "${APP_ROOT}/migrations"
chown -R root:root "${APP_ROOT}"
find "${APP_ROOT}" -type d -exec chmod 0755 {} +
find "${APP_ROOT}" -type f -exec chmod 0644 {} +

chown root:kenai-vpn "${ENV_DIRECTORY}"
chmod 0750 "${ENV_DIRECTORY}"
install -d -o root -g kenai-vpn -m 0750 "${TLS_DIRECTORY}"

"${VENV}/bin/python" -m kenai_vpn_admin.web_env_renderer --output "${WEB_ENV}"
chown root:kenai-vpn "${WEB_ENV}"
chmod 0640 "${WEB_ENV}"

temporary_tls="$(mktemp -d /run/kenai-web-tls.XXXXXX)"
trap 'rm -rf -- "${temporary_tls}"' EXIT

openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -keyout "${TLS_DIRECTORY}/ca.key" \
    -out "${TLS_DIRECTORY}/ca.crt" \
    -subj "/CN=Kenai VPN Admin Local CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -keyout "${TLS_DIRECTORY}/server.key" \
    -out "${temporary_tls}/server.csr" \
    -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

cat >"${temporary_tls}/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 825 \
    -in "${temporary_tls}/server.csr" \
    -CA "${TLS_DIRECTORY}/ca.crt" \
    -CAkey "${TLS_DIRECTORY}/ca.key" \
    -CAcreateserial \
    -out "${TLS_DIRECTORY}/server.crt" \
    -extfile "${temporary_tls}/server.ext" >/dev/null 2>&1

chown root:root "${TLS_DIRECTORY}/ca.key"
chmod 0600 "${TLS_DIRECTORY}/ca.key"
chown root:root "${TLS_DIRECTORY}/ca.crt" "${TLS_DIRECTORY}/server.crt"
chmod 0644 "${TLS_DIRECTORY}/ca.crt" "${TLS_DIRECTORY}/server.crt"
chown root:kenai-vpn "${TLS_DIRECTORY}/server.key"
chmod 0640 "${TLS_DIRECTORY}/server.key"
openssl verify -CAfile "${TLS_DIRECTORY}/ca.crt" "${TLS_DIRECTORY}/server.crt" >/dev/null
openssl x509 -in "${TLS_DIRECTORY}/server.crt" -noout -checkend 86400 >/dev/null

set -a
# shellcheck disable=SC1090
. "${WEB_ENV}"
set +a
runuser --preserve-environment -u postgres -- \
    "${VENV}/bin/python" -m kenai_vpn_admin.postgres_bootstrap
"${VENV}/bin/python" -c \
    'from kenai_vpn_admin.config import Settings; value=Settings(); value.ensure_safe_production()'

runuser --preserve-environment -u vpnadmin -- /bin/sh -c \
    'cd /opt/kenai-vpn/app && exec /opt/kenai-vpn/venv/bin/alembic -c alembic.ini upgrade head'
runuser --preserve-environment -u vpnadmin -- /bin/sh -c \
    'cd /opt/kenai-vpn/app && exec /opt/kenai-vpn/venv/bin/alembic -c alembic.ini current'

install -o root -g root -m 0644 "${WEB_UNIT_SOURCE}" "${WEB_UNIT_TARGET}"
systemctl daemon-reload
systemd-analyze verify "${WEB_UNIT_TARGET}"

[[ "$(systemctl is-active kenai-vpn-web.service || true)" == "inactive" ]] \
    || fail "web_service_not_inactive"
[[ "$(systemctl is-enabled kenai-vpn-web.service || true)" == "disabled" ]] \
    || fail "web_service_not_disabled"
[[ "$(systemctl is-active kenai-vpn-helper.service || true)" == "inactive" ]] \
    || fail "helper_state_changed"
[[ ! -S /run/kenai-vpn/helper.sock ]] || fail "helper_socket_created"
runuser --preserve-environment -u vpnadmin -- /bin/sh -c \
    'cd /opt/kenai-vpn/app && exec /opt/kenai-vpn/venv/bin/alembic -c alembic.ini current' \
    >/dev/null || fail "database_missing"
[[ -z "$(ss -Hltn '( sport = :8443 )')" ]] || fail "unexpected_web_listener"
[[ "$(sha256sum "${XRAY_CONFIG}" | awk '{print $1}')" == "${xray_hash_before}" ]] \
    || fail "xray_source_changed"
[[ "$(sha256sum "${NFT_CONFIG}" | awk '{print $1}')" == "${nft_config_hash_before}" ]] \
    || fail "nftables_config_changed"
[[ "$(nft -nn list ruleset | sha256sum | awk '{print $1}')" == "${nft_runtime_hash_before}" ]] \
    || fail "nftables_runtime_changed"
[[ "$(sha256sum "${HELPER_ENV}" | awk '{print $1}')" == "${helper_env_hash_before}" ]] \
    || fail "helper_environment_changed"
[[ "$(sha256sum "${HELPER_UNIT}" | awk '{print $1}')" == "${helper_unit_hash_before}" ]] \
    || fail "helper_unit_changed"

printf 'web_install_only=pass\n'
printf 'web_active=no\n'
printf 'web_enabled=no\n'
printf 'helper_active=no\n'
printf 'helper_enabled=no\n'
printf 'firewall_changed=no\n'
printf 'live_vpn_sources_unchanged=yes\n'
printf 'helper_installation_unchanged=yes\n'
printf 'tcp_8443_listener_created=no\n'
printf 'administrator_created=no\n'
printf 'secret_values_printed=0\n'
