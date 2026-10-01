#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Upgrade only the Kenai web process. Existing Xray, AmneziaWG and helper
# processes/configurations are deliberately left untouched.
archive=/home/codexuser/kenai-vpn-staging-20260914T194100Z.tar.gz
archive_sha256=6dfc82fa326a1cdf2eb3c389ce23f933d5316e91dc974d249dba43e8c8884a7c
release=/opt/kenai-vpn/releases/dual-20260914T194100Z
venv=/opt/kenai-vpn/venv-20260913
web_env=/etc/kenai-vpn/web.env
helper_env=/etc/kenai-vpn/helper.env
dropin=/etc/systemd/system/kenai-vpn-web.service.d/20-dual-protocol.conf
backup_dir=/var/backups/kenai-vpn-admin/dual-protocol-20260914T194100Z

fail() { printf 'dual_protocol_upgrade=blocked:%s\n' "$1" >&2; exit 1; }
[[ $EUID == 0 ]] || fail root_required
[[ -f $archive && ! -L $archive ]] || fail archive_missing
[[ -x $venv/bin/python && -x $venv/bin/kenai-backup ]] || fail installed_runtime_missing
[[ -f $web_env && ! -L $web_env ]] || fail web_environment_invalid
[[ -f $helper_env && ! -L $helper_env ]] || fail helper_environment_invalid
[[ -f /etc/amneziawg/awg0.conf && ! -L /etc/amneziawg/awg0.conf ]] || fail awg_configuration_missing
[[ ! -e $release && ! -e $dropin && ! -e $backup_dir ]] || fail upgrade_already_staged
[[ $(sha256sum "$archive" | cut -d' ' -f1) == "$archive_sha256" ]] || fail archive_hash_mismatch
[[ $(grep -Ec '^KENAI_SUBSCRIPTION_PROTOCOLS=' "$web_env") == 1 ]] || fail protocol_setting_invalid
current_protocols=$(grep '^KENAI_SUBSCRIPTION_PROTOCOLS=' "$web_env")
[[ $current_protocols == 'KENAI_SUBSCRIPTION_PROTOCOLS=vless' || $current_protocols == "KENAI_SUBSCRIPTION_PROTOCOLS='vless'" ]] || fail unexpected_protocol_setting
for service in xray awg-quick@awg0 kenai-vpn-helper kenai-vpn-web postgresql nginx; do
    systemctl is-active --quiet "$service" || fail "service_inactive:$service"
done

# Verify the helper can issue an AWG peer whose key, port, address pool and
# obfuscation parameters match the running server. Never print key material.
set -a
# shellcheck disable=SC1090
. "$helper_env"
set +a
"$venv/bin/python" - <<'PY' || fail awg_parameters_mismatch
import base64
import ipaddress
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from kenai_vpn_admin.helper.main import HelperSettings

try:
    settings = HelperSettings()
    assert settings.amneziawg_enabled
    iface = {}
    in_interface = False
    with settings.amneziawg_config.open(encoding="utf-8") as source:
        for line in source:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_interface = stripped.lower() == "[interface]"
            elif in_interface and "=" in stripped and not stripped.startswith(("#", ";")):
                key, value = stripped.split("=", 1)
                iface[key.strip().lower()] = value.strip()
    private = base64.b64decode(iface["privatekey"], validate=True)
    derived = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert base64.b64encode(derived).decode() == settings.amneziawg_server_public_key
    assert int(iface["listenport"]) == settings.amneziawg_listen_port
    addresses = [ipaddress.ip_interface(value.strip()) for value in iface["address"].split(",")]
    assert any(
        address.ip == settings.amneziawg_server_address
        and address.network == settings.amneziawg_network
        for address in addresses
    )
    values = {
        "Jc": settings.amneziawg_jc,
        "Jmin": settings.amneziawg_jmin,
        "Jmax": settings.amneziawg_jmax,
        "S1": settings.amneziawg_s1,
        "S2": settings.amneziawg_s2,
        "S3": settings.amneziawg_s3,
        "S4": settings.amneziawg_s4,
        "H1": settings.amneziawg_h1,
        "H2": settings.amneziawg_h2,
        "H3": settings.amneziawg_h3,
        "H4": settings.amneziawg_h4,
        "I1": settings.amneziawg_i1,
        "I2": settings.amneziawg_i2,
        "I3": settings.amneziawg_i3,
        "I4": settings.amneziawg_i4,
        "I5": settings.amneziawg_i5,
    }
    assert all(iface.get(key.lower(), "").strip() == str(value).strip() for key, value in values.items())
except Exception:
    print("awg_compatibility=failed")
    sys.exit(1)
print("awg_compatibility=pass")
PY

set -a
# shellcheck disable=SC1090
. "$web_env"
set +a
"$venv/bin/kenai-backup" create || fail encrypted_backup_failed
install -d -o root -g root -m 0700 "$backup_dir"
cp -a -- "$web_env" "$backup_dir/web.env"
systemctl cat kenai-vpn-web.service > "$backup_dir/kenai-vpn-web.unit.txt"

install -d -o root -g root -m 0755 "$release"
tar -xzf "$archive" -C "$release"
chown -R root:root "$release"
find "$release" -type d -exec chmod 0755 {} +
find "$release" -type f -exec chmod 0644 {} +
[[ -f $release/src/kenai_vpn_admin/application/services.py ]] || fail release_incomplete
PYTHONPATH="$release/src" "$venv/bin/python" -c \
    'from kenai_vpn_admin.application.services import AdminService' || fail release_import_failed

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
install -d -o root -g root -m 0755 "$(dirname "$dropin")"
printf '[Service]\nEnvironment=PYTHONPATH=%s/src\n' "$release" > "$dropin"
chmod 0644 "$dropin"
systemctl daemon-reload
systemctl restart kenai-vpn-web.service
systemctl is-active --quiet kenai-vpn-web.service
curl --silent --show-error --fail --insecure --max-time 10 \
    https://10.66.66.1:8443/healthz >/dev/null
systemctl is-active --quiet xray
systemctl is-active --quiet awg-quick@awg0
systemctl is-active --quiet kenai-vpn-helper
trap - ERR
printf 'dual_protocol_upgrade=pass\nweb_release=%s\nbackup_directory=%s\n' "$release" "$backup_dir"
