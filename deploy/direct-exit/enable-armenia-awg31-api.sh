#!/usr/bin/env bash
# Add the Netherlands AWG 3.1 profile to the existing authenticated activation API.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1

old=/opt/kenai-vpn/releases/panel-20260926T180615Z
new=/opt/kenai-vpn/releases/awg31-20260927
backup=/var/backups/kenai-vpn-admin/awg31-api-20260927
dropin=/etc/systemd/system/kenai-vpn-web.service.d/30-support.conf
env_file=/etc/kenai-vpn/web.env
staging=/root/kenai-awg31-api
awg_env=/root/nl-awg31-public.env
[[ -d $old/src && ! -e $new && ! -e $backup ]] || exit 1
for path in config.py main.py web/routes.py application/direct_locations.py; do
    [[ -f $staging/$path ]] || exit 1
done
[[ -f $awg_env ]] || exit 1
grep -qx 'Environment=PYTHONPATH=/opt/kenai-vpn/releases/panel-20260926T180615Z/src' "$dropin"
[[ $(sha256sum "$old/src/kenai_vpn_admin/config.py" | cut -d' ' -f1) == \
    142f7b0e5adddf42539bbb314346135aec80320ae96bdafc5de83f06073164a5 ]]
[[ $(sha256sum "$old/src/kenai_vpn_admin/web/routes.py" | cut -d' ' -f1) == \
    0a43ff898634e5451cb436989c30680e4291f9d0d5f940d6f8ca2434aa71aed1 ]]
systemctl is-active --quiet kenai-vpn-web.service kenai-vpn-helper.service \
    kenai-vpn-support.service xray.service postgresql.service nginx.service

install -d -o root -g root -m 0700 "$backup"
cp -p "$dropin" "$backup/web-dropin.conf"
cp -p "$env_file" "$backup/web.env"
cp -a "$old" "$new"
for path in config.py main.py web/routes.py application/direct_locations.py; do
    install -o root -g root -m 0644 "$staging/$path" \
        "$new/src/kenai_vpn_admin/$path"
done

rollback() {
    trap - ERR
    cp -p "$backup/web.env" "$env_file"
    cp -p "$backup/web-dropin.conf" "$dropin"
    systemctl daemon-reload
    systemctl restart kenai-vpn-web.service || true
    printf 'armenia_awg31_api=rolled_back\n' >&2
    exit 1
}
trap rollback ERR

python3 - "$env_file" "$awg_env" "$dropin" "$new" <<'PY'
import base64
import os
import sys
import tempfile
from pathlib import Path

env_path, awg_path, dropin_path, release = map(Path, sys.argv[1:])
content = env_path.read_text(encoding="utf-8")
if "KENAI_NETHERLANDS_AWG_" in content:
    raise ValueError("AWG environment is already configured")
lines = [line for line in awg_path.read_text(encoding="utf-8").splitlines() if line]
if len(lines) != 2:
    raise ValueError("Invalid AWG environment")
expected = {
    "KENAI_NETHERLANDS_AWG_PUBLIC_KEY",
    "KENAI_NETHERLANDS_AWG_HEADER_PROTECTION_KEY",
}
parsed = dict(line.split("=", 1) for line in lines)
if set(parsed) != expected:
    raise ValueError("Invalid AWG environment")
for value in parsed.values():
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Invalid AWG key")
content = content.rstrip() + "\n" + "\n".join(lines) + "\n"

def replace(path: Path, value: str) -> None:
    stat = path.stat()
    fd, name = tempfile.mkstemp(prefix=".awg31-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchown(output.fileno(), stat.st_uid, stat.st_gid)
            os.fchmod(output.fileno(), stat.st_mode & 0o777)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)

replace(env_path, content)
dropin = dropin_path.read_text(encoding="utf-8")
old = "Environment=PYTHONPATH=/opt/kenai-vpn/releases/panel-20260926T180615Z/src"
if dropin.count(old) != 1:
    raise ValueError("Unexpected web drop-in")
replace(dropin_path, dropin.replace(old, f"Environment=PYTHONPATH={release}/src"))
PY

python3 -m compileall -q "$new/src/kenai_vpn_admin"
set -a
. "$env_file"
set +a
export PYTHONPATH="$new/src"
cd "$new"
runuser --preserve-environment -u vpnadmin -- \
    /opt/kenai-vpn/venv-20260913/bin/python - <<'PY'
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.main import app

settings = Settings()
assert settings.netherlands_exit is not None
assert settings.netherlands_awg_exit is not None
assert "/api/v1/activate" in app.openapi()["paths"]
print("armenia_awg31_api_preflight=pass")
PY

systemctl daemon-reload
systemd-analyze verify kenai-vpn-web.service
systemctl restart kenai-vpn-web.service
for attempt in {1..20}; do
    code=$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' -d '{}' \
        https://88.218.94.3:9443/api/v1/activate) || true
    [[ $code == 422 ]] && break
    sleep 1
done
[[ $code == 422 ]]
systemctl is-active --quiet kenai-vpn-web.service kenai-vpn-support.service \
    kenai-vpn-helper.service xray.service postgresql.service nginx.service
trap - ERR
printf 'armenia_awg31_api=enabled\n'
