#!/usr/bin/env bash
# Narrow live web-only update; keeps Armenia Xray/helper and support worker unchanged.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
old=/opt/kenai-vpn/releases/support-chat-20260920-r1
new=/opt/kenai-vpn/releases/direct-nl-20260926
backup=/var/backups/kenai-vpn-admin/direct-nl-20260926
dropin=/etc/systemd/system/kenai-vpn-web.service.d/30-support.conf
env_file=/etc/kenai-vpn/web.env
public=/root/nl-public-20260926.json
module=/root/kenai-nl-direct-locations-20260926.py
[[ -d $old/src && ! -e $new && ! -e $backup ]] || exit 1
[[ -f $public && -f $module ]] || exit 1
[[ $(sha256sum "$old/src/kenai_vpn_admin/web/routes.py" | cut -d' ' -f1) == \
   c340d77d61db2e6982614c18f4f77ff1adc95fab00172292f299dac05d451f2f ]] || exit 1
[[ $(sha256sum "$old/src/kenai_vpn_admin/config.py" | cut -d' ' -f1) == \
   a557ff228f828dafc41ef267e94eb43eb172a3a6ca412fa523394103a781a5a9 ]] || exit 1
grep -qx "Environment=PYTHONPATH=$old/src" "$dropin"
systemctl is-active --quiet xray.service kenai-vpn-helper.service kenai-vpn-web.service \
    kenai-vpn-support.service postgresql.service nginx.service

install -d -o root -g root -m 0700 "$backup"
cp -p -- "$dropin" "$backup/web-dropin.conf"
cp -p -- "$env_file" "$backup/web.env"
cp -a -- "$old" "$new"
install -o root -g root -m 0644 "$module" \
    "$new/src/kenai_vpn_admin/application/direct_locations.py"
python3 - "$new" "$public" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]) / "src/kenai_vpn_admin"
routes = root / "web/routes.py"
text = routes.read_text()
anchor = '    if account is None:\n        raise HTTPException(status_code=401, detail="Invalid activation key")\n'
assert text.count(anchor) == 1
text = text.replace(anchor, anchor + '    netherlands = request.app.state.settings.netherlands_exit\n')
anchor = '            "subscription": {\n                "status": "active",\n'
assert text.count(anchor) >= 1
text = text.replace(anchor,
    '            "locations": (\n'
    '                {"netherlands-1": {"vless": netherlands.profile_from(account.vless_uri)}}\n'
    '                if netherlands is not None and account.vless_uri is not None\n'
    '                else {}\n'
    '            ),\n' + anchor, 1)
routes.write_text(text)

config = root / "config.py"
text = config.read_text()
anchor = 'from kenai_vpn_admin.domain.enums import Protocol\n'
assert text.count(anchor) == 1
text = text.replace(anchor, 'from kenai_vpn_admin.application.direct_locations import DirectVlessExit\n' + anchor)
anchor = '    support_telegram_admin_ids: str = ""\n'
assert text.count(anchor) == 1
text = text.replace(anchor, anchor +
    '    netherlands_address: str = ""\n'
    '    netherlands_server_name: str = ""\n'
    '    netherlands_public_key: str = ""\n'
    '    netherlands_short_id: str = ""\n\n'
    '    @property\n'
    '    def netherlands_exit(self) -> DirectVlessExit | None:\n'
    '        values = (self.netherlands_address, self.netherlands_server_name,\n'
    '                  self.netherlands_public_key, self.netherlands_short_id)\n'
    '        if not any(values):\n'
    '            return None\n'
    '        if not all(values):\n'
    '            raise ValueError("Incomplete Netherlands direct-exit configuration")\n'
    '        return DirectVlessExit(*values)\n')
config.write_text(text)

public = json.loads(Path(sys.argv[2]).read_text())
assert public['address'] == '147.45.231.194'
from importlib.util import module_from_spec, spec_from_file_location
spec = spec_from_file_location('direct_locations', root / 'application/direct_locations.py')
assert spec and spec.loader
module = module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.DirectVlessExit(public['address'], public['server_name'],
                       public['public_key'], public['short_id'])
PY
python3 -m compileall -q "$new/src/kenai_vpn_admin"

rollback() {
    trap - ERR
    cp -p -- "$backup/web.env" "$env_file"
    cp -p -- "$backup/web-dropin.conf" "$dropin"
    systemctl daemon-reload
    systemctl restart kenai-vpn-web.service || true
    printf 'nl_api=rolled_back\n' >&2
    exit 1
}
trap rollback ERR
python3 - "$env_file" "$public" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
content = path.read_text()
assert 'KENAI_NETHERLANDS_' not in content
public = json.loads(Path(sys.argv[2]).read_text())
for name, key in (("ADDRESS", "address"), ("SERVER_NAME", "server_name"),
                  ("PUBLIC_KEY", "public_key"), ("SHORT_ID", "short_id")):
    content += f"\nKENAI_NETHERLANDS_{name}={public[key]}"
content += "\n"
stat = path.stat()
fd, name = tempfile.mkstemp(prefix='.web-env-', dir=path.parent)
with os.fdopen(fd, 'w') as output:
    os.fchown(output.fileno(), stat.st_uid, stat.st_gid)
    os.fchmod(output.fileno(), stat.st_mode & 0o777)
    output.write(content)
    output.flush()
    os.fsync(output.fileno())
os.replace(name, path)
PY
printf '[Service]\nEnvironment=PYTHONPATH=%s/src\n' "$new" > "$dropin"
chmod 0644 "$dropin"
systemctl daemon-reload
systemd-analyze verify kenai-vpn-web.service
set -a
. "$env_file"
set +a
export PYTHONPATH="$new/src"
cd "$new"
runuser --preserve-environment -u vpnadmin -- \
    /opt/kenai-vpn/venv-20260913/bin/python - <<'PY'
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.main import app
assert Settings().netherlands_exit is not None
assert '/api/v1/activate' in app.openapi()['paths']
print('nl_api_preflight=pass')
PY
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
    kenai-vpn-helper.service xray.service
trap - ERR
printf 'nl_api=enabled; armenia_xray=unchanged\n'
