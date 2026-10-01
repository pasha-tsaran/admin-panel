#!/usr/bin/env bash
# Armenia: allow NL to read only the active VLESS user manifest.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
[[ -f /root/kenai-nl-sync-key-20260926.pub ]] || exit 1
[[ -f /root/export-active-vless-20260926.py ]] || exit 1
[[ ! -e /root/.ssh/authorized_keys.pre-nl-20260926 ]] || exit 1
install -d -o root -g root -m 0755 /usr/local/libexec/kenai
install -o root -g root -m 0755 /root/export-active-vless-20260926.py \
    /usr/local/libexec/kenai/export-active-vless.py
cp -p -- /root/.ssh/authorized_keys /root/.ssh/authorized_keys.pre-nl-20260926
python3 - <<'PY'
from pathlib import Path

key = Path("/root/kenai-nl-sync-key-20260926.pub").read_text().strip()
parts = key.split()
if len(parts) < 2 or parts[0] != "ssh-ed25519" or len(parts[1]) < 40:
    raise ValueError("Invalid Netherlands SSH public key")
path = Path("/root/.ssh/authorized_keys")
entry = (
    'restrict,from="147.45.231.194",'
    'command="/usr/local/libexec/kenai/export-active-vless.py" '
    f"{parts[0]} {parts[1]} kenai-nl-sync\n"
)
with path.open("a", encoding="utf-8") as output:
    output.write(entry)
path.chmod(0o600)
PY
python3 /usr/local/libexec/kenai/export-active-vless.py | \
    python3 -c 'import json,sys; p=json.load(sys.stdin); print("active_vless_clients="+str(len(p["clients"])))'
/usr/sbin/sshd -t
printf 'nl_export=authorized\n'
