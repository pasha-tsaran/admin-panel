#!/usr/bin/env bash
# Prepare a clean Debian 13 Netherlands VPS. Does not enable the VPN yet.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
[[ $# == 1 && $1 =~ ^[a-zA-Z0-9.-]+$ ]] || exit 1
[[ $(. /etc/os-release; printf '%s' "$ID:$VERSION_ID") == debian:13 ]] || exit 1
[[ ! -e /usr/local/etc/xray/config.json ]] || exit 1
[[ $(sha256sum /root/xray-staging-20260926 | cut -d' ' -f1) == \
   8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed ]] || exit 1

id -u xray >/dev/null 2>&1 || useradd --system --user-group --no-create-home \
    --home-dir /var/lib/xray --shell /usr/sbin/nologin xray
install -d -o root -g root -m 0755 /usr/local/etc/xray /usr/local/libexec/kenai
install -d -o root -g root -m 0700 /etc/kenai-vpn
install -o root -g root -m 0755 /root/xray-staging-20260926 /usr/local/bin/xray
install -o root -g root -m 0644 /root/kenai-nl-deploy/xray.service /etc/systemd/system/xray.service
install -o root -g root -m 0644 /root/kenai-nl-deploy/kenai-nl-sync.service /etc/systemd/system/kenai-nl-sync.service
install -o root -g root -m 0644 /root/kenai-nl-deploy/kenai-nl-sync.timer /etc/systemd/system/kenai-nl-sync.timer
install -o root -g root -m 0755 /root/kenai-nl-deploy/sync-direct-exit.py /usr/local/libexec/kenai/sync-direct-exit.py
ssh-keygen -q -t ed25519 -N '' -f /etc/kenai-vpn/armenia-sync-key
python3 - "$1" <<'PY'
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

target = sys.argv[1]
output = subprocess.run(["/usr/local/bin/xray", "x25519"], capture_output=True,
                        text=True, check=True, timeout=10).stdout
fields = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
private_key = fields["PrivateKey"].strip()
public_key = fields["Password (PublicKey)"].strip()
if not re.fullmatch(r"[A-Za-z0-9_-]{43}", private_key):
    raise ValueError("Invalid REALITY private key")
if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
    raise ValueError("Invalid REALITY public key")
short_id = secrets.token_hex(4)
private = {"target": f"{target}:443", "server_name": target,
           "private_key": private_key, "short_id": short_id}
public = {"address": "147.45.231.194", "server_name": target,
          "public_key": public_key, "short_id": short_id}
for name, value in (("nl-reality.json", private), ("nl-public.json", public)):
    path = Path("/etc/kenai-vpn") / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
PY
systemctl daemon-reload
systemd-analyze verify xray.service kenai-nl-sync.service kenai-nl-sync.timer
printf 'nl_prepare=ready; vpn_not_enabled\n'
