#!/usr/bin/env bash
# Upgrade the prepared Netherlands AWG 3.1 node to mirror Armenia's active peers.
set -Eeuo pipefail
umask 077

[[ $EUID == 0 ]] || exit 1
for path in /root/sync-direct-exit.py /root/kenai-nl-sync.service \
    /root/kenai-nl-sync.timer /etc/kenai-awg31/awg0.conf; do
    [[ -f $path ]] || exit 1
done
[[ $(docker inspect -f '{{.Config.Image}}' kenai-awg31) == \
    amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72 ]] || exit 1

backup=/var/backups/kenai-awg31/upgrade-20260927-r2
[[ ! -e $backup ]] || exit 1
install -d -m 0700 "$backup"
cp -p /etc/kenai-awg31/awg0.conf "$backup/awg0.conf"
cp -p /usr/local/libexec/kenai/sync-direct-exit.py "$backup/sync-direct-exit.py"
cp -p /etc/systemd/system/kenai-nl-sync.service "$backup/kenai-nl-sync.service"
cp -p /etc/systemd/system/kenai-nl-sync.timer "$backup/kenai-nl-sync.timer"

rollback() {
    trap - ERR
    systemctl stop kenai-nl-sync.timer || true
    cp -p "$backup/awg0.conf" /etc/kenai-awg31/awg0.conf
    cp -p "$backup/sync-direct-exit.py" /usr/local/libexec/kenai/sync-direct-exit.py
    cp -p "$backup/kenai-nl-sync.service" /etc/systemd/system/kenai-nl-sync.service
    cp -p "$backup/kenai-nl-sync.timer" /etc/systemd/system/kenai-nl-sync.timer
    rm -f /etc/kenai-awg31/interface.conf
    docker rm -f kenai-awg31 >/dev/null 2>&1 || true
    docker run -d --name kenai-awg31 --restart unless-stopped --network host \
        --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh \
        -v /etc/kenai-awg31/awg0.conf:/etc/amnezia/awg/awg0.conf:ro \
        amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72 \
        -ec 'awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; awg-quick up /etc/amnezia/awg/awg0.conf; trap "awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
        >/dev/null || true
    systemctl daemon-reload
    systemctl start kenai-nl-sync.timer || true
    printf 'nl_awg31_sync=rolled_back\n' >&2
    exit 1
}
trap rollback ERR

systemctl stop kenai-nl-sync.timer
python3 - <<'PY'
from pathlib import Path

source = Path("/etc/kenai-awg31/awg0.conf").read_text(encoding="utf-8")
interface = source.split("[Peer]", 1)[0].rstrip() + "\n"
if interface.count("[Interface]") != 1 or "[Peer]" in interface:
    raise ValueError("Invalid AWG interface block")
if "Address = 10.68.68.1/24" not in interface:
    raise ValueError("Unexpected staging AWG address")
interface = interface.replace("10.68.68.1/24", "10.67.67.1/24")
interface = interface.replace("10.68.68.0/24", "10.67.67.0/24")
required = (
    "ListenPort = 443",
    "HeaderProtectionKey = ",
    "RandomTrailers = on",
    "DisableCookies = on",
)
if not all(value in interface for value in required):
    raise ValueError("Incomplete AWG 3.1 interface block")
Path("/etc/kenai-awg31/interface.conf").write_text(interface, encoding="utf-8")
Path("/etc/kenai-awg31/awg0.conf").write_text(interface, encoding="utf-8")
PY
chmod 0600 /etc/kenai-awg31/interface.conf /etc/kenai-awg31/awg0.conf
install -o root -g root -m 0755 /root/sync-direct-exit.py \
    /usr/local/libexec/kenai/sync-direct-exit.py
install -o root -g root -m 0644 /root/kenai-nl-sync.service \
    /etc/systemd/system/kenai-nl-sync.service
install -o root -g root -m 0644 /root/kenai-nl-sync.timer \
    /etc/systemd/system/kenai-nl-sync.timer

docker rm -f kenai-awg31 >/dev/null
docker run -d --name kenai-awg31 --restart unless-stopped --network host \
    --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh \
    -v /etc/kenai-awg31:/etc/amnezia/awg:ro \
    amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72 \
    -ec 'awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; awg-quick up /etc/amnezia/awg/awg0.conf; trap "awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
    >/dev/null

systemctl daemon-reload
systemd-analyze verify kenai-nl-sync.service kenai-nl-sync.timer
systemctl start kenai-nl-sync.service
systemctl enable --now kenai-nl-sync.timer >/dev/null

systemctl is-active --quiet xray.service kenai-nl-sync.timer
[[ $(docker inspect -f '{{.State.Status}}' kenai-awg31) == running ]]
[[ $(docker inspect -f '{{json .HostConfig.Binds}}' kenai-awg31) == \
    '["/etc/kenai-awg31:/etc/amnezia/awg:ro"]' ]]
[[ $(grep -c '^\[Peer\]$' /etc/kenai-awg31/awg0.conf) -gt 0 ]]
docker exec kenai-awg31 awg show awg0 >/dev/null
ip -4 address show dev awg0 | grep -q '10.67.67.1/24'
ss -H -lnup | grep -q '0.0.0.0:443'
ss -H -lntp | grep -q ':443'
trap - ERR
printf 'nl_awg31_sync=enabled\n'
