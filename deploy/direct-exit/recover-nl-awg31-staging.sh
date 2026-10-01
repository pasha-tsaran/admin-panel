#!/usr/bin/env bash
# Restore the pre-sync NL AWG 3.1 staging container from the upgrade backup.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
backup=/var/backups/kenai-awg31/upgrade-20260927
[[ -f $backup/awg0.conf ]] || exit 1
cp -p "$backup/awg0.conf" /etc/kenai-awg31/awg0.conf
rm -f /etc/kenai-awg31/interface.conf
docker rm -f kenai-awg31 >/dev/null 2>&1 || true
docker run -d --name kenai-awg31 --restart unless-stopped --network host \
    --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh \
    -v /etc/kenai-awg31/awg0.conf:/etc/amnezia/awg/awg0.conf:ro \
    amneziavpn/amneziawg-go@sha256:cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72 \
    -ec 'awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; awg-quick up /etc/amnezia/awg/awg0.conf; trap "awg-quick down /etc/amnezia/awg/awg0.conf >/dev/null 2>&1 || true; exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
    >/dev/null
[[ $(docker inspect -f '{{.State.Status}}' kenai-awg31) == running ]]
docker exec kenai-awg31 awg show awg0 >/dev/null
ss -H -lnup | grep -q '0.0.0.0:443'
printf 'nl_awg31_staging=recovered\n'
