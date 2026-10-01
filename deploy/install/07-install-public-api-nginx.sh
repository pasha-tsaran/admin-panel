#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'api_nginx_error=root_required' >&2; exit 1; }
[[ -f /etc/letsencrypt/live/88.218.94.3/fullchain.pem ]] \
    || { echo 'api_nginx_error=certificate_missing' >&2; exit 1; }
[[ -f /etc/kenai-vpn/tls/ca.crt ]] \
    || { echo 'api_nginx_error=upstream_ca_missing' >&2; exit 1; }
[[ ! -e /etc/nginx/sites-available/kenai-api-ip ]] \
    || { echo 'api_nginx_error=site_exists' >&2; exit 1; }
[[ ! -e /etc/nginx/sites-enabled/kenai-api-ip ]] \
    || { echo 'api_nginx_error=site_enabled' >&2; exit 1; }
[[ ! -e /etc/nginx/kenai-upstream-ca.crt ]] \
    || { echo 'api_nginx_error=upstream_ca_copy_exists' >&2; exit 1; }

install -o root -g root -m 0644 /etc/kenai-vpn/tls/ca.crt /etc/nginx/kenai-upstream-ca.crt
install -o root -g root -m 0644 /home/codexuser/kenai-api-ip.conf \
    /etc/nginx/sites-available/kenai-api-ip
ln -s /etc/nginx/sites-available/kenai-api-ip /etc/nginx/sites-enabled/kenai-api-ip

if ! nginx -t || ! systemctl reload nginx.service; then
    unlink /etc/nginx/sites-enabled/kenai-api-ip
    nginx -t
    systemctl reload nginx.service
    echo 'api_nginx_error=site_reverted' >&2
    exit 1
fi

echo 'api_https_site=active'
echo 'public_firewall_unchanged=yes'
