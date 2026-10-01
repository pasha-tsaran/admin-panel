#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'acme_install_error=root_required' >&2; exit 1; }
[[ "$(readlink -f /etc/nginx/sites-enabled/default)" == /etc/nginx/sites-available/default ]] \
    || { echo 'acme_install_error=unexpected_default_site' >&2; exit 1; }
[[ ! -e /etc/nginx/sites-available/kenai-api-acme ]] \
    || { echo 'acme_install_error=site_exists' >&2; exit 1; }
[[ ! -e /etc/nginx/sites-enabled/kenai-api-acme ]] \
    || { echo 'acme_install_error=site_enabled' >&2; exit 1; }

install -d -o root -g root -m 0755 /var/www/kenai-acme/.well-known/acme-challenge
install -o root -g root -m 0644 /home/codexuser/kenai-api-acme.conf \
    /etc/nginx/sites-available/kenai-api-acme
ln -s /etc/nginx/sites-available/kenai-api-acme /etc/nginx/sites-enabled/kenai-api-acme
unlink /etc/nginx/sites-enabled/default

if ! nginx -t || ! systemctl reload nginx.service; then
    unlink /etc/nginx/sites-enabled/kenai-api-acme
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    nginx -t
    systemctl reload nginx.service
    echo 'acme_install_error=nginx_reverted' >&2
    exit 1
fi

echo 'acme_challenge_site=active'
echo 'vpn_services_unchanged=yes'
