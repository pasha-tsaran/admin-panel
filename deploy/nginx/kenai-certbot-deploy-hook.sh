#!/bin/sh
set -eu

if [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/88.218.94.3 ]; then
    /usr/sbin/nginx -t
    /usr/bin/systemctl reload nginx.service
fi
