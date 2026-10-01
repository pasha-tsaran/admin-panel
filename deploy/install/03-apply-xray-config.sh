#!/usr/bin/env bash
set -euo pipefail

# Apply a previously generated and reviewed Xray JSON with validation and rollback.
# This script installs no packages and accepts no shell fragments.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 /absolute/candidate.json /absolute/live-config.json" >&2
  exit 2
fi

candidate="$1"
live_config="$2"
xray_bin="/usr/local/bin/xray"
systemctl_bin="/usr/bin/systemctl"
backup_root="/var/backups/kenai-vpn/xray"

if [[ "${candidate}" != /* || "${live_config}" != /* ]]; then
  echo "Both paths must be absolute." >&2
  exit 2
fi
if [[ ! -f "${candidate}" || -L "${candidate}" ]]; then
  echo "Candidate must be a regular non-symlink file." >&2
  exit 2
fi
if [[ -e "${live_config}" && (! -f "${live_config}" || -L "${live_config}") ]]; then
  echo "Live config must be absent or a regular non-symlink file." >&2
  exit 2
fi
if [[ ! -x "${xray_bin}" || ! -x "${systemctl_bin}" ]]; then
  echo "Pinned Xray and systemctl binaries are required." >&2
  exit 1
fi

"${xray_bin}" run -test -config "${candidate}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${backup_root}/${timestamp}"
install -d -m 0700 -o root -g root "${backup_dir}"
had_live_config="false"
if [[ -f "${live_config}" ]]; then
  had_live_config="true"
  install -m 0600 -o root -g root "${live_config}" "${backup_dir}/config.json"
fi

install -d -m 0755 -o root -g root "$(dirname "${live_config}")"
staged="$(dirname "${live_config}")/.kenai-xray-${timestamp}.json"
install -m 0600 -o root -g root "${candidate}" "${staged}"

rollback() {
  if [[ "${had_live_config}" == "true" ]]; then
    install -m 0600 -o root -g root "${backup_dir}/config.json" "${live_config}"
    "${systemctl_bin}" reload-or-restart xray.service || true
  else
    mv -- "${live_config}" "${backup_dir}/failed-config.json" 2>/dev/null || true
    "${systemctl_bin}" stop xray.service || true
  fi
}
trap rollback ERR

mv -- "${staged}" "${live_config}"
"${systemctl_bin}" reload-or-restart xray.service
"${systemctl_bin}" is-active --quiet xray.service
"${xray_bin}" run -test -config "${live_config}"

trap - ERR
echo "xray_config_applied=yes"
echo "xray_backup=${backup_dir}"
