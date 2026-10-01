#!/usr/bin/env bash
set -euo pipefail

# Read-only helper for checking a proposed REALITY target with the exact pinned core.

if [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 hostname[:port]" >&2
  exit 2
fi
target="$1"
if [[ ! "${target}" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
  echo "Target must be a hostname with an optional port." >&2
  exit 2
fi
xray_bin="/usr/local/bin/xray"
if [[ ! -x "${xray_bin}" ]]; then
  echo "Pinned Xray binary is not installed at ${xray_bin}." >&2
  exit 1
fi

"${xray_bin}" tls ping "${target}"
echo "Check that the chosen serverName is present in the certificate SAN above."
echo "Prefer a stable target in the same ASN as the VPS; this script cannot prove that property."
