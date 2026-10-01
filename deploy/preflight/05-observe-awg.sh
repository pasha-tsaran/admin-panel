#!/usr/bin/env bash
# A passive 90-second capture; no route, firewall, daemon or profile changes.
set -euo pipefail
[[ $EUID == 0 ]] || { echo root_required; exit 1; }
[[ -x /usr/bin/tcpdump && -x /usr/bin/python3 ]] || { echo capture_tools_missing; exit 1; }
umask 022
report_dir=$(mktemp -d /var/tmp/kenai-awg-observe.XXXXXXXX)
chmod 0755 "$report_dir"
nohup /usr/bin/python3 /home/codexuser/awg_packet_observer.py "$report_dir/result.json" \
    </dev/null >/dev/null 2>"$report_dir/observer-error.log" &
printf 'observer_started=yes\nreport_path=%s/result.json\nduration_seconds=90\n' "$report_dir"
