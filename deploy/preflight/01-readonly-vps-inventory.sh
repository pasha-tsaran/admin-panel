#!/usr/bin/env bash
set -u

WG_CONFIG="${WG_CONFIG:-/etc/wireguard/wg0.conf}"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/etc/xray/config.json}"

section() {
    printf '\n=== %s ===\n' "$1"
}

status_value() {
    local value
    value="$("$@" 2>/dev/null)" || value="unavailable"
    printf '%s\n' "$value"
}

section "identity and platform"
printf 'timestamp_utc='; date -u +'%Y-%m-%dT%H:%M:%SZ'
printf 'effective_uid='; id -u
printf 'kernel='; uname -r
printf 'architecture='; dpkg --print-architecture 2>/dev/null || uname -m
. /etc/os-release
printf 'os=%s\n' "${PRETTY_NAME:-unknown}"

section "binary inventory"
for binary in wg wg-quick xray systemctl nft jq; do
    printf '%s=' "$binary"
    command -v "$binary" 2>/dev/null || printf 'missing\n'
done
printf 'wireguard_tools_version='; status_value wg --version
printf 'xray_version='; status_value xray version
printf 'nft_version='; status_value nft --version

section "service state"
for unit in ssh.service nftables.service wg-quick@wg0.service xray.service; do
    printf '%s_active=' "$unit"
    status_value systemctl is-active "$unit"
    printf '%s_enabled=' "$unit"
    status_value systemctl is-enabled "$unit"
done
printf 'failed_units='
systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk 'NF {count++} END {print count+0}'
printf 'xray_service_user='; status_value systemctl show xray.service --property=User --value
printf 'xray_exec_start='; status_value systemctl show xray.service --property=ExecStart --value

section "wireguard configuration metadata"
printf 'path=%s\n' "$WG_CONFIG"
if [[ -f "$WG_CONFIG" && ! -L "$WG_CONFIG" ]]; then
    stat -c 'type=regular owner=%U group=%G mode=%a size=%s' "$WG_CONFIG"
    printf 'sha256='; sha256sum "$WG_CONFIG" | awk '{print $1}'
    awk '
        /^\[Interface\][[:space:]]*$/ {section="interface"; next}
        /^\[Peer\][[:space:]]*$/ {section="peer"; peers++; next}
        section == "interface" && /^[[:space:]]*Address[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); print "server_address=" $0
        }
        section == "interface" && /^[[:space:]]*ListenPort[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); print "listen_port=" $0
        }
        section == "peer" && /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); print "peer_allowed_ips=" $0
        }
        /^[[:space:]]*(PostUp|PostDown|PreUp|PreDown|SaveConfig)[[:space:]]*=/ {
            split($0, parts, "="); gsub(/[[:space:]]/, "", parts[1]);
            print "special_directive=" parts[1]
        }
        END {print "peer_count=" peers+0}
    ' "$WG_CONFIG"
    printf 'wg_quick_strip_check='
    if wg-quick strip "$WG_CONFIG" >/dev/null 2>&1; then printf 'pass\n'; else printf 'fail\n'; fi
else
    printf 'status=missing_or_not_regular\n'
fi

section "wireguard runtime summary"
if ip link show wg0 >/dev/null 2>&1; then
    printf 'interface=present\n'
    printf 'listen_port='; wg show wg0 listen-port 2>/dev/null || printf 'unavailable\n'
    printf 'peer_count='; wg show wg0 peers 2>/dev/null | awk 'NF {count++} END {print count+0}'
else
    printf 'interface=absent\n'
fi

section "xray configuration metadata"
printf 'path=%s\n' "$XRAY_CONFIG"
if [[ -f "$XRAY_CONFIG" && ! -L "$XRAY_CONFIG" ]]; then
    stat -c 'type=regular owner=%U group=%G mode=%a size=%s' "$XRAY_CONFIG"
    printf 'sha256='; sha256sum "$XRAY_CONFIG" | awk '{print $1}'
    printf 'json_parse_check='
    if jq empty "$XRAY_CONFIG" >/dev/null 2>&1; then printf 'pass\n'; else printf 'fail\n'; fi
    jq -c '
        (.inbounds // [])[] |
        {
            tag: (.tag // null),
            protocol: (.protocol // null),
            listen: (.listen // null),
            port: (.port // null),
            client_count: ((.settings.clients // []) | length),
            transport: (.streamSettings.network // null),
            security: (.streamSettings.security // null),
            reality_server_names: (.streamSettings.realitySettings.serverNames // [])
        }
    ' "$XRAY_CONFIG" 2>/dev/null || printf 'inbound_summary=unavailable\n'
    printf 'xray_native_check='
    if xray run -test -config "$XRAY_CONFIG" >/dev/null 2>&1; then
        printf 'pass\n'
    else
        printf 'fail\n'
    fi
else
    printf 'status=missing_or_not_regular\n'
fi

section "network and firewall invariants"
printf 'ipv4_forward='; status_value sysctl -n net.ipv4.ip_forward
printf 'default_route='; ip -4 route show default 2>/dev/null || printf 'unavailable\n'
printf 'tcp_22_listener_count='
ss -Hltn '( sport = :22 )' 2>/dev/null | awk 'NF {count++} END {print count+0}'
printf 'tcp_443_listener_count='
ss -Hltn '( sport = :443 )' 2>/dev/null | awk 'NF {count++} END {print count+0}'
printf 'udp_51820_listener_count='
ss -Hlun '( sport = :51820 )' 2>/dev/null | awk 'NF {count++} END {print count+0}'
printf 'nft_ruleset_nonempty='
if nft list ruleset 2>/dev/null | grep -q '[^[:space:]]'; then printf 'yes\n'; else printf 'no\n'; fi

section "preflight result"
printf 'read_only_inventory=completed\n'
printf 'secrets_printed=no_private_keys_no_client_uuids_no_short_ids\n'
