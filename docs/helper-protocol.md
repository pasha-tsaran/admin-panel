# Privileged helper protocol

The production web process never runs as root and never invokes WireGuard, Xray, systemd,
or nftables directly. It talks to a minimal root-owned helper through an `AF_UNIX` stream
socket.

## Trust boundary

- The socket is created below `/run/kenai-vpn` and is not exposed over TCP.
- The helper verifies the caller UID using Linux `SO_PEERCRED`.
- Messages are newline-delimited JSON and limited to 64 KiB.
- Pydantic models reject unknown fields, wrong types, unsafe device references, and unknown
  operations.
- No request may contain an executable path, filesystem path, shell fragment, or arbitrary
  command.
- The helper command runner accepts only absolute, preconfigured executable paths, always
  uses `shell=False`, has a timeout, and does not expose stdout/stderr in errors.

## Version 1 operations

| Operation | Input | Result |
| --- | --- | --- |
| `issue` | safe device reference, one or both protocols | typed credential records |
| `set_enabled` | device reference, protocol, boolean | change acknowledgement |
| `revoke` | device reference, protocol | change acknowledgement |
| `health` | empty object | WireGuard/Xray/firewall state |
| `device_status` | validated `device_ref` | Per-device runtime state; WireGuard handshake and WG/Xray byte counters, no key material |

`device_status` resolves a managed WireGuard public key inside the privileged helper and returns
only connection metadata. Public/private keys, endpoints, UUIDs, and client material never cross
the socket for this operation. VLESS traffic uses `xray api statsquery` and its current online
state uses `xray api statsonline`, both with the exact managed device reference. Traffic queries
use `reset=false`. The configured Stats API endpoint is restricted to IPv4 or
IPv6 loopback; it must never be exposed publicly. When it is not configured, VLESS still reports
its configuration state and zero counters so the UI can label statistics as unavailable.

Every envelope carries protocol version `1`, a UUID request ID, and a strict payload. Every
response echoes the request ID and is either a typed success or a sanitized error.

## Implementation status

The transport contract, unprivileged client, peer-credential check, bounded framing, safe
command runner, WireGuard adapter, Xray adapter, cross-protocol rollback, and root-only entrypoint
are implemented. Automated tests operate exclusively on temporary configuration copies. On
2026-08-28 the adapters also passed a non-mutating VPS staging run against temporary copies of the
live configuration, using the native WireGuard and Xray validators while intercepting all runtime
mutations.

## Configuration mutation

- WireGuard peers are bounded by `# BEGIN KENAI <device-ref>` markers. Existing unmanaged peers
  are preserved.
- Xray clients are managed only inside one explicitly configured inbound tag. Other inbounds and
  outbounds are preserved.
- A candidate inherits the owner, group, and mode of the active configuration and is validated by
  the native service binary using the filename expected by that validator (`wg0.conf` or
  `config.json`).
- The validated candidate atomically replaces the active file.
- Runtime activation uses fixed allowlisted commands. Activation failure restores the previous
  file and attempts to reactivate it.
- Helper state is root-owned mode 0600. Full client configurations and WireGuard private keys are
  never stored there; VLESS UUID and public WireGuard peer data are retained to support re-enable.

## Change rule

Protocol changes require a version decision, contract tests, backward-compatibility analysis,
and updates to this document. Never silently add an arbitrary-command operation.

## Windows routing considerations

Generated profiles use `AllowedIPs = 0.0.0.0/0, ::/0` for full-tunnel routing. WireGuard on
Windows automatically creates a persistent route to the endpoint IP, so handshake packets are
not blocked by the full-tunnel setting.

**Known conflict**: When a second VPN client (e.g. Amnezia/hidemy.name) is active on the same
machine, its routing table can intercept or conflict with WireGuard's routes, causing handshake
failures even though the WireGuard config itself is correct. On the affected machine the external
IP was `91.195.254.67` (Amnezia proxy) instead of the VPS IP `88.218.94.3`.

**Resolution**: Disable or uninstall the conflicting VPN client before connecting to Kenai VPN.
Do not change `AllowedIPs` in server-generated profiles to work around third-party VPN conflicts.
