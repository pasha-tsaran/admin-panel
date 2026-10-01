# VPS read-only preflight

This gate discovers the exact shape of the already working WireGuard/Xray installation before
helper deployment. It does not install packages, edit configuration, reload services, change
firewall rules, or reboot the server.

## Script

Use `deploy/preflight/01-readonly-vps-inventory.sh`. Review it before transfer. Run it as root
because WireGuard and Xray configuration metadata may otherwise be inaccessible. Its stdout is
designed to omit:

- WireGuard private and public keys;
- VLESS client UUIDs;
- REALITY private keys and short IDs;
- complete WireGuard or Xray configurations.

The report intentionally includes public operational structure: file paths/modes/hashes, VPN
addresses, peer/client counts, inbound tags, ports, transport/security modes, REALITY server
names, binary versions, and service status.

## Path overrides

If the active files use different paths, pass them only for that invocation:

```bash
WG_CONFIG=/actual/path/wg0.conf \
XRAY_CONFIG=/actual/path/config.json \
bash ./01-readonly-vps-inventory.sh
```

Never guess the Xray path from a stale document. Confirm it from the service `ExecStart` value.

## Acceptance gate

Do not deploy the helper until all of the following are understood:

- both native configuration checks pass;
- the WireGuard managed pool does not collide with existing `AllowedIPs`;
- one exact Xray VLESS inbound tag is selected;
- helper binary paths match the VPS;
- existing configuration files are regular files rather than symlinks;
- the report contains no unexpected sensitive value;
- backup and rollback paths have been separately approved.

After review, create sanitized fixture copies locally and run the production-adapter integration
suite against their structure. The report alone does not authorize deployment.

## Verified VPS inventory (2026-08-27)

- Debian 13 amd64; all four services active/enabled; no failed units.
- WireGuard: `/etc/wireguard/wg0.conf`, regular `root:root` 0600, server
  `10.66.66.1/24`, one existing peer at `10.66.66.2/32`; native strip passes.
- Xray: `/usr/local/etc/xray/config.json`, regular `root:xray` 0640, Xray 26.3.27,
  one untagged VLESS/raw/REALITY inbound on TCP/443 and one existing client; native test passes.
- The adapter must preserve owner/group/mode and select the untagged inbound only when it is the
  unique VLESS inbound on the configured port.
- Sanitized structural fixtures live under `tests/fixtures/vps/`; they contain placeholders, not
  server credentials.
