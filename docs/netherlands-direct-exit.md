# Netherlands direct exit (updated 2026-09-27)

The Netherlands VPS `147.45.231.194` is a separate, direct VLESS/REALITY and
AmneziaWG 3.1 exit. TCP/443 remains assigned to Xray; AWG uses UDP/443.
It is **not** an Armenia relay and does not host the admin panel, database,
Telegram worker, or activation API. Armenia remains the account authority.
The Windows client receives a distinct NL URI under `locations.netherlands-1.vless`
from the existing authenticated `/api/v1/activate` response; older clients
ignore this additive field. No private REALITY key or VLESS UUID belongs in Git.

AmneziaWG peers use the same per-device private key and `10.67.67.x/32`
address already issued for Armenia. The API replaces only the server public
key, endpoint and 3.1 obfuscation settings. Armenia remains on AWG 2.0, and the
desktop client stores distinct opaque handles for the two locations.

## Access lifecycle

Armenia Xray is the source of the active VLESS UUID allowlist. A restricted SSH
key on NL can execute only `export-active-vless.py` on Armenia, and only from
the NL IP. The NL timer fetches this allowlist every 30 seconds, validates the
manifest and atomically tests/reloads its own Xray config. NL has an independent
REALITY key and short ID. New credentials and revocations therefore take up to
roughly 30 seconds to propagate; this is not instantaneous authorization.
The same manifest carries the public AWG peer keys and addresses, never client
private keys. If synchronization has not succeeded for 180 seconds, the timer
stops NL Xray and the AWG container instead of serving stale revoked
credentials. Xray is deliberately disabled as an independent boot unit; a
successful sync starts both exits after reboot.

The NL server has Debian 13, Xray 26.3.27, TCP/443 and its own working IPv6
egress. This setup does not alter Armenia's Xray listener or existing clients.
The Windows client keeps separate opaque service profile handles for Armenia
and NL; choosing NL cannot silently reuse the Armenian handle.

Windows service 2.3.1 adds an endpoint-scoped Firefox handshake override for NL
after concurrent Chrome handshakes stalled on the tested direct path. Cached
profiles continue to work without API changes; see
`client/docs/releases/2.3.1.md` in the repository root for evidence and limits.

## Production rollout and checks

The reviewed scripts are in `deploy/direct-exit/`. The bootstrap transfers a
hash-checked Xray binary and the scripts over pinned SSH, prepares the NL
service without starting it, then authorizes a forced export command on Armenia.
The Armenian SSH host key on NL must be compared to a previously trusted
fingerprint before installing `armenia-known-hosts`. The first sync generates
and tests the NL config. Only then should the narrow web-only API update run.
The API release copies the *live* support-chat source tree and patches only
activation/configuration, because that live tree differs from the repository's
newer panel source. It backs up `web.env` and the web drop-in, checks exact
source hashes, and rolls them back if the web service fails health checks.
The Telegram worker and Armenian VPN/helper are not switched to the new tree.

Verification on 2026-09-26:

- NL Xray config passed `xray run -test`, TCP/443 was reachable externally,
  and the mirrored active-client count matched Armenia.
- An isolated SOCKS/Xray probe on Armenia connected directly to NL without
  changing system proxy, DNS or routes. Cloudflare's trace identified the exit
  country as NL. The probe's temporary profile was removed.
- A successful production activation returned distinct Armenia and NL VLESS
  URIs for the same authorized device. No key or URI was printed.
- After deployment, `kenai-vpn-web`, `kenai-vpn-helper`, `xray`,
  `kenai-vpn-support` remained active on Armenia.

These checks do **not** replace a Windows-client end-to-end connection test or
testing on a clean machine. The desktop app must be rebuilt and updated before
NL appears in its server list.

## Rollback

To remove NL access without touching Armenia, stop and disable
`kenai-nl-sync.timer`, then stop `xray.service` on NL. To remove the API field,
restore `/etc/kenai-vpn/web.env` and the web drop-in from
`/var/backups/kenai-vpn-admin/direct-nl-20260926`, reload systemd, and restart
only `kenai-vpn-web`. The previous release remains at
`/opt/kenai-vpn/releases/support-chat-20260920-r1`. The existing Armenian
Xray config, helper, database and support worker are not part of this rollback.
