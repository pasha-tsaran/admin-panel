# Client activation API

## Activate an account

`POST /api/v1/activate`

```json
{"activation_key":"KENAI-..."}
```

A valid active subscription returns account metadata and connection material for the protocols
enabled by `KENAI_SUBSCRIPTION_PROTOCOLS`. With `vless,amneziawg`, a Windows app installation
receives independent VLESS and AmneziaWG 2.0 profiles using the same 12-digit account key.
With `vless` only, `amneziawg` remains `null`. Invalid, disabled, incomplete, and unknown accounts all return the same
`401 Invalid activation key` response. Successful responses include `Cache-Control: no-store`.

The endpoint must be exposed only through production HTTPS. Activation keys contain exactly 12
random decimal digits. The API applies a persistent per-source failure limit because this format
has less entropy than the previous long token. A SHA-256 lookup hash and an encrypted recoverable
copy are stored; only authenticated administrators can reveal the latter. Client applications must
keep the key and returned profiles in operating-system secure storage and must never log them.

The key is a stable account credential, not the subscription period itself. When the configured
expiry passes, activation returns the same generic `401` response and the periodic expiry job
disables every credential issued for that subscription. An administrator can renew for 3 days,
30 days, a custom number of days, or a selected calendar date. Renewal restores the issued protocols while preserving
the existing activation key.

## Shared-key Windows MVP

The Windows client sends a stable random 32-character hexadecimal `device_id` alongside the same
12-digit `activation_key` on every installation. The server issues distinct VLESS and (when enabled)
AmneziaWG credentials for each installation. Repeated activation with the same pair returns existing
profiles. An existing VLESS-only installation receives its missing AmneziaWG profile without rotating
its VLESS UUID. No device identifier is put into logs or shown as a credential. The response also contains
`subscription.expires_at` and `subscription.device_limit`.

When the separate Netherlands direct exit is enabled, the same successful
response additionally contains `locations.netherlands-1.vless`. This is a
server-specific VLESS URI for the same device UUID, with the Netherlands
endpoint and its independent REALITY public parameters. Older clients ignore
the additive field. The new client stores it as a separate protected profile
and requests it again on first NL selection after an upgrade. See
`docs/netherlands-direct-exit.md` for synchronization and revocation timing.

`KENAI_MAX_SUBSCRIPTION_DEVICES` defaults to 32 active app installations per subscription. New
installations above that limit receive 409; a previously registered installation can still
reactivate. Invalid/expired keys receive 401. Revoked devices cannot reactivate with the same
identifier. The administrator can revoke an individual device from the panel. A copied account key
allows new device registration up to the limit, so it must be kept private. This is an MVP
trade-off, not a substitute for a revocable per-device token.

The optional `device_id` preserves the old `/api/v1/activate` request format for older clients,
which continues to use the subscription's primary device. The older format shares the primary
device's VPN credentials across every old client and should not be used for new installs. `/api/v2/activate`
remains a separate one-time-token flow for the future cascade; do not mix it with this direct
single-server MVP.
