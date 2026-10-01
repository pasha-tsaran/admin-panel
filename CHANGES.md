# Changeset: Dashboard runtime recovery and direct-server inventory

Deployed to the Armenia control plane on 2026-09-26.

- Treat Xray's missing zero-valued online counter as a valid offline state so one idle device no
  longer hides all dashboard traffic and connection totals.
- Show the configured Armenia primary server and Netherlands direct VLESS exit separately from the
  future Russian-ingress cascade inventory.
- Deployed the simplified application-user and manual-issuance forms from the current source tree.
- Split connection totals and detail pages between application keys and manually issued profiles.
  Application rows show the activation key used by the connected account; manual profiles remain
  on the manual issuance dashboard.

# Changeset: PostgreSQL cascade control plane

Implemented locally on 2026-09-08. No live VPS was changed.

- Added Russian-ingress to country-exit topology, fail-closed Xray routing and Observatory health.
- Added one-time device activation and bearer-authenticated `/api/v2` location/profile endpoints.
- Added encrypted per-device/per-location route profiles and expiry enforcement.
- Added PostgreSQL production configuration, pooled connections and UTC sessions.
- Added a transactional, empty-target-only SQLite to PostgreSQL importer.
- Changed production backups to use `pg_dump` without putting the password in process arguments.
- Added a local Docker Compose control plane with PostgreSQL, the panel and official Xray core.
- Added a no-Docker Windows development launcher that creates an isolated PostgreSQL 18 cluster,
  verifies the official Xray archive checksum and runs both services on loopback only.
- Added complete create-only Russian ingress and foreign exit generators with mandatory REALITY
  targets, stable Xray pinning, native validation and rollback deployment scripts.
- Changed both generated nodes to fail closed by default and documented the target/SAN/ASN checks
  that prevent an arbitrary camouflage domain from being used incorrectly.

# Changeset: Stable activation keys and renewable subscriptions

Implemented locally on 2026-09-03.

- Activation keys now remain stable for the lifetime of an application user.
- Subscription creation and renewal support 3 days, 30 days, custom days, or a calendar date.
- Renewal re-enables disabled protocols and reissues any revoked protocol without changing the key.
- Removed the conflicting activation-key regeneration action from the application and UI.
- Added conditional subscription-period fields and an expiry/renewal regression test.

# Changeset: Repository audit hardening

Implemented locally on 2026-09-02.

- Restricted post-action redirects to the current origin.
- Enforced production safety checks when `Settings` is passed directly to `create_app`.
- Added the previously omitted AmneziaWG configuration and helper state to production backups.
- Removed the redundant migration-directory `.gitkeep` file.

# Changeset: Single-device deletion

Implemented locally on 2026-09-02.

- Every device card now has an always-available `Удалить устройство` action.
- The action revokes that device's WG, AWG, and VLESS credentials before deleting it.
- Other devices and the owning user remain unchanged.
- Confirmation, CSRF, audit events, and partial-failure safety are preserved.

# Changeset: Recoverable 12-digit activation keys

Implemented locally on 2026-09-02.

- Replaced long activation tokens with 12 random decimal digits.
- Stores a lookup hash plus an encrypted recoverable copy; plaintext is never stored.
- Added reveal/hide and clipboard copy controls to subscriber profiles.
- Added persistent per-source activation failure limiting.
- Made the post-creation card compact and responsive.
- Added reversible Alembic revision `b7e2a91d4c60`.

# Changeset: Activation-key subscriptions

Implemented locally on 2026-09-02.

- Added application subscribers with email, Telegram username, phone number, and comments.
- Added generation of an activation key and a SHA-256 lookup hash.
- Automatically creates one internal profile and issues WG, AWG, and VLESS.
- Added `POST /api/v1/activate` with uniform authentication failure and non-cacheable responses.
- Kept the existing device/QR/config workflow under the separate `Ручная выдача` tab.
- Added reversible Alembic revision `a9f4d31c72e8`.

# Changeset: VLESS online status and uniform dashboard cards

Implemented locally on 2026-09-01. Production deployment requires the Xray gate in
`docs/deployment.md`.

- Removed the redundant total from the issued-access card; the per-protocol breakdown remains.
- Added typed per-device Xray online counters through the privileged helper.
- Made the VLESS dashboard card show currently connected devices like WG and AWG.
- Changed the VLESS details page to list only devices with active Xray connections.
- Added tests and documentation for `statsUserOnline` and `xray api statsonline`.

# Changeset: Independent AmneziaWG 2.0 support

Implemented locally on 2026-08-31. Production has not been changed.

- Added `Protocol.AMNEZIAWG` with independent per-device credentials, lifecycle and traffic data.
- Added reversible Alembic revision `c2a4e6f91b30` and an encrypted AWG flag in one-time packages.
- Added a dedicated `awg0` helper adapter using `10.67.67.0/24`, UDP/585 and configurable
  Jc/Jmin/Jmax, S1-S4, H1-H4 and optional AWG 2.0 I1-I5 obfuscation parameters.
- Added AWG health/runtime data, admin controls, QR/config downloads, dashboard counts and filters.
- Kept ordinary WireGuard and VLESS independent; AWG actions do not revoke or rewrite them.
- Added production environment template and a documented backup, validation and rollback gate.
- Added `/etc/amneziawg` to the helper unit `ReadWritePaths`; without it,
  `ProtectSystem=strict` prevents AWG peer updates and the web route returns HTTP 500.
- Verified locally: Ruff format/lint PASS, mypy PASS, pytest 58 passed / 1 skipped.

Dashboard follow-up:

- kept the service-health row unchanged;
- placed user and issued-access totals together on the second level;
- expanded traffic into one full-width, three-protocol row;
- added clickable WG, AWG and VLESS cards on the fourth level;
- added an authenticated AWG connection list with fresh-handshake filtering;
- retained an explicit VLESS limitation: Xray counters do not provide an exact online handshake.

Production activation still requires a separately reviewed migration and deployment: protected
backups, verified `awg`/`awg-quick`, `awg0.conf`, nftables UDP rule, helper environment update,
single-device canary, and rollback verification. Do not deploy this as an ordinary hot reload,
because the new helper settings are required at startup.

# Changeset: WireGuard Windows Routing Fix (Reverted)

## Initial Hypothesis (Incorrect)

On Windows, WireGuard client configs used `AllowedIPs = 0.0.0.0/0, ::/0` (full-tunnel).
It was assumed this caused routing conflicts: the client tried to route all traffic (including handshake
requests to the VPN server itself) through the tunnel before it was established. Handshake
failed, no internet through VPN.

The initial fix replaced full-tunnel with split-tunnel:
```
AllowedIPs = 10.66.66.0/24
```

## Root Cause (Correct Analysis from Second Agent)

The handshake failures were **NOT caused by `AllowedIPs = 0.0.0.0/0`**. They were caused by a
**conflicting third-party VPN client (Amnezia / hidemy.name)** installed on the test machine:

- Amnezia creates a network adapter `hidemy.name_VPN` with its own routing table
- `hidemy.name VPN Watcher` runs simultaneously
- The machine's external IP was `91.195.254.67` (Amnezia proxy), not the VPS IP `88.218.94.3`
- Stale routes through the home router bypassed the WireGuard tunnel

WireGuard on Windows **automatically creates a persistent route to the endpoint IP**, so
`0.0.0.0/0` does not block handshake packets. The real culprit was the Amnezia conflict.

## Resolution

**Reverted the split-tunnel change.** All files restored to original `AllowedIPs = 0.0.0.0/0, ::/0`.

### Correct Resolution Steps

1. **Uninstall or disable Amnezia / hidemy.name VPN** on the client machine
2. **Test WireGuard on a clean machine** (no other VPN clients)
3. If UDP traffic to port 51820 is filtered by ISP, test:
   - Different UDP port
   - AmneziaWG (server-side support required)
4. Consider making full-tunnel vs split-tunnel an **optional setting** for users, not a server default

## Files Changed (Rollback)

| File | Change |
| --- | --- |
| `src/kenai_vpn_admin/helper/wireguard_adapter.py` | Reverted to `AllowedIPs = 0.0.0.0/0, ::/0` |
| `src/kenai_vpn_admin/infrastructure/mock_vpn.py` | Reverted to `AllowedIPs = 0.0.0.0/0, ::/0` |
| `tests/test_production_adapters.py` | Reverted assertion |
| `tests/test_user_workflow.py` | Reverted assertion |
| `docs/helper-protocol.md` | Rewrote section to document Amnezia conflict and correct troubleshooting |

## Verification

- `pytest` — 56 passed, 1 skipped (unchanged, tests verify full-tunnel behavior)
- All assertions restored to expect `AllowedIPs = 0.0.0.0/0, ::/0`

## Impact & Rollback

- **No code change required** — the revert restores the original intended behavior
- Existing devices issued before and after this cycle use `0.0.0.0/0`
- Users experiencing handshake failures should:
  1. Check for other VPN clients (Amnezia, hidemy.name, ProtonVPN, etc.)
  2. Disable/uninstall the conflicting client
  3. Verify their external IP matches the VPS IP (not a proxy)
  4. Try connecting again

## Notes for Future Agents

- **Do not change `AllowedIPs` to fix client-side VPN conflicts.** The real cause is almost always a second VPN client or ISP UDP filtering.
- If full-tunnel is undesirable for some users, implement it as an **optional client-side setting**, not a server default.
- Always verify the test machine has no other VPN software installed before diagnosing WireGuard issues.
- The `docs/helper-protocol.md` section "Windows routing considerations" documents the correct diagnosis.
