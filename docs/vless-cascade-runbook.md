# VLESS cascade runbook

This is the deployment sequence for the first production topology:

`client -> Russian ingress -> Armenian exit -> Internet`

Kenai manages users, subscriptions, per-device route profiles and location health. Official Xray
remains the data plane. The Russian ingress has no direct Internet outbound: its first and fallback
outbound is `blackhole`. The Armenian exit is the only component with a `freedom` outbound.

## What REALITY does and does not promise

REALITY makes the public client-to-ingress handshake resemble ordinary TLS traffic. The visible
destination IP is still the Russian VPS. The chosen `serverName` must be a name present in the
certificate returned by the configured `target`; it cannot be an arbitrary Russian domain.
Prefer a stable Russian target in the same ASN as the Russian VPS and verify it using the exact
pinned Xray binary:

```bash
sudo deploy/preflight/03-reality-target-check.sh example.ru:443
```

No protocol can guarantee permanent immunity from blocking, throttling or active probing. Do not
advertise the service as indistinguishable from a visit to a particular domain.

## Independent credentials

Use separate credentials for the two hops. Never reuse the client-facing private key on the
inter-server link.

On each relevant server, generate an X25519 pair with `xray x25519`. Generate the inter-server UUID
with `xray uuid` and a non-empty 8-byte short ID with `openssl rand -hex 8`. Keep private keys only
in root-readable specification files on the server where they are used.

Required values:

- Russian ingress: public endpoint, listen port, target, server names, private/public X25519 keys,
  and short ID;
- Armenian exit: public endpoint, listen port, target, server names, private/public X25519 keys,
  short ID, and one UUID accepted only from the Russian ingress;
- panel location: Armenian endpoint plus the public inter-server parameters. These values are
  encrypted in PostgreSQL.

## Generate the Armenian exit configuration

Copy `deploy/examples/exit-spec.example.json` outside the repository, replace every placeholder,
and restrict the file to root (`chmod 600`). Then generate a create-only candidate:

```bash
kenai-admin render-cascade-exit \
  --spec /root/kenai/armenia-exit.spec.json \
  --output /root/kenai/armenia-exit.candidate.json \
  --confirm WRITE
/usr/local/bin/xray run -test -config /root/kenai/armenia-exit.candidate.json
```

The exit configuration has no access log, blocks private destination ranges and uses `blackhole`
as the default outbound. Only traffic from the managed VLESS inbound is explicitly routed to the
Internet. The REALITY server block includes the mandatory `target`.

Apply only after reviewing the candidate and confirming SSH recovery access:

```bash
sudo deploy/install/03-apply-xray-config.sh \
  /root/kenai/armenia-exit.candidate.json \
  /usr/local/etc/xray/config.json
```

The script validates before replacement, creates a root-only backup and restores the previous
configuration if Xray does not become active.

## Generate the Russian ingress configuration

Copy `deploy/examples/ingress-spec.example.json` outside the repository, fill it, set mode `0600`
and generate the fail-closed base:

```bash
kenai-admin render-cascade-ingress-base \
  --spec /root/kenai/russia-ingress.spec.json \
  --output /root/kenai/russia-ingress.base.json \
  --confirm WRITE
```

In the panel, create one ingress node, one Armenian exit node and the Armenia location. Use the
same inter-server UUID, Armenian REALITY public key, server name, short ID and port used above.
Then merge all enabled PostgreSQL locations into a new candidate:

```bash
kenai-admin render-cascade-ingress \
  --base /root/kenai/russia-ingress.base.json \
  --output /root/kenai/russia-ingress.candidate.json \
  --confirm WRITE
/usr/local/bin/xray run -test -config /root/kenai/russia-ingress.candidate.json
```

Apply the reviewed candidate using the same `03-apply-xray-config.sh` script. Only TCP/443 (or the
selected client port) should be publicly reachable for VLESS. The Xray API stays on
`127.0.0.1:10085`; PostgreSQL and the administration panel must not be exposed to the public
Internet.

## Acceptance before selling access

Do not mark the service production-ready until all of these pass:

1. The exact pinned Xray core accepts both JSON files with `run -test`.
2. Twenty connection attempts succeed at least 95% of the time on home Internet and two mobile
   operators.
3. A 30-minute video does not show recurring disconnects or severe throttling.
4. The public exit IP is Armenian and the client has no DNS or IPv6 leak.
5. Stopping the Armenian Xray marks Armenia unavailable and never produces a direct Russian exit.
6. Expiring a subscription removes or disables its Russian ingress route profile.
7. Rebooting both VPS nodes restores Xray, PostgreSQL, the helper and health timers.
8. A database restore and an Xray rollback have been rehearsed on staging.

DNS and IPv6 leak prevention ultimately belongs to the future client application's TUN and DNS
configuration. A VLESS share URI alone cannot force every operating system application to send
all DNS and IPv6 traffic through the proxy.

## Adding another country

Generate an independent exit configuration and credentials, install it on the new VPS, add the
node and location to PostgreSQL, regenerate the Russian ingress candidate, validate it, and apply
it. The client receives only a Russian ingress profile; foreign addresses and inter-server
credentials are never included in the client response.

The current first-production workflow deliberately applies exit configuration through a reviewed
candidate and rollback script. A public remote node-agent is not enabled yet: exposing one before
mTLS enrollment, replay protection and upgrade rollback are finished would add a high-value
management endpoint to every VPS.

Both production roles are Debian Linux hosts. The Windows scripts under `deploy/local/` exist only
to run the control plane on the development PC; they are never used as the production data plane.
The Russian host runs PostgreSQL, the loopback-only panel, helper and Xray; each foreign Debian
host runs Xray and receives reviewed candidate configurations.
