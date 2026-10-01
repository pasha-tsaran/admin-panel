# Architecture

## Goals

Kenai VPN Admin is designed as a maintainable control plane. The UI must remain independent from WireGuard/Xray implementation details, and production privilege must never leak into the web process.

The cascade data path is `client -> Russian ingress -> selected foreign exit -> Internet`. The
control plane stores users, subscriptions, node metadata and encrypted inter-server parameters in
PostgreSQL. Xray remains the data plane; Kenai generates and validates configuration but does not
reimplement the proxy core.

## Layers

### Domain

Pure business language: users, devices, protocols, credential lifecycle, provisioning lifecycle, and audit actions. It does not import FastAPI, SQLAlchemy, systemd, or shell tooling.

Live device statistics follow the same boundary as mutations: the unprivileged web process asks the
helper for a validated device reference. The helper maps it to its private operational state and
returns only non-secret runtime metadata. WireGuard and Xray counters are live values and are not
persisted. The dashboard aggregates those live counters in the application layer; templates never
inspect helper state or VPN configuration directly. Xray counters are queried only when the helper
is configured with a loopback-only Xray Stats API endpoint; otherwise the UI explicitly reports
that counters are not yet available instead of estimating traffic.
The authenticated VLESS traffic view lists non-revoked credentials by user and device with their
live Xray uplink/downlink counters. It deliberately does not claim a current-connection time:
unlike WireGuard, the configured Xray Stats API does not expose a handshake timestamp.

### Application

Use cases coordinate repositories, encryption, provisioning, and the VPN manager through typed ports. This layer owns transaction boundaries and authorization-independent business rules.

Client-application subscribers authenticate with a 12-digit activation key. Its SHA-256 lookup
hash and an encrypted administrator-recoverable copy are stored. Persistent per-source rate
limiting protects the activation endpoint. Successful activation returns the three encrypted-at-rest protocol
profiles over HTTPS with `Cache-Control: no-store`. The legacy manual device workflow remains an
authenticated administrator-only UI and is not part of the client API.

### Infrastructure

SQLAlchemy repositories, encryption-at-rest implementation, mock VPN adapter, and later the Unix-socket production adapter. Infrastructure implements application ports.

Production uses PostgreSQL through Psycopg 3. SQLite is limited to tests and the legacy import
source. Xray Observatory measures the actual country outbound, and every country balancer has a
blackhole fallback so a failed exit cannot silently become a direct connection.

### Web

HTTP routes, form parsing, CSRF, authentication dependencies, templates, and static assets. Routes call application services and never manipulate VPN configuration directly.

## Production privilege boundary

```text
unprivileged web service
        |
        | validated request over root-owned Unix socket
        v
minimal privileged helper
        |
        +-- WireGuard adapter
        +-- AmneziaWG 2.0 adapter (independent interface and address pool)
        +-- Xray adapter
```

The helper accepts an allowlisted operation schema. It does not accept shell fragments, paths supplied by users, or arbitrary commands.

The wire format and security invariants are documented in
[`helper-protocol.md`](helper-protocol.md).

## Runtime modes

- `mock`: deterministic local development and tests; no operating-system mutations.
- `helper`: production mode; communicates with the separately deployed helper.

## Dependency rule

Dependencies point inward. Domain knows nothing about other layers. Application depends on domain and ports. Infrastructure and web depend on application contracts.
