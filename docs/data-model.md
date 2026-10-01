# Relational data model

PostgreSQL is the production database. SQLite remains supported only for isolated tests and as the
source of the one-time legacy importer.

The production schema is managed by Alembic on PostgreSQL and uses explicit primary keys, foreign
keys, unique constraints, and indexes. SQLite is retained only for isolated tests and legacy import.

## Entity relationships

```text
administrators 1 ─── * sessions
administrators 1 ─── * audit_events

users 1 ─── * devices
devices 1 ─── 0..1 wireguard_credentials
devices 1 ─── 0..1 amneziawg_credentials
devices 1 ─── 0..1 vless_credentials
devices 1 ─── * provisioning_packages
provisioning_packages 1 ─── * one_time_tokens
users/devices 1 ─── * audit_events (optional references)
```

## Tables

### administrators

- UUID primary key;
- unique normalized username;
- Argon2id password hash;
- encrypted TOTP secret;
- optional encrypted pending TOTP secret used only during safe replacement;
- TOTP-confirmed flag; new accounts remain inactive until enrollment is confirmed;
- active flag and timestamps.

### sessions

- UUID primary key;
- administrator foreign key with cascade delete;
- SHA-256 hash of the opaque cookie token;
- CSRF token hash;
- expiry, last-seen, client metadata, revocation timestamp.

### users

- UUID primary key;
- unique stable slug;
- display name, email, Telegram username, phone number and optional comment;
- optional unique SHA-256 activation-key hash and separately encrypted recoverable key;
- lifecycle status and timestamps.

### devices

- UUID primary key;
- user foreign key with cascade delete;
- unique `(user_id, slug)`;
- display name, lifecycle status, timestamps.

### wireguard_credentials

- one-to-one device foreign key;
- unique tunnel address;
- encrypted private configuration material;
- public key, lifecycle status, handshake and counters.

### amneziawg_credentials

- one-to-one device foreign key, independent from ordinary WireGuard;
- unique address from the dedicated `10.67.67.0/24` pool;
- encrypted AWG client configuration, public key, lifecycle status, handshake and counters;
- revocation or reissue does not modify the device's WireGuard or VLESS credential.

### vless_credentials

- one-to-one device foreign key;
- unique UUID credential identifier;
- encrypted client URI;
- lifecycle status, last-seen and counters.

### provisioning_packages

- device foreign key;
- selected protocol flags;
- encrypted generated payload;
- expiry, download and purge timestamps.

### one_time_tokens

- package foreign key;
- unique SHA-256 token hash (the plaintext token is never stored);
- expiry, consumed timestamp, attempt counter.

### audit_events

- immutable event id and timestamp;
- administrator, user, and device optional foreign keys;
- action, outcome, request correlation id;
- sanitized JSON metadata without credentials.

## Schema rules

- Foreign keys are enabled for every SQLite connection.
- Credential rows cannot exist without a device.
- A device can have at most one credential record per protocol.
- Device deletion first revokes every credential belonging to that device in separately committed
  operations and does not affect sibling devices. User deletion first
  moves every owned credential to the revoked lifecycle state in separately committed operations, then
  removes the relational user tree. Foreign keys use database cascades for dependent rows and
  `SET NULL` for the immutable audit trail.
- Secret values are encrypted at application level and excluded from model representations.
- Application subscribers have one internal `primary` device. It preserves the existing independent
  credential and helper boundaries without exposing device selection in the subscriber workflow.
