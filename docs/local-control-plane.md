# Local Kenai control plane

This mode is intended for a Windows PC before a Russian ingress VPS exists. It starts the same
three foundations that will move to the VPS later:

- PostgreSQL 17 for users, subscriptions, devices, nodes and route profiles;
- the Kenai administration panel and `/api/v2`;
- the official XTLS Xray container, pinned by tag and image digest to stable version `26.3.27`.

The local Xray configuration is deliberately **fail closed**. It has no direct `freedom` outbound
and cannot accidentally send a subscriber directly to the Internet. A real client ingress and a
country outbound are added only after an exit server has been configured and its REALITY public
parameters are known.

## Start on the PC

### Native Windows mode used on the current development PC

This mode uses the locally installed PostgreSQL 18 binaries and does not require Docker. Runtime
data, logs, downloaded Xray and generated secrets stay under ignored `.local/` and `.env.native`.

```powershell
powershell -ExecutionPolicy Bypass -File deploy/local/init-native.ps1
powershell -ExecutionPolicy Bypass -File deploy/local/start-native.ps1
powershell -ExecutionPolicy Bypass -File deploy/local/verify-native.ps1
```

The first command is create-only: it refuses an existing or partial database and never prints the
generated secrets. It installs the official Windows Xray 26.3.27 archive only after checking the
pinned SHA-256. The second starts an isolated PostgreSQL cluster on `127.0.0.1:55432`, applies all
Alembic migrations, starts fail-closed Xray and exposes the panel only on
`http://127.0.0.1:8000`. Stop it with:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/local/stop-native.ps1
```

Create the first administrator interactively after startup:

```powershell
.venv\Scripts\kenai-admin.exe create-admin
```

The native and Docker modes are alternatives. Do not start both on port 8000.

### Docker mode

1. Install Docker Desktop.
2. Run `powershell -ExecutionPolicy Bypass -File deploy/local/init-local.ps1`. It creates `.env.local`
   once with independent random PostgreSQL, application and Fernet secrets and never prints them.
   The `.env.local.example` file documents the three required names.

3. Start the stack:

   `docker compose --env-file .env.local up --build -d`

4. Create the first administrator:

   `docker compose --env-file .env.local run --rm admin kenai-admin create-admin`

5. Open `http://127.0.0.1:8000` and use **Servers** to add the future Russian ingress and foreign
   exit metadata.

6. Run `powershell -ExecutionPolicy Bypass -File deploy/local/verify-local.ps1`. It validates
   Compose, the mounted Xray JSON, the panel health endpoint and the PostgreSQL Alembic revision.

`docker compose ps` must show PostgreSQL, the panel and Xray running. The database is stored in a
named Docker volume and is not deleted by a normal `docker compose down`.

## What works before buying the Russian VPS

- subscription and activation-key management;
- one-time `/api/v2/activate` exchange for a device token;
- location catalogue, health state and per-location profiles;
- encrypted storage of client profiles;
- Xray configuration validation, rollback primitives and fail-closed routing generation;
- legacy SQLite import into PostgreSQL;
- development of the future client against `/api/v2`.

The Docker Xray service is a control-plane test instance. It is intentionally not exposed as a
public VPN ingress. End-to-end country traffic becomes possible only after at least one real foreign
exit is configured. The existing foreign VPS can be used for that role.

For every location, the panel asks for the inter-server VLESS UUID, the exit REALITY server name,
public key and short ID. This secret-bearing link document is encrypted in PostgreSQL. To turn the
registered locations into an ingress configuration, generate a complete fail-closed base from a
root-only specification file:

`docker compose --env-file .env.local run --rm -v C:/kenai-config:/config admin kenai-admin render-cascade-ingress-base --spec /config/ingress-spec.json --output /config/base.json --confirm WRITE`

Then merge the registered locations:

`docker compose --env-file .env.local run --rm -v C:/kenai-config:/config admin kenai-admin render-cascade-ingress --base /config/base.json --output /config/generated.json --confirm WRITE`

The command creates a new file and refuses to overwrite anything. Validate it with the exact pinned
Xray binary (`xray run -test -config generated.json`) before replacing the active config. Managed
country outbounds and balancers are rebuilt from PostgreSQL; unmanaged base objects are preserved.
If an observed exit is down, its balancer falls back to `kenai-blocked`, never to direct Internet.
The matching exit configuration is generated with `kenai-admin render-cascade-exit`. The complete
credential, target-selection, validation, rollout and rollback sequence is documented in
[`vless-cascade-runbook.md`](vless-cascade-runbook.md).

## Move the database from the old MVP

Stop writes to the old application and keep an untouched copy of its SQLite file. With the new
PostgreSQL schema already migrated, run inside the admin container:

`docker compose --env-file .env.local run --rm -v C:/absolute/path:/import:ro admin kenai-admin import-sqlite --source /import/kenai-admin.db --confirm IMPORT`

The importer checks SQLite integrity, requires an empty target database and copies all known tables
in foreign-key order inside one PostgreSQL transaction. It never prints the PostgreSQL password.

## Move to a Russian VPS later

Export the PostgreSQL database with `pg_dump`, copy the environment and encrypted backup through a
secure channel, run `alembic upgrade head`, and then replace the local Xray control configuration
with the generated Russian ingress configuration. The application API and database schema do not
change during this move; only endpoints, certificates and REALITY keys change.
