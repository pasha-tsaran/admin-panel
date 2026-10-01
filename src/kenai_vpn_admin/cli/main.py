import argparse
import getpass
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import pyotp
import qrcode
from sqlalchemy import select

from kenai_vpn_admin.config import get_settings
from kenai_vpn_admin.domain.validation import normalize_username
from kenai_vpn_admin.helper.cascade_config import (
    CascadeExit,
    ExitServer,
    IngressServer,
    RealityPeer,
    render_exit_config,
    render_ingress_base_config,
    render_ingress_config,
)
from kenai_vpn_admin.infrastructure.crypto import FernetCipher
from kenai_vpn_admin.infrastructure.database import build_engine, build_session_factory
from kenai_vpn_admin.infrastructure.models import AdministratorModel
from kenai_vpn_admin.infrastructure.sqlite_import import (
    DatabaseImportError,
    import_sqlite_database,
)
from kenai_vpn_admin.security import hash_password


def print_terminal_qr(value: str) -> None:
    """Render a compact QR code without writing the TOTP secret to disk."""
    qr = qrcode.QRCode(version=None, border=2)
    qr.add_data(value)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    for row_index in range(0, len(matrix), 2):
        upper = matrix[row_index]
        lower = matrix[row_index + 1] if row_index + 1 < len(matrix) else [False] * len(upper)
        line = ""
        for upper_cell, lower_cell in zip(upper, lower, strict=True):
            line += (
                "█"
                if upper_cell and lower_cell
                else "▀"
                if upper_cell
                else "▄"
                if lower_cell
                else " "
            )
        print(line)


def verify_totp_enrollment(secret: str, code: str) -> bool:
    return bool(re.fullmatch(r"\d{6}", code)) and pyotp.TOTP(secret).verify(code, valid_window=1)


def create_admin(username_arg: str | None) -> int:
    settings = get_settings()
    cipher = FernetCipher(
        settings.encryption_key,
        settings.secret_key,
        allow_derived=settings.env in {"development", "test"},
    )
    factory = build_session_factory(build_engine(settings))
    username = normalize_username(username_arg or input("Administrator username: "))
    with factory() as db:
        if db.scalar(select(AdministratorModel.id).where(AdministratorModel.username == username)):
            print("Administrator already exists.", file=sys.stderr)
            return 3
    password = getpass.getpass("Password (minimum 10 characters): ")
    confirmation = getpass.getpass("Repeat password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    totp_secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=username, issuer_name="Kenai VPN Admin"
    )
    print("\nAdd this TOTP secret to your authenticator now:")
    print(totp_secret)
    print("Provisioning URI:")
    print(provisioning_uri)
    print("\nScan this QR code with your authenticator application:")
    print_terminal_qr(provisioning_uri)
    code = input("\nEnter the current six-digit TOTP code to confirm enrollment: ").strip()
    if not verify_totp_enrollment(totp_secret, code):
        print("TOTP verification failed; administrator was not created.", file=sys.stderr)
        return 4
    with factory() as db:
        if db.scalar(select(AdministratorModel.id).where(AdministratorModel.username == username)):
            print("Administrator already exists.", file=sys.stderr)
            return 3
        db.add(
            AdministratorModel(
                username=username,
                password_hash=password_hash,
                encrypted_totp_secret=cipher.encrypt(totp_secret),
            )
        )
        db.commit()
    print("\nAdministrator created and TOTP enrollment verified.")
    print("The TOTP secret will not be shown again.")
    return 0


def expire_subscriptions() -> int:
    from kenai_vpn_admin.main import create_app

    application = create_app(get_settings())
    with application.state.session_factory() as db:
        targets = application.state.admin_service.expired_subscription_targets(db)
        for device_id, protocol in targets:
            try:
                application.state.admin_service.set_protocol_enabled(
                    db,
                    device_id=device_id,
                    protocol=protocol,
                    enabled=False,
                    administrator_id=None,
                    correlation_id=str(uuid.uuid4()),
                )
                db.commit()
            except Exception:
                db.rollback()
                return 1
        route_targets = application.state.cascade_service.expired_route_credentials(db)
        for credential in route_targets:
            try:
                application.state.cascade_service.disable_route_credential(credential)
                db.commit()
            except Exception:
                db.rollback()
                return 1
    print(
        f"expired_protocols_disabled={len(targets)} "
        f"expired_route_profiles_disabled={len(route_targets)}"
    )
    return 0


def refresh_cascade_health() -> int:
    """Probe every enabled route through Xray Observatory once."""
    from kenai_vpn_admin.main import create_app

    application = create_app(get_settings())
    failures = 0
    with application.state.session_factory() as db:
        locations = application.state.cascade_service.list_locations(db)
        for location in locations:
            try:
                application.state.cascade_service.refresh_location_health(db, location.id)
                db.commit()
            except Exception:
                db.rollback()
                failures += 1
    print(f"cascade_locations_checked={len(locations)} cascade_probe_failures={failures}")
    return 1 if failures else 0


def import_sqlite(source: Path, confirmation: str) -> int:
    if confirmation != "IMPORT":
        print("Confirmation must be exactly IMPORT.", file=sys.stderr)
        return 2
    settings = get_settings()
    engine = build_engine(settings)
    try:
        result = import_sqlite_database(source, engine)
    except DatabaseImportError as exc:
        print(f"Database import refused: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(f"sqlite_import_tables={result.tables} sqlite_import_rows={result.rows}")
    return 0


def _load_secret_spec(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Specification must be a regular non-symlink file")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("Specification containing private material must have mode 0600")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Specification JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("Specification root must be an object")
    return value


def _string(spec: dict[str, Any], name: str) -> str:
    value = spec.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Specification field {name} must be a non-empty string")
    return value


def _integer(spec: dict[str, Any], name: str) -> int:
    value = spec.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Specification field {name} must be an integer")
    return value


def _strings(spec: dict[str, Any], name: str) -> tuple[str, ...]:
    value = spec.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Specification field {name} must be a string list")
    return tuple(value)


def _write_new_file(output_path: Path, content: str) -> None:
    if output_path.exists():
        raise FileExistsError("Output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def render_cascade_ingress_base(spec_path: Path, output_path: Path, confirmation: str) -> int:
    if confirmation != "WRITE":
        print("Confirmation must be exactly WRITE.", file=sys.stderr)
        return 2
    try:
        spec = _load_secret_spec(spec_path)
        allowed = {
            "listen_port",
            "reality_target",
            "reality_private_key",
            "server_names",
            "short_ids",
            "inbound_tag",
        }
        if extra := set(spec) - allowed:
            raise ValueError(f"Unknown specification fields: {', '.join(sorted(extra))}")
        content = render_ingress_base_config(
            IngressServer(
                listen_port=_integer(spec, "listen_port"),
                reality_target=_string(spec, "reality_target"),
                reality_private_key=_string(spec, "reality_private_key"),
                server_names=_strings(spec, "server_names"),
                short_ids=_strings(spec, "short_ids"),
                inbound_tag=str(spec.get("inbound_tag", "kenai-client-in")),
            )
        )
        _write_new_file(output_path, content)
    except (OSError, ValueError) as exc:
        print(f"Ingress specification refused: {exc}", file=sys.stderr)
        return 1
    print(f"cascade_ingress_base_written={output_path}")
    print("xray_activation_performed=no")
    return 0


def render_cascade_exit(spec_path: Path, output_path: Path, confirmation: str) -> int:
    if confirmation != "WRITE":
        print("Confirmation must be exactly WRITE.", file=sys.stderr)
        return 2
    try:
        spec = _load_secret_spec(spec_path)
        allowed = {
            "location_slug",
            "listen_port",
            "ingress_uuid",
            "ingress_name",
            "reality_private_key",
            "reality_target",
            "server_names",
            "short_ids",
        }
        if extra := set(spec) - allowed:
            raise ValueError(f"Unknown specification fields: {', '.join(sorted(extra))}")
        content = render_exit_config(
            ExitServer(
                location_slug=_string(spec, "location_slug"),
                listen_port=_integer(spec, "listen_port"),
                ingress_uuid=_string(spec, "ingress_uuid"),
                ingress_name=_string(spec, "ingress_name"),
                reality_private_key=_string(spec, "reality_private_key"),
                reality_target=_string(spec, "reality_target"),
                server_names=_strings(spec, "server_names"),
                short_ids=_strings(spec, "short_ids"),
            )
        )
        _write_new_file(output_path, content)
    except (OSError, ValueError) as exc:
        print(f"Exit specification refused: {exc}", file=sys.stderr)
        return 1
    print(f"cascade_exit_written={output_path}")
    print("xray_activation_performed=no")
    return 0


def render_cascade_ingress(base_path: Path, output_path: Path, confirmation: str) -> int:
    if confirmation != "WRITE":
        print("Confirmation must be exactly WRITE.", file=sys.stderr)
        return 2
    if not base_path.is_file() or base_path.is_symlink() or output_path.exists():
        print("Base must be a regular file and output must not exist.", file=sys.stderr)
        return 1
    try:
        base = json.loads(base_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("Base Xray configuration is invalid.", file=sys.stderr)
        return 1
    if not isinstance(base, dict):
        print("Base Xray configuration root must be an object.", file=sys.stderr)
        return 1

    from kenai_vpn_admin.main import create_app

    application = create_app(get_settings())
    with application.state.session_factory() as db:
        specs = application.state.cascade_service.cascade_route_specs(db)
    exits = [
        CascadeExit(
            location_slug=spec.location_slug,
            peer=RealityPeer(
                address=spec.address,
                port=spec.port,
                client_uuid=spec.client_uuid,
                server_name=spec.server_name,
                public_key=spec.reality_public_key,
                short_id=spec.short_id,
            ),
        )
        for spec in specs
    ]
    content = render_ingress_config(base, exits)
    _write_new_file(output_path, content)
    print(f"cascade_ingress_written={output_path} routes={len(exits)}")
    print("xray_activation_performed=no")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="kenai-admin")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create-admin", help="Create the initial administrator")
    create_parser.add_argument("--username")
    subparsers.add_parser(
        "expire-subscriptions", help="Disable protocols for expired subscriptions"
    )
    subparsers.add_parser(
        "refresh-cascade-health", help="Probe cascade exits through Xray Observatory"
    )
    import_parser = subparsers.add_parser(
        "import-sqlite", help="Import the legacy SQLite database into empty PostgreSQL"
    )
    import_parser.add_argument("--source", type=Path, required=True)
    import_parser.add_argument("--confirm", required=True)
    render_parser = subparsers.add_parser(
        "render-cascade-ingress", help="Create a fail-closed Xray ingress config from PostgreSQL"
    )
    render_parser.add_argument("--base", type=Path, required=True)
    render_parser.add_argument("--output", type=Path, required=True)
    render_parser.add_argument("--confirm", required=True)
    ingress_base_parser = subparsers.add_parser(
        "render-cascade-ingress-base",
        help="Create a complete fail-closed Russian ingress Xray configuration",
    )
    ingress_base_parser.add_argument("--spec", type=Path, required=True)
    ingress_base_parser.add_argument("--output", type=Path, required=True)
    ingress_base_parser.add_argument("--confirm", required=True)
    exit_parser = subparsers.add_parser(
        "render-cascade-exit", help="Create a complete foreign exit Xray configuration"
    )
    exit_parser.add_argument("--spec", type=Path, required=True)
    exit_parser.add_argument("--output", type=Path, required=True)
    exit_parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        raise SystemExit(create_admin(args.username))
    if args.command == "expire-subscriptions":
        raise SystemExit(expire_subscriptions())
    if args.command == "refresh-cascade-health":
        raise SystemExit(refresh_cascade_health())
    if args.command == "import-sqlite":
        raise SystemExit(import_sqlite(args.source, args.confirm))
    if args.command == "render-cascade-ingress":
        raise SystemExit(render_cascade_ingress(args.base, args.output, args.confirm))
    if args.command == "render-cascade-ingress-base":
        raise SystemExit(render_cascade_ingress_base(args.spec, args.output, args.confirm))
    if args.command == "render-cascade-exit":
        raise SystemExit(render_cascade_exit(args.spec, args.output, args.confirm))


if __name__ == "__main__":
    main()
