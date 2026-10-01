from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy.engine import make_url

from kenai_vpn_admin.backup.service import (
    BackupEntry,
    BackupError,
    BackupResult,
    BackupService,
    production_backup_entries,
)
from kenai_vpn_admin.config import get_settings

DEFAULT_KEY = Path("/etc/kenai-vpn/backup.key")
DEFAULT_DIRECTORY = Path("/var/backups/kenai-vpn-admin")
DEFAULT_DATABASE = Path("/var/lib/kenai-vpn-admin/kenai-admin.db")
# Debian 13's /usr/bin/pg_dump is a pg_wrapper symlink; use the installed
# PostgreSQL 17 binary directly so backup validation can reject symlinks.
PG_DUMP = Path("/usr/lib/postgresql/17/bin/pg_dump")


def _service(args: argparse.Namespace) -> BackupService:
    return BackupService(args.key_file, args.backup_directory, retention=args.retention)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kenai-backup")
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--backup-directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--retention", type=int, default=14)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-key")
    create = subparsers.add_parser("create")
    create.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    verify = subparsers.add_parser("verify")
    verify.add_argument("backup", type=Path)
    extract = subparsers.add_parser("extract")
    extract.add_argument("backup", type=Path)
    extract.add_argument("destination", type=Path)
    return parser


def create_production_backup(service: BackupService, legacy_database: Path) -> BackupResult:
    settings = get_settings()
    managed_entries = production_backup_entries(settings.backup_protocol_set)
    url = settings.database_url
    if url.startswith("sqlite"):
        return service.create(legacy_database, managed_entries)
    if not url.startswith("postgresql"):
        raise BackupError("Unsupported production database")
    if not PG_DUMP.is_file() or PG_DUMP.is_symlink():
        raise BackupError("pg_dump is unavailable")
    parsed = make_url(url)
    if not parsed.host or not parsed.username or not parsed.database or parsed.password is None:
        raise BackupError("PostgreSQL backup connection is incomplete")
    with tempfile.TemporaryDirectory(prefix="kenai-pg-dump-") as directory:
        dump = Path(directory) / "kenai.dump"
        environment = os.environ.copy()
        environment["PGPASSWORD"] = parsed.password
        sslmode = parsed.query.get("sslmode")
        if isinstance(sslmode, str) and sslmode:
            environment["PGSSLMODE"] = sslmode
        arguments = [
            str(PG_DUMP),
            "--format=custom",
            "--file",
            str(dump),
            "--host",
            parsed.host,
            "--username",
            parsed.username,
            "--dbname",
            parsed.database,
        ]
        if parsed.port is not None:
            arguments.extend(("--port", str(parsed.port)))
        try:
            subprocess.run(
                arguments,
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise BackupError("PostgreSQL dump failed") from exc
        return service.create_from_snapshot(
            BackupEntry("database/kenai.dump", dump), managed_entries
        )


def main() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("kenai-backup must run as root on Linux")
    args = build_parser().parse_args()
    service = _service(args)
    try:
        if args.command == "init-key":
            service.initialize_key()
            print("backup_key_initialized=yes")
        elif args.command == "create":
            result = create_production_backup(service, args.database)
            print(f"backup_created={result.path}")
            print(f"backup_sha256={result.sha256}")
            print(f"backup_entries={result.entry_count}")
            print("backup_verified=yes")
        elif args.command == "verify":
            manifest = service.verify(args.backup)
            entries = manifest.get("entries")
            if not isinstance(entries, dict):
                raise BackupError("Backup manifest is invalid")
            print("backup_verified=yes")
            print(f"backup_entries={len(entries)}")
        else:
            destination = service.extract_to_staging(args.backup, args.destination)
            print(f"restore_staging={destination}")
            print("live_files_changed=no")
    except BackupError as exc:
        print(f"backup_error={exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
