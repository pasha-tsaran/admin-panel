from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from kenai_vpn_admin.backup.main import PG_DUMP
from kenai_vpn_admin.backup.service import (
    BackupEntry,
    BackupError,
    BackupService,
    production_backup_entries,
)
from kenai_vpn_admin.domain.enums import Protocol


def test_pg_dump_uses_debian_13_versioned_binary() -> None:
    assert Path("/usr/lib/postgresql/17/bin/pg_dump") == PG_DUMP


def _database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample(value) VALUES ('safe-value')")
        connection.commit()
    finally:
        connection.close()


def test_encrypted_backup_verifies_and_extracts_only_to_staging(tmp_path: Path) -> None:
    key = tmp_path / "backup.key"
    backups = tmp_path / "backups"
    database = tmp_path / "database.sqlite"
    config = tmp_path / "wg0.conf"
    _database(database)
    config.write_text("sanitized-config\n", encoding="utf-8")
    service = BackupService(key, backups)
    service.initialize_key()

    result = service.create(database, (BackupEntry("config/wg0.conf", config),))
    encoded = result.path.read_bytes()

    assert b"sanitized-config" not in encoded
    assert b"safe-value" not in encoded
    manifest = service.verify(result.path)
    assert set(manifest["entries"]) == {"database/kenai-admin.db", "config/wg0.conf"}

    destination = tmp_path / "restore-staging"
    service.extract_to_staging(result.path, destination)
    assert (destination / "config/wg0.conf").read_text(encoding="utf-8") == "sanitized-config\n"
    restored = sqlite3.connect(destination / "database/kenai-admin.db")
    try:
        assert restored.execute("SELECT value FROM sample").fetchone() == ("safe-value",)
    finally:
        restored.close()


def test_backup_authentication_rejects_tampering(tmp_path: Path) -> None:
    key = tmp_path / "backup.key"
    backups = tmp_path / "backups"
    database = tmp_path / "database.sqlite"
    config = tmp_path / "config.json"
    _database(database)
    config.write_text("{}\n", encoding="utf-8")
    service = BackupService(key, backups)
    service.initialize_key()
    result = service.create(database, (BackupEntry("config/xray/config.json", config),))
    encoded = bytearray(result.path.read_bytes())
    encoded[-1] ^= 1
    result.path.write_bytes(encoded)

    with pytest.raises(BackupError, match="authentication failed"):
        service.verify(result.path)


def test_backup_refuses_symlink_source_and_existing_restore_target(tmp_path: Path) -> None:
    key = tmp_path / "backup.key"
    backups = tmp_path / "backups"
    database = tmp_path / "database.sqlite"
    source = tmp_path / "source.conf"
    link = tmp_path / "link.conf"
    _database(database)
    source.write_text("content", encoding="utf-8")
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("Symlink creation is unavailable")
    service = BackupService(key, backups)
    service.initialize_key()

    with pytest.raises(BackupError, match="regular file"):
        service.create(database, (BackupEntry("config/link.conf", link),))


def test_backup_key_is_create_only(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backup.key", tmp_path / "backups")
    service.initialize_key()

    with pytest.raises(BackupError, match="already exists"):
        service.initialize_key()


def test_production_backup_covers_every_managed_protocol() -> None:
    entries = {entry.archive_name: entry.source_path for entry in production_backup_entries()}

    assert entries["config/wireguard/wg0.conf"] == Path("/etc/wireguard/wg0.conf")
    assert entries["config/amneziawg/awg0.conf"] == Path("/etc/amneziawg/awg0.conf")
    assert entries["config/xray/config.json"] == Path("/usr/local/etc/xray/config.json")
    assert entries["state/helper/wireguard.json"] == Path(
        "/var/lib/kenai-vpn-helper/wireguard.json"
    )
    assert entries["state/helper/amneziawg.json"] == Path(
        "/var/lib/kenai-vpn-helper/amneziawg.json"
    )
    assert entries["state/helper/xray.json"] == Path("/var/lib/kenai-vpn-helper/xray.json")


def test_vless_only_backup_does_not_require_wireguard_files() -> None:
    entries = {
        entry.archive_name: entry.source_path
        for entry in production_backup_entries({Protocol.VLESS})
    }

    assert set(entries) == {
        "config/xray/config.json",
        "state/helper/xray.json",
        "secrets/web.env",
        "secrets/helper.env",
    }
