import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from kenai_vpn_admin.config import get_settings


def column_names(database: Path, table: str) -> set[str]:
    with sqlite3.connect(database) as connection:
        return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def test_administrator_totp_migration_is_reversible(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "36368bd3c193")
    assert "totp_confirmed" not in column_names(database, "administrators")

    command.upgrade(config, "head")
    upgraded = column_names(database, "administrators")
    assert {"totp_confirmed", "pending_encrypted_totp_secret"} <= upgraded

    command.downgrade(config, "36368bd3c193")
    downgraded = column_names(database, "administrators")
    assert "totp_confirmed" not in downgraded
    assert "pending_encrypted_totp_secret" not in downgraded
    get_settings.cache_clear()


def test_amneziawg_migration_is_reversible(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "amneziawg-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "8f4c2b91a7de")
    assert "includes_amneziawg" not in column_names(database, "provisioning_packages")

    command.upgrade(config, "head")
    assert "includes_amneziawg" in column_names(database, "provisioning_packages")
    assert column_names(database, "amneziawg_credentials")

    command.downgrade(config, "8f4c2b91a7de")
    assert "includes_amneziawg" not in column_names(database, "provisioning_packages")
    assert not column_names(database, "amneziawg_credentials")
    get_settings.cache_clear()


def test_activation_account_migration_is_reversible(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "activation-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "c2a4e6f91b30")
    assert "activation_key_hash" not in column_names(database, "users")

    command.upgrade(config, "a9f4d31c72e8")
    assert {"email", "telegram_username", "phone_number", "activation_key_hash"} <= column_names(
        database, "users"
    )

    command.downgrade(config, "c2a4e6f91b30")
    assert "activation_key_hash" not in column_names(database, "users")
    get_settings.cache_clear()


def test_encrypted_activation_key_migration_is_reversible(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "encrypted-activation-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "a9f4d31c72e8")
    assert "encrypted_activation_key" not in column_names(database, "users")

    command.upgrade(config, "head")
    assert "encrypted_activation_key" in column_names(database, "users")
    assert column_names(database, "activation_attempts")

    command.downgrade(config, "a9f4d31c72e8")
    assert "encrypted_activation_key" not in column_names(database, "users")
    assert not column_names(database, "activation_attempts")
    get_settings.cache_clear()


def test_cascade_topology_migration_is_reversible(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "cascade-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "d4c8f31a62b9")
    assert "activation_key_consumed_at" not in column_names(database, "users")

    command.upgrade(config, "head")
    assert "activation_key_consumed_at" in column_names(database, "users")
    assert column_names(database, "vpn_nodes")
    assert column_names(database, "vpn_locations")
    assert column_names(database, "device_access_tokens")
    assert column_names(database, "route_credentials")

    command.downgrade(config, "d4c8f31a62b9")
    assert "activation_key_consumed_at" not in column_names(database, "users")
    assert not column_names(database, "vpn_nodes")
    assert not column_names(database, "vpn_locations")
    assert not column_names(database, "device_access_tokens")
    assert not column_names(database, "route_credentials")
    get_settings.cache_clear()
