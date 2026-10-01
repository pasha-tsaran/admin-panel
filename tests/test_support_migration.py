import sqlite3

from alembic import command
from alembic.config import Config

from kenai_vpn_admin.config import get_settings


def test_operator_selection_migration_preserves_ticket_tables(tmp_path, monkeypatch):
    database = tmp_path / "support-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")
    try:
        command.upgrade(config, "f7b2c8d93e10")
        command.upgrade(config, "a8c3d9e04f21")
        with sqlite3.connect(database) as connection:
            columns = connection.execute("PRAGMA table_info(support_operator_sessions)").fetchall()
            assert {c[1] for c in columns} == {"chat_id", "operator_id", "ticket_id"}
        command.downgrade(config, "f7b2c8d93e10")
        with sqlite3.connect(database) as connection:
            tables = {
                r[0]
                for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            assert "support_operator_sessions" not in tables
            assert {"support_tickets", "support_messages", "support_outbox"} <= tables
    finally:
        get_settings.cache_clear()


def test_guest_support_migration_is_reversible_without_guest_data(tmp_path, monkeypatch):
    database = tmp_path / "guest-support-migration.db"
    monkeypatch.setenv("KENAI_DATABASE_URL", f"sqlite:///{database}")
    get_settings.cache_clear()
    config = Config("alembic.ini")
    try:
        command.upgrade(config, "a8c3d9e04f21")
        command.upgrade(config, "b9d4e6f10a22")
        with sqlite3.connect(database) as connection:
            columns = {
                row[1]: row for row in connection.execute("PRAGMA table_info(support_tickets)")
            }
            assert {"guest_token_hash", "guest_ip_hash", "guest_name"} <= columns.keys()
            assert columns["user_id"][3] == 0
        command.downgrade(config, "a8c3d9e04f21")
        with sqlite3.connect(database) as connection:
            columns = {
                row[1]: row for row in connection.execute("PRAGMA table_info(support_tickets)")
            }
            assert "guest_token_hash" not in columns
            assert columns["user_id"][3] == 1
    finally:
        get_settings.cache_clear()
