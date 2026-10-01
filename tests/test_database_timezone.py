"""Optional PostgreSQL regression: empty reads must not delay the support outbox."""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.database import build_engine


def test_postgresql_timezone_survives_empty_poll_and_rollback():
    configured = os.environ.get("KENAI_TEST_POSTGRES_URL")
    if not configured:
        pytest.skip("Set KENAI_TEST_POSTGRES_URL to an isolated local PostgreSQL database")
    url = make_url(configured)
    assert url.host in {"127.0.0.1", "localhost", "::1"}, "Never test against a production database"
    # Emulate the production server's non-UTC default without changing its settings.
    url = url.update_query_dict({"options": "-c timezone=Asia/Dubai"})
    engine = build_engine(
        Settings(env="test", database_url=url.render_as_string(hide_password=False))
    )
    try:
        backend = None
        for _ in range(3):
            with engine.connect() as connection:
                current = connection.scalar(text("SELECT pg_backend_pid()"))
                if backend is not None:
                    assert current == backend  # Exercise the reused pool connection.
                backend = current
                assert connection.scalar(text("SHOW TIME ZONE")) == "UTC"
                assert (
                    connection.scalar(
                        text(
                            "SELECT TIMESTAMPTZ '2026-09-20 16:37:00+00' "
                            "<= TIMESTAMP '2026-09-20 16:44:00'"
                        )
                    )
                    is True
                )
                assert connection.connection.dbapi_connection.autocommit is False
                # Context exit rolls back, as an empty queue/read-only poll does.
        with engine.connect() as connection:
            connection.execute(text("CREATE TEMP TABLE kenai_transaction_probe (value integer)"))
            connection.commit()
            connection.execute(text("INSERT INTO kenai_transaction_probe VALUES (1)"))
            connection.rollback()
            assert connection.scalar(text("SELECT count(*) FROM kenai_transaction_probe")) == 0
    finally:
        engine.dispose()
