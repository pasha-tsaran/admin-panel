from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from kenai_vpn_admin.infrastructure.database import Base
from kenai_vpn_admin.infrastructure.models import UserModel, utc_now
from kenai_vpn_admin.infrastructure.sqlite_import import (
    DatabaseImportError,
    import_sqlite_database,
)


def test_sqlite_import_copies_rows_and_refuses_an_occupied_target(tmp_path: Path) -> None:
    source_path = tmp_path / "legacy.db"
    source_engine = create_engine(f"sqlite:///{source_path}")
    Base.metadata.create_all(source_engine)
    with Session(source_engine) as db:
        db.add(
            UserModel(
                slug="legacy-user",
                display_name="Legacy user",
                status="active",
                subscription_expires_at=utc_now(),
            )
        )
        db.commit()
    source_engine.dispose()

    target_engine = create_engine(f"sqlite:///{tmp_path / 'target.db'}")
    Base.metadata.create_all(target_engine)
    result = import_sqlite_database(source_path, target_engine, allow_non_postgresql_for_test=True)
    assert result.rows == 1
    with Session(target_engine) as db:
        assert db.scalar(select(UserModel.slug)) == "legacy-user"

    with pytest.raises(DatabaseImportError, match="not empty"):
        import_sqlite_database(source_path, target_engine, allow_non_postgresql_for_test=True)
    target_engine.dispose()
