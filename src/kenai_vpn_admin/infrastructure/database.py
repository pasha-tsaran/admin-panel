from collections.abc import Generator
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from kenai_vpn_admin.config import Settings


class Base(DeclarativeBase):
    pass


def _ensure_sqlite_directory(database_url: str) -> None:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return
    Path(url.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def build_engine(settings: Settings) -> Engine:
    _ensure_sqlite_directory(settings.database_url)
    backend = make_url(settings.database_url).get_backend_name()
    connect_args = {"check_same_thread": False} if backend == "sqlite" else {}
    pool_options: dict[str, Any] = {}
    if backend == "postgresql":
        pool_options = {"pool_size": 10, "max_overflow": 10, "pool_recycle": 1800}
    elif backend == "sqlite" and make_url(settings.database_url).database == ":memory:":
        pool_options = {"poolclass": StaticPool}
    engine = create_engine(
        settings.database_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        **pool_options,
    )
    if backend == "sqlite":

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    elif backend == "postgresql":

        @event.listens_for(engine, "connect")
        def force_postgresql_utc(dbapi_connection: object, _: object) -> None:
            # SET inside a transaction is undone by the first read-only session's
            # rollback. Set it outside a transaction, then restore normal writes.
            previous = dbapi_connection.autocommit  # type: ignore[attr-defined]
            dbapi_connection.autocommit = True  # type: ignore[attr-defined]
            try:
                cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
                try:
                    cursor.execute("SET TIME ZONE 'UTC'")
                finally:
                    cursor.close()
            finally:
                dbapi_connection.autocommit = previous  # type: ignore[attr-defined]

    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def session_dependency(factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    with factory() as session:
        yield session
