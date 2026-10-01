from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Engine, func, inspect, select

from kenai_vpn_admin.infrastructure.database import Base


class DatabaseImportError(RuntimeError):
    pass


@dataclass(frozen=True)
class DatabaseImportResult:
    tables: int
    rows: int


def import_sqlite_database(
    source: Path,
    target: Engine,
    *,
    allow_non_postgresql_for_test: bool = False,
) -> DatabaseImportResult:
    """Copy a consistent legacy SQLite database into an empty migrated database."""
    source = source.expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise DatabaseImportError("SQLite source must be a regular file")
    if target.dialect.name != "postgresql" and not allow_non_postgresql_for_test:
        raise DatabaseImportError("Import target must be PostgreSQL")

    target_tables = set(inspect(target).get_table_names())
    expected_tables = {table.name for table in Base.metadata.sorted_tables}
    missing = expected_tables - target_tables
    if missing:
        raise DatabaseImportError("Target schema is incomplete; run Alembic migrations first")

    uri = f"file:{source.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as source_connection:
        source_connection.row_factory = sqlite3.Row
        if source_connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise DatabaseImportError("SQLite integrity check failed")
        source_tables = {
            str(row[0])
            for row in source_connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        copied_tables = 0
        copied_rows = 0
        with target.begin() as target_connection:
            occupied = [
                table.name
                for table in Base.metadata.sorted_tables
                if target_connection.scalar(select(func.count()).select_from(table))
            ]
            if occupied:
                raise DatabaseImportError("PostgreSQL target is not empty")

            for table in Base.metadata.sorted_tables:
                if table.name not in source_tables:
                    continue
                quoted_name = '"' + table.name.replace('"', '""') + '"'
                source_rows = source_connection.execute(f"SELECT * FROM {quoted_name}").fetchall()
                if not source_rows:
                    continue
                target_columns = {column.name: column for column in table.columns}
                rows = [
                    {
                        name: _convert_value(target_columns[name].type, value)
                        for name, value in dict(row).items()
                        if name in target_columns
                    }
                    for row in source_rows
                ]
                target_connection.execute(table.insert(), rows)
                copied_tables += 1
                copied_rows += len(rows)
    return DatabaseImportResult(copied_tables, copied_rows)


def _convert_value(column_type: Any, value: object) -> object:
    if value is None:
        return None
    if isinstance(column_type, Boolean):
        return bool(value)
    if isinstance(column_type, DateTime) and isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(column_type, JSON) and isinstance(value, str):
        return json.loads(value)
    return value
