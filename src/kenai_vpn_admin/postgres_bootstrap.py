from __future__ import annotations

import os

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


def main() -> None:
    parsed = make_url(os.environ["KENAI_DATABASE_URL"])
    if (
        parsed.get_backend_name() != "postgresql"
        or parsed.host not in {"127.0.0.1", "localhost"}
        or not parsed.username
        or not parsed.database
        or parsed.password is None
    ):
        raise SystemExit("postgres_bootstrap_error=unsupported_database_url")
    with psycopg.connect(dbname="postgres") as connection:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (parsed.username,))
            if cursor.fetchone() is not None:
                raise SystemExit("postgres_bootstrap_error=role_already_exists")
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (parsed.database,))
            if cursor.fetchone() is not None:
                raise SystemExit("postgres_bootstrap_error=database_already_exists")
            cursor.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(parsed.username), sql.Literal(parsed.password)
                )
            )
            try:
                cursor.execute(
                    sql.SQL("CREATE DATABASE {} OWNER {}").format(
                        sql.Identifier(parsed.database), sql.Identifier(parsed.username)
                    )
                )
            except Exception:
                cursor.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(parsed.username)))
                raise
    print("postgres_database_created=yes")
    print("postgres_secret_printed=0")


if __name__ == "__main__":
    main()
