"""Create a PostgreSQL environment beside an existing SQLite production environment.

Never modifies the live environment and never prints generated credentials.
"""

from __future__ import annotations

import argparse
import grp
import os
import secrets
import shlex
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("postgres_env_error=root_required")
    if not args.source.is_file() or args.source.is_symlink():
        raise SystemExit("postgres_env_error=source_invalid")
    lines = args.source.read_text(encoding="utf-8").splitlines()
    old_urls = [line for line in lines if line.startswith("KENAI_DATABASE_URL=")]
    if len(old_urls) != 1 or "sqlite" not in old_urls[0].lower():
        raise SystemExit("postgres_env_error=expected_one_sqlite_url")
    password = secrets.token_urlsafe(36)
    url = f"postgresql+psycopg://kenai:{password}@127.0.0.1:5432/kenai"
    rendered = (
        "\n".join(
            f"KENAI_DATABASE_URL={shlex.quote(url)}"
            if line.startswith("KENAI_DATABASE_URL=")
            else line
            for line in lines
        )
        + "\n"
    )
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(args.output, 0, grp.getgrnam("kenai-vpn").gr_gid)
        os.chmod(args.output, 0o640)
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print("postgres_environment_created=yes")
    print("secret_values_printed=0")


if __name__ == "__main__":
    main()
