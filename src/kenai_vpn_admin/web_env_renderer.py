from __future__ import annotations

import argparse
import os
import secrets
import shlex
from pathlib import Path

from cryptography.fernet import Fernet


def render_web_environment() -> str:
    database_password = secrets.token_urlsafe(36)
    values = {
        "KENAI_ENV": "production",
        "KENAI_DATABASE_URL": (
            f"postgresql+psycopg://kenai:{database_password}@127.0.0.1:5432/kenai"
        ),
        "KENAI_SECRET_KEY": secrets.token_urlsafe(48),
        "KENAI_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
        "KENAI_VPN_BACKEND": "helper",
        "KENAI_SUBSCRIPTION_PROTOCOLS": "vless",
        "KENAI_BACKUP_PROTOCOLS": "vless",
        "KENAI_HELPER_SOCKET": "/run/kenai-vpn/helper.sock",
        "KENAI_HOST": "127.0.0.1",
        "KENAI_PORT": "8443",
        "KENAI_COOKIE_SECURE": "true",
        "KENAI_SESSION_TTL_MINUTES": "60",
        "KENAI_PROVISIONING_TTL_MINUTES": "15",
        "KENAI_LOGIN_MAX_ATTEMPTS": "5",
        "KENAI_LOGIN_WINDOW_MINUTES": "15",
    }
    return "\n".join(f"{name}={shlex.quote(value)}" for name, value in values.items()) + "\n"


def write_new_environment(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a production Kenai web environment")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_new_environment(args.output, render_web_environment())
    print("web_environment_created=yes")
    print("secret_values_printed=0")


if __name__ == "__main__":
    main()
