from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.web_env_renderer import render_web_environment, write_new_environment


def parse_environment(content: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in content.splitlines())


def test_web_environment_contains_independent_production_secrets() -> None:
    first = parse_environment(render_web_environment())
    second = parse_environment(render_web_environment())

    assert first["KENAI_ENV"] == "production"
    assert first["KENAI_VPN_BACKEND"] == "helper"
    assert first["KENAI_COOKIE_SECURE"] == "true"
    assert first["KENAI_HOST"] == "127.0.0.1"
    assert first["KENAI_SUBSCRIPTION_PROTOCOLS"] == "vless"
    assert first["KENAI_BACKUP_PROTOCOLS"] == "vless"
    assert make_url(first["KENAI_DATABASE_URL"]).get_backend_name() == "postgresql"
    assert first["KENAI_DATABASE_URL"] != second["KENAI_DATABASE_URL"]
    assert first["KENAI_SECRET_KEY"] != second["KENAI_SECRET_KEY"]
    assert first["KENAI_ENCRYPTION_KEY"] != second["KENAI_ENCRYPTION_KEY"]


def test_web_environment_file_is_create_only(tmp_path: Path) -> None:
    target = tmp_path / "web.env"
    write_new_environment(target, "KENAI_ENV=production\n")

    with pytest.raises(FileExistsError):
        write_new_environment(target, "KENAI_ENV=test\n")

    assert target.read_text(encoding="utf-8") == "KENAI_ENV=production\n"


def test_production_settings_require_explicit_encryption_key() -> None:
    settings = Settings(
        env="production",
        database_url="sqlite:////var/lib/kenai-vpn-admin/kenai-admin.db",
        secret_key="a" * 32,
        encryption_key=None,
        vpn_backend="helper",
        host="10.66.66.1",
        cookie_secure=True,
    )

    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        settings.ensure_safe_production()


def test_production_settings_reject_sqlite() -> None:
    settings = Settings(
        env="production",
        database_url="sqlite:////var/lib/kenai-vpn-admin/kenai-admin.db",
        secret_key="a" * 32,
        encryption_key="b" * 44,
        vpn_backend="helper",
        host="10.66.66.1",
        cookie_secure=True,
    )

    with pytest.raises(RuntimeError, match="PostgreSQL"):
        settings.ensure_safe_production()
