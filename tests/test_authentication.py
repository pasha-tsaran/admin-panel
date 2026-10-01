import pyotp
import pytest
from fastapi.testclient import TestClient

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.database import Base
from kenai_vpn_admin.infrastructure.models import AdministratorModel
from kenai_vpn_admin.main import create_app
from kenai_vpn_admin.security import hash_password


def test_password_minimum_length_is_ten_characters() -> None:
    with pytest.raises(ValueError, match="at least 10"):
        hash_password("123456789")
    assert hash_password("1234567890")


def test_login_requires_valid_password_and_totp(
    client: TestClient, admin, totp_secret: str
) -> None:
    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong password value", "totp_code": "000000"},
    )
    assert response.status_code == 401
    assert "Неверные данные" in response.text

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "totp_code": pyotp.TOTP(totp_secret).now(),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert response.cookies.get("kenai_session")


def test_dashboard_redirects_without_session(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_test_preview_can_disable_login_totp(settings: Settings) -> None:
    preview_settings = settings.model_copy(update={"login_totp_required": False})
    app = create_app(preview_settings)
    Base.metadata.create_all(app.state.engine)
    with app.state.session_factory() as db:
        db.add(
            AdministratorModel(
                username="preview-admin",
                password_hash=hash_password("preview password 2026"),
                encrypted_totp_secret=app.state.cipher.encrypt("JBSWY3DPEHPK3PXP"),
            )
        )
        db.commit()
    with TestClient(app) as preview_client:
        page = preview_client.get("/login")
        assert 'name="totp_code"' not in page.text
        response = preview_client.post(
            "/login",
            data={"username": "preview-admin", "password": "preview password 2026"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_totp_bypass_is_rejected_outside_test_mode() -> None:
    settings = Settings(
        env="development",
        database_url="sqlite:///:memory:",
        secret_key="development-secret-key-with-at-least-32-characters",
        login_totp_required=False,
    )
    with pytest.raises(RuntimeError, match="allowed only in test mode"):
        create_app(settings)


def test_create_app_rejects_unsafe_explicit_production_settings() -> None:
    settings = Settings(
        env="production",
        database_url="sqlite:///:memory:",
        secret_key="production-secret-key-with-at-least-32-characters",
        encryption_key="invalid-but-not-reached",
        vpn_backend="mock",
        cookie_secure=False,
    )

    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        create_app(settings)
