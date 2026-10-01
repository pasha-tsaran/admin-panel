from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.database import Base
from kenai_vpn_admin.infrastructure.models import AdministratorModel
from kenai_vpn_admin.main import create_app
from kenai_vpn_admin.security import hash_password


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        env="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        secret_key="test-secret-key-with-at-least-thirty-two-characters",
        vpn_backend="mock",
        cookie_secure=False,
    )


@pytest.fixture
def app(settings: Settings):
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    yield application
    Base.metadata.drop_all(application.state.engine)


@pytest.fixture
def totp_secret() -> str:
    return pyotp.random_base32()


@pytest.fixture
def admin(app, totp_secret: str) -> AdministratorModel:
    with app.state.session_factory() as db:
        model = AdministratorModel(
            username="admin",
            password_hash=hash_password("correct horse battery staple"),
            encrypted_totp_secret=app.state.cipher.encrypt(totp_secret),
        )
        db.add(model)
        db.commit()
        db.refresh(model)
        db.expunge(model)
        return model


@pytest.fixture
def client(app) -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client: TestClient, admin, totp_secret: str) -> TestClient:
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
    return client
