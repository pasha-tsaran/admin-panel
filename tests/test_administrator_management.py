import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from kenai_vpn_admin.infrastructure.models import AdministratorModel, AuditEventModel
from kenai_vpn_admin.security import verify_password


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def test_create_and_confirm_administrator_totp(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    response = client.post(
        "/administrators",
        data={
            "csrf_token": csrf(client),
            "username": "second-admin",
            "password": "another secure password",
            "password_repeat": "another secure password",
            "acting_password": "correct horse battery staple",
            "acting_totp": pyotp.TOTP(totp_secret).now(),
        },
    )
    assert response.status_code == 200
    assert "data:image/png;base64," in response.text
    assert response.headers["cache-control"] == "no-store"

    with client.app.state.session_factory() as db:
        administrator = db.scalar(
            select(AdministratorModel).where(AdministratorModel.username == "second-admin")
        )
        assert administrator is not None
        assert administrator.is_active is False
        assert administrator.totp_confirmed is False
        new_secret = client.app.state.cipher.decrypt(administrator.encrypted_totp_secret)
        administrator_id = administrator.id

    confirmed = client.post(
        f"/administrators/{administrator_id}/confirm-totp",
        data={"csrf_token": csrf(client), "totp_code": pyotp.TOTP(new_secret).now()},
        follow_redirects=False,
    )
    assert confirmed.status_code == 303
    with client.app.state.session_factory() as db:
        administrator = db.get(AdministratorModel, administrator_id)
        assert administrator is not None
        assert administrator.is_active is True
        assert administrator.totp_confirmed is True
        events = list(db.scalars(select(AuditEventModel)))
        assert all(new_secret not in str(event.metadata_json) for event in events)


def test_password_change_and_totp_reset_are_reauthenticated(
    authenticated_client: TestClient, admin: AdministratorModel, totp_secret: str
) -> None:
    client = authenticated_client
    wrong = client.post(
        "/administrators/change-password",
        data={
            "csrf_token": csrf(client),
            "current_password": "wrong password",
            "current_totp": pyotp.TOTP(totp_secret).now(),
            "new_password": "new password value",
            "new_password_repeat": "new password value",
        },
        follow_redirects=False,
    )
    assert wrong.headers["location"] == "/administrators?notice=invalid"

    changed = client.post(
        "/administrators/change-password",
        data={
            "csrf_token": csrf(client),
            "current_password": "correct horse battery staple",
            "current_totp": pyotp.TOTP(totp_secret).now(),
            "new_password": "new password value",
            "new_password_repeat": "new password value",
        },
        follow_redirects=False,
    )
    assert changed.status_code == 303
    with client.app.state.session_factory() as db:
        refreshed = db.get(AdministratorModel, admin.id)
        assert refreshed is not None
        assert verify_password(refreshed.password_hash, "new password value")

    reset = client.post(
        "/administrators/reset-totp",
        data={
            "csrf_token": csrf(client),
            "current_password": "new password value",
            "current_totp": pyotp.TOTP(totp_secret).now(),
        },
    )
    assert reset.status_code == 200
    with client.app.state.session_factory() as db:
        refreshed = db.get(AdministratorModel, admin.id)
        assert refreshed is not None
        assert refreshed.pending_encrypted_totp_secret is not None
        assert client.app.state.auth_service.verify_totp(refreshed, pyotp.TOTP(totp_secret).now())


def test_administrator_cannot_disable_self(
    authenticated_client: TestClient, admin: AdministratorModel, totp_secret: str
) -> None:
    response = authenticated_client.post(
        f"/administrators/{admin.id}/status",
        data={
            "csrf_token": csrf(authenticated_client),
            "active": "false",
            "acting_password": "correct horse battery staple",
            "acting_totp": pyotp.TOTP(totp_secret).now(),
        },
        follow_redirects=False,
    )
    assert response.headers["location"] == "/administrators?notice=invalid"
    with authenticated_client.app.state.session_factory() as db:
        refreshed = db.get(AdministratorModel, admin.id)
        assert refreshed is not None and refreshed.is_active
