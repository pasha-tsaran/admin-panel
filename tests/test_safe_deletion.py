import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from kenai_vpn_admin.domain.enums import LifecycleStatus, Protocol
from kenai_vpn_admin.infrastructure.models import (
    AdministratorModel,
    AuditEventModel,
    DeviceModel,
    UserModel,
)


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def critical(client: TestClient, totp_secret: str) -> dict[str, str]:
    return {
        "acting_password": "correct horse battery staple",
        "acting_totp": pyotp.TOTP(totp_secret).now(),
    }


def create_user_and_device(client: TestClient) -> tuple[str, str]:
    created = client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "slug": "delete-test",
            "display_name": "Delete test",
            "comment": "",
        },
        follow_redirects=False,
    )
    user_id = created.headers["location"].rsplit("/", 1)[-1]
    client.post(
        f"/users/{user_id}/devices",
        data={
            "csrf_token": csrf(client),
            "slug": "device",
            "display_name": "Device",
            "amneziawg": "true",
            "vless": "true",
        },
    )
    with client.app.state.session_factory() as db:
        device_id = db.scalar(select(DeviceModel.id).where(DeviceModel.user_id == user_id))
        assert device_id
    return user_id, device_id


def test_device_deletion_revokes_its_protocols_without_deleting_other_devices(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    user_id, device_id = create_user_and_device(client)
    client.post(
        f"/users/{user_id}/devices",
        data={
            "csrf_token": csrf(client),
            "slug": "other-device",
            "display_name": "Other device",
            "amneziawg": "true",
        },
    )
    with client.app.state.session_factory() as db:
        other_device_id = db.scalar(
            select(DeviceModel.id).where(
                DeviceModel.user_id == user_id, DeviceModel.slug == "other-device"
            )
        )
        assert other_device_id

    deleted = client.post(
        f"/devices/{device_id}/delete",
        data={
            "csrf_token": csrf(client),
            "confirmation": "DELETE",
            **critical(client, totp_secret),
        },
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == f"/users/{user_id}"

    with client.app.state.session_factory() as db:
        assert db.get(DeviceModel, device_id) is None
        assert db.get(DeviceModel, other_device_id) is not None
        event = db.scalar(select(AuditEventModel).where(AuditEventModel.action == "device.delete"))
        assert event is not None
        assert event.device_id is None
        assert event.metadata_json == {"device_slug": "device"}
        revoked_protocols = {
            metadata["protocol"]
            for metadata in db.scalars(
                select(AuditEventModel.metadata_json).where(
                    AuditEventModel.action == "protocol.revoke"
                )
            )
        }
        assert revoked_protocols == {"amneziawg", "vless"}


def test_user_deletion_revokes_every_protocol_and_requires_confirmation(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    user_id, _ = create_user_and_device(client)

    missing_confirmation = client.post(
        f"/users/{user_id}/delete",
        data={"csrf_token": csrf(client), "confirmation": "delete"},
    )
    assert missing_confirmation.status_code == 409

    deleted = client.post(
        f"/users/{user_id}/delete",
        data={
            "csrf_token": csrf(client),
            "confirmation": "DELETE",
            **critical(client, totp_secret),
        },
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/"

    with client.app.state.session_factory() as db:
        assert db.get(UserModel, user_id) is None
        event = db.scalar(select(AuditEventModel).where(AuditEventModel.action == "user.delete"))
        assert event is not None
        assert event.user_id is None
        assert event.metadata_json == {"user_slug": "delete-test", "device_count": 1}
        revoke_events = list(
            db.scalars(select(AuditEventModel).where(AuditEventModel.action == "protocol.revoke"))
        )
        assert len(revoke_events) == 2

    states = client.app.state.vpn_manager._states
    assert states[("delete-test-device", Protocol.AMNEZIAWG)] is False
    assert states[("delete-test-device", Protocol.VLESS)] is False


def test_user_is_preserved_when_one_protocol_cannot_be_revoked(
    authenticated_client: TestClient, monkeypatch, totp_secret: str
) -> None:
    client = authenticated_client
    user_id, device_id = create_user_and_device(client)
    original_revoke = client.app.state.vpn_manager.revoke

    def fail_vless(device_ref: str, protocol: Protocol) -> None:
        if protocol is Protocol.VLESS:
            raise RuntimeError("simulated helper failure")
        original_revoke(device_ref, protocol)

    monkeypatch.setattr(client.app.state.vpn_manager, "revoke", fail_vless)
    response = client.post(
        f"/users/{user_id}/delete",
        data={
            "csrf_token": csrf(client),
            "confirmation": "DELETE",
            **critical(client, totp_secret),
        },
    )

    assert response.status_code == 409
    with client.app.state.session_factory() as db:
        assert db.get(UserModel, user_id) is not None
        device = db.get(DeviceModel, device_id)
        assert device is not None
        assert device.amneziawg is not None
        assert device.vless is not None
        assert device.amneziawg.status == LifecycleStatus.ACTIVE.value
        assert device.vless.status == LifecycleStatus.ACTIVE.value


def test_existing_wireguard_access_is_revoked_on_device_deletion(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    user_id, device_id = create_user_and_device(client)
    with client.app.state.session_factory() as db:
        administrator_id = db.scalar(select(AdministratorModel.id))
        assert administrator_id
        client.app.state.admin_service.issue_protocol(
            db,
            device_id=device_id,
            protocol=Protocol.WIREGUARD,
            administrator_id=administrator_id,
            correlation_id="legacy-wireguard-test",
        )
        db.commit()

    deleted = client.post(
        f"/devices/{device_id}/delete",
        data={
            "csrf_token": csrf(client),
            "confirmation": "DELETE",
            **critical(client, totp_secret),
        },
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == f"/users/{user_id}"
    with client.app.state.session_factory() as db:
        assert db.get(DeviceModel, device_id) is None
    assert client.app.state.vpn_manager._states[("delete-test-device", Protocol.WIREGUARD)] is False
