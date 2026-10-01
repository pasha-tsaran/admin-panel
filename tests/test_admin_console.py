import re
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from kenai_vpn_admin.application.rbac import PERMISSIONS
from kenai_vpn_admin.infrastructure.models import (
    ApiTokenModel,
    ServerMetricModel,
    SubscriptionEventModel,
    SubscriptionModel,
    TelegramRecipientModel,
    utc_now,
)
from kenai_vpn_admin.infrastructure.node_agent import NodeAgentClient
from kenai_vpn_admin.security import hash_token


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def test_console_pages_use_real_empty_states(authenticated_client: TestClient) -> None:
    home = authenticated_client.get("/")
    users = authenticated_client.get("/users")
    settings = authenticated_client.get("/settings")

    assert home.status_code == users.status_code == settings.status_code == 200
    assert "нет данных" in home.text
    assert "Пользователи" in users.text
    assert "Bot token не настроен" in settings.text


def test_rbac_is_enforced_by_server_for_every_admin_request(
    authenticated_client: TestClient, admin
) -> None:
    with authenticated_client.app.state.session_factory() as db:
        model = db.get(type(admin), admin.id)
        assert model is not None
        model.role = "custom"
        model.permissions_json = ["users"]
        db.commit()

    assert authenticated_client.get("/users").status_code == 200
    assert authenticated_client.get("/topology").status_code == 403
    assert authenticated_client.get("/settings").status_code == 403
    assert (
        authenticated_client.post(
            "/logout", data={"csrf_token": csrf(authenticated_client)}, follow_redirects=False
        ).status_code
        == 303
    )


def test_api_token_plaintext_is_shown_once_and_only_hash_is_stored(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/settings/api-tokens",
        data={
            "csrf_token": csrf(authenticated_client),
            "name": "automation",
            "permissions": ["users", "audit"],
            "expires_in_days": "30",
        },
    )
    assert response.status_code == 200
    match = re.search(r'value="(kn_[A-Za-z0-9_-]+)"', response.text)
    assert match is not None
    plaintext = match.group(1)
    with authenticated_client.app.state.session_factory() as db:
        token = db.scalar(select(ApiTokenModel))
        assert token is not None
        assert token.token_hash == hash_token(plaintext)
        assert plaintext not in repr(token.__dict__)
        assert token.permissions_json == ["audit", "users"]
    reopened = authenticated_client.get("/settings?section=api")
    assert plaintext not in reopened.text


def test_metrics_collection_retains_thirty_days_and_keeps_unknowns_null(
    authenticated_client: TestClient,
) -> None:
    with authenticated_client.app.state.session_factory() as db:
        db.add(
            ServerMetricModel(
                source="primary",
                captured_at=utc_now() - timedelta(days=31),
                health_status="online",
            )
        )
        db.commit()
        metric = authenticated_client.app.state.console_service.collect_metrics(db)
        db.commit()
        assert metric.cpu_percent is None
        assert metric.memory_percent is None
        assert metric.disk_percent is None
        assert len(list(db.scalars(select(ServerMetricModel)))) == 1


def test_telegram_categories_are_persisted_without_bot_token(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/settings/telegram/recipients",
        data={
            "csrf_token": csrf(authenticated_client),
            "label": "Duty",
            "chat_id": "123456",
            "categories": ["server_unavailable", "backup_failed"],
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with authenticated_client.app.state.session_factory() as db:
        recipient = db.scalar(select(TelegramRecipientModel))
        assert recipient is not None
        assert recipient.categories_json == ["backup_failed", "server_unavailable"]
        assert (
            authenticated_client.app.state.console_service.queue_notification(
                db, category="server_unavailable", message="Node unavailable"
            )
            == 1
        )
        assert authenticated_client.app.state.console_service.send_pending_notifications(db) == 0


def test_subscription_creation_records_manual_confirmation_history(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(authenticated_client),
            "display_name": "Subscriber",
            "email": "subscriber@example.com",
            "telegram_username": "",
            "phone_number": "",
            "comment": "",
            "period_type": "30",
            "device_limit": "3",
        },
    )
    assert response.status_code == 201
    with authenticated_client.app.state.session_factory() as db:
        subscription = db.scalar(select(SubscriptionModel))
        event = db.scalar(select(SubscriptionEventModel))
        assert subscription is not None and subscription.status == "active"
        assert subscription.confirmed_at is not None
        assert event is not None and event.event_type == "manual_confirm"
        assert event.details_json == {"provider": None, "automatic_payment": False}


def test_manual_issuance_creates_real_one_time_package(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/issuance",
        data={
            "csrf_token": csrf(authenticated_client),
            "display_name": "Manual user",
            "duration_days": "30",
            "device_limit": "1",
            "server": "primary",
            "amneziawg": "true",
            "vless": "true",
            "comment": "",
        },
    )
    assert response.status_code == 201
    assert "/provision/" in response.text
    assert "PrivateKey" not in response.text
    assert "vless://" not in response.text


def test_node_agent_rejects_paths_and_non_https_origins() -> None:
    fingerprint = "a" * 64
    for endpoint in ("http://203.0.113.10:9443", "https://203.0.113.10:9443/path"):
        try:
            NodeAgentClient(endpoint, fingerprint)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe agent origin was accepted")


def test_permission_catalog_covers_requested_modules() -> None:
    assert {
        "users",
        "issuance",
        "servers",
        "audit",
        "administrators",
        "settings",
        "backups",
        "api_tokens",
        "billing",
    } == PERMISSIONS
