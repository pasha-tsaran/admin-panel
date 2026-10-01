import io
import re
import zipfile
from datetime import UTC, date, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from kenai_vpn_admin.application.ports import DeviceRuntimeStatus, ProtocolRuntimeStatus
from kenai_vpn_admin.infrastructure.models import DeviceModel, UserModel, utc_now
from kenai_vpn_admin.web.routes import subscription_period


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def critical(totp_secret: str) -> dict[str, str]:
    return {
        "acting_password": "correct horse battery staple",
        "acting_totp": pyotp.TOTP(totp_secret).now(),
    }


def test_subscription_period_accepts_presets_custom_days_and_calendar_date() -> None:
    assert subscription_period("3", "", "") == (3, None)
    assert subscription_period("30", "", "") == (30, None)
    assert subscription_period("custom_days", "90", "") == (90, None)
    assert subscription_period("date", "", "2026-12-31") == (None, date(2026, 12, 31))


def test_activation_subscription_issues_every_protocol_and_authenticates_app(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    # Existing deployments can still have WireGuard in their saved configuration.
    client.app.state.settings.subscription_protocols = "wireguard,amneziawg,vless"
    created = client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(client),
            "email": "Buyer@Example.com",
            "telegram_username": "@buyer_name",
            "phone_number": "+7 999 111-22-33",
            "comment": "Paid subscription",
        },
    )

    assert created.status_code == 201
    match = re.search(r'value="(\d{12})" readonly', created.text)
    assert match is not None
    activation_key = match.group(1)
    assert all(name in created.text for name in ("AmneziaWG 2.0", "VLESS"))
    assert "WireGuard" not in created.text

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.email == "buyer@example.com"))
        assert user is not None
        assert user.activation_key_hash is not None
        assert user.encrypted_activation_key is not None
        assert activation_key not in user.activation_key_hash
        assert user.telegram_username == "buyer_name"
        assert len(user.devices) == 1
        device = user.devices[0]
        assert device.slug == "primary"
        assert device.wireguard is None
        assert device.amneziawg and device.vless

    activated = client.post("/api/v1/activate", json={"activation_key": activation_key})
    assert activated.status_code == 200
    assert activated.headers["cache-control"] == "no-store"
    payload = activated.json()
    assert payload["account"]["email"] == "buyer@example.com"
    assert set(payload["protocols"]) == {"wireguard", "amneziawg", "vless"}
    assert payload["protocols"]["wireguard"] is None
    assert payload["protocols"]["vless"].startswith("vless://")

    rejected = client.post("/api/v1/activate", json={"activation_key": "000000000000"})
    assert rejected.status_code == 401

    dashboard = client.get("/")
    assert "buyer@example.com" in dashboard.text
    assert "Создайте пользователя и передайте ему" not in dashboard.text
    assert "Подключено пользователей: 1" in dashboard.text
    application_connections = client.get("/connections/vless?source=app")
    assert application_connections.status_code == 200
    assert "Ключ активации" in application_connections.text
    assert activation_key in application_connections.text
    assert "Приложение" in application_connections.text
    legacy = client.get("/legacy")
    assert "buyer@example.com" not in legacy.text
    assert "Подключено пользователей: 0" in legacy.text

    profile = client.get(f"/users/{payload['account']['id']}")
    assert profile.status_code == 200
    assert activation_key in profile.text
    assert "data-secret-toggle" in profile.text
    assert "data-secret-copy" in profile.text

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.id == payload["account"]["id"]))
        assert user is not None
        user.subscription_expires_at = utc_now() - timedelta(minutes=1)
        db.commit()
        targets = client.app.state.admin_service.expired_subscription_targets(db)
        assert len(targets) == 2
        for device_id, protocol in targets:
            client.app.state.admin_service.set_protocol_enabled(
                db,
                device_id=device_id,
                protocol=protocol,
                enabled=False,
                administrator_id=None,
                correlation_id="subscription-expired-test",
            )
            db.commit()

    expired = client.post("/api/v1/activate", json={"activation_key": activation_key})
    assert expired.status_code == 401

    renewed = client.post(
        f"/users/{payload['account']['id']}/subscription/renew",
        data={
            "csrf_token": csrf(client),
            "period_type": "custom_days",
            "custom_days": "45",
        },
        follow_redirects=True,
    )
    assert renewed.status_code == 200
    keys = re.findall(r'value="(\d{12})" readonly', renewed.text)
    assert keys == [activation_key]
    assert "Продлить и включить доступ" in renewed.text
    assert (
        client.post("/api/v1/activate", json={"activation_key": activation_key}).status_code == 200
    )

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.id == payload["account"]["id"]))
        assert user is not None
        assert user.subscription_expires_at is not None
        assert user.subscription_expires_at > utc_now() + timedelta(days=44)
        device = user.devices[0]
        assert device.wireguard is None
        assert device.amneziawg and device.amneziawg.status == "active"
        assert device.vless and device.vless.status == "active"


def test_activation_api_rate_limits_repeated_failures(authenticated_client: TestClient) -> None:
    client = authenticated_client
    for attempt in range(10):
        response = client.post("/api/v1/activate", json={"activation_key": f"{attempt:012d}"})
        assert response.status_code == 401
    limited = client.post("/api/v1/activate", json={"activation_key": "999999999999"})
    assert limited.status_code == 429


def test_vless_only_subscription_does_not_issue_unused_protocols(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    client.app.state.settings.subscription_protocols = "vless"
    created = client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(client),
            "email": "vless-only@example.com",
            "telegram_username": "",
            "phone_number": "",
            "comment": "VLESS-only",
        },
    )

    assert created.status_code == 201
    match = re.search(r'value="(\d{12})" readonly', created.text)
    assert match is not None
    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.email == "vless-only@example.com"))
        assert user is not None
        device = user.devices[0]
        assert device.wireguard is None
        assert device.amneziawg is None
        assert device.vless is not None

    payload = client.post("/api/v1/activate", json={"activation_key": match.group(1)}).json()
    assert payload["protocols"] == {
        "wireguard": None,
        "amneziawg": None,
        "vless": payload["protocols"]["vless"],
    }
    assert payload["protocols"]["vless"].startswith("vless://")


def test_shared_subscription_key_issues_independent_idempotent_vless_profiles(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    client.app.state.settings.subscription_protocols = "vless"
    client.app.state.settings.max_subscription_devices = 2
    client.app.state.settings.netherlands_address = "147.45.231.194"
    client.app.state.settings.netherlands_server_name = "www.example.org"
    client.app.state.settings.netherlands_public_key = "A" * 43
    client.app.state.settings.netherlands_short_id = "aabbccdd"
    created = client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(client),
            "email": "shared@example.com",
            "telegram_username": "",
            "phone_number": "",
            "comment": "Shared MVP key",
        },
    )
    assert created.status_code == 201
    match = re.search(r'value="(\d{12})" readonly', created.text)
    assert match is not None
    key = match.group(1)
    first_id = "a" * 32
    second_id = "b" * 32

    first = client.post("/api/v1/activate", json={"activation_key": key, "device_id": first_id})
    repeated = client.post("/api/v1/activate", json={"activation_key": key, "device_id": first_id})
    second = client.post("/api/v1/activate", json={"activation_key": key, "device_id": second_id})
    assert first.status_code == repeated.status_code == second.status_code == 200
    first_uri = first.json()["protocols"]["vless"]
    second_uri = second.json()["protocols"]["vless"]
    first_nl_uri = first.json()["locations"]["netherlands-1"]["vless"]
    second_nl_uri = second.json()["locations"]["netherlands-1"]["vless"]
    assert urlsplit(first_nl_uri).username == urlsplit(first_uri).username
    assert urlsplit(second_nl_uri).username == urlsplit(second_uri).username
    assert urlsplit(first_nl_uri).hostname == "147.45.231.194"
    assert parse_qs(urlsplit(first_nl_uri).query)["sni"] == ["www.example.org"]
    assert first_nl_uri == repeated.json()["locations"]["netherlands-1"]["vless"]
    assert first_uri == repeated.json()["protocols"]["vless"]
    assert first_uri != second_uri
    assert first.json()["protocols"]["wireguard"] is None
    assert second.json()["protocols"]["amneziawg"] is None

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.email == "shared@example.com"))
        assert user is not None
        assert {device.slug for device in user.devices} == {
            "primary",
            f"app-{first_id}",
            f"app-{second_id}",
        }
        assert len({device.vless.client_uuid for device in user.devices if device.vless}) == 3
        assert all(device.wireguard is None for device in user.devices)

    over_limit = client.post(
        "/api/v1/activate", json={"activation_key": key, "device_id": "c" * 32}
    )
    assert over_limit.status_code == 409
    assert (
        client.post(
            "/api/v1/activate", json={"activation_key": key, "device_id": first_id}
        ).status_code
        == 200
    )

    assert (
        client.post(
            "/api/v1/activate", json={"activation_key": key, "device_id": "not-a-uuid"}
        ).status_code
        == 422
    )

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.email == "shared@example.com"))
        assert user is not None
        user.subscription_expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
        targets = client.app.state.admin_service.expired_subscription_targets(db)
        assert len(targets) == 3
        for device_id, protocol in targets:
            client.app.state.admin_service.set_protocol_enabled(
                db,
                device_id=device_id,
                protocol=protocol,
                enabled=False,
                administrator_id=None,
                correlation_id="shared-expiry-test",
            )
        db.commit()

    assert (
        client.post(
            "/api/v1/activate", json={"activation_key": key, "device_id": first_id}
        ).status_code
        == 401
    )
    renewed = client.post(
        f"/users/{first.json()['account']['id']}/subscription/renew",
        data={"csrf_token": csrf(client), "period_type": "30"},
        follow_redirects=True,
    )
    assert renewed.status_code == 200
    assert (
        client.post(
            "/api/v1/activate", json={"activation_key": key, "device_id": first_id}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/activate", json={"activation_key": key, "device_id": second_id}
        ).status_code
        == 200
    )


def test_existing_vless_install_gains_awg_with_same_account_key(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    client.app.state.settings.subscription_protocols = "vless"
    created = client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(client),
            "email": "dual-protocol@example.com",
            "telegram_username": "",
            "phone_number": "",
            "comment": "Dual protocol",
        },
    )
    assert created.status_code == 201
    match = re.search(r'value="(\d{12})" readonly', created.text)
    assert match is not None
    request = {"activation_key": match.group(1), "device_id": "d" * 32}
    before = client.post("/api/v1/activate", json=request)
    assert before.status_code == 200
    assert before.json()["protocols"]["amneziawg"] is None
    original_vless = before.json()["protocols"]["vless"]

    client.app.state.settings.subscription_protocols = "vless,amneziawg"
    upgraded = client.post("/api/v1/activate", json=request)
    repeated = client.post("/api/v1/activate", json=request)
    another = client.post(
        "/api/v1/activate",
        json={"activation_key": match.group(1), "device_id": "e" * 32},
    )
    assert upgraded.status_code == repeated.status_code == another.status_code == 200
    assert upgraded.json()["protocols"]["vless"] == original_vless
    assert upgraded.json()["protocols"]["amneziawg"] == repeated.json()["protocols"]["amneziawg"]
    assert "[Interface]" in upgraded.json()["protocols"]["amneziawg"]
    assert another.json()["protocols"]["amneziawg"] != upgraded.json()["protocols"]["amneziawg"]
    assert another.json()["protocols"]["vless"] != original_vless


def test_create_user_device_and_one_time_dual_protocol_package(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    response = client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "slug": "ivan",
            "display_name": "Иван",
            "comment": "Тестовый пользователь",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    user_url = response.headers["location"]

    page = client.get(user_url)
    assert page.status_code == 200
    user_id = user_url.rsplit("/", 1)[-1]
    response = client.post(
        f"/users/{user_id}/devices",
        data={
            "csrf_token": csrf(client),
            "slug": "windows-pc",
            "display_name": "Windows-PC",
            "wireguard": "true",
            "amneziawg": "true",
            "vless": "true",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "WireGuard" not in response.text
    assert "AmneziaWG 2.0" in response.text
    assert "VLESS" in response.text

    dashboard = client.get("/legacy")
    assert dashboard.status_code == 200
    assert "1 AWG · 1 VLESS" in dashboard.text
    assert "Всего:" not in dashboard.text  # noqa: RUF001
    assert "Выдано доступов: 1" not in dashboard.text
    assert "Подключения VLESS / Xray" in dashboard.text
    assert "Подключено пользователей: 1" in dashboard.text
    assert "Активных устройств: 1" in dashboard.text
    assert 'href="/connections/wireguard"' not in dashboard.text
    assert 'href="/connections/amneziawg?source=manual"' in dashboard.text
    assert 'href="/connections/vless?source=manual"' in dashboard.text
    assert "data-user-search" in dashboard.text
    assert 'data-protocol-filter="wireguard"' not in dashboard.text
    assert 'data-protocol-filter="amneziawg"' in dashboard.text
    assert "иван ivan" in dashboard.text.lower()
    assert "windows-pc windows-pc" in dashboard.text.lower()

    vless_traffic = client.get("/connections/vless?source=manual")
    assert vless_traffic.status_code == 200
    assert "Подключённые устройства" in vless_traffic.text
    assert "Xray Stats API" in vless_traffic.text
    assert "Windows-PC" in vless_traffic.text
    assert "2.0 МБ" in vless_traffic.text
    assert "0.8 МБ" in vless_traffic.text
    assert "Ручная выдача" in vless_traffic.text

    application_dashboard = client.get("/")
    assert application_dashboard.status_code == 200
    assert "Подключено пользователей: 0" in application_dashboard.text
    assert 'href="/connections/vless?source=app"' in application_dashboard.text

    amneziawg_connections = client.get("/connections/amneziawg?source=manual")
    assert amneziawg_connections.status_code == 200
    assert "Подключённые устройства" in amneziawg_connections.text
    assert "Windows-PC" in amneziawg_connections.text
    assert "3.0 МБ" in amneziawg_connections.text
    assert "1.0 МБ" in amneziawg_connections.text

    with client.app.state.session_factory() as db:
        device_id = db.scalar(select(DeviceModel.id))
        assert device_id

    blocked_wireguard_issue = client.post(
        f"/devices/{device_id}/protocol/wireguard/issue",
        data={"csrf_token": csrf(client), "confirmation": "ISSUE"},
    )
    assert blocked_wireguard_issue.status_code == 409

    amneziawg_qr = client.get(f"/devices/{device_id}/qr/amneziawg")
    assert amneziawg_qr.status_code == 200
    assert amneziawg_qr.headers["content-type"] == "image/png"
    assert amneziawg_qr.content.startswith(b"\x89PNG")

    revoked = client.post(
        f"/devices/{device_id}/protocol/vless/revoke",
        data={
            "csrf_token": csrf(client),
            "confirmation": "REVOKE",
            **critical(totp_secret),
        },
        headers={"referer": "https://attacker.example/phishing"},
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    assert revoked.headers["location"] == "/"
    reissued = client.post(
        f"/devices/{device_id}/protocol/vless/issue",
        data={"csrf_token": csrf(client), "confirmation": "ISSUE"},
        follow_redirects=False,
    )
    assert reissued.status_code == 303

    response = client.post(
        f"/devices/{device_id}/packages",
        data={
            "csrf_token": csrf(client),
            "wireguard": "true",
            "amneziawg": "true",
            "vless": "true",
        },
    )
    assert response.status_code == 200
    marker = 'href="/provision/'
    token_start = response.text.index(marker) + len('href="')
    token_end = response.text.index('"', token_start)
    download_url = response.text[token_start:token_end]

    download = client.get(download_url)
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        assert set(archive.namelist()) == {
            "amneziawg.conf",
            "amneziawg-qr.png",
            "vless.txt",
            "vless-qr.png",
            "README.txt",
        }
        assert archive.read("amneziawg-qr.png").startswith(b"\x89PNG")
        assert archive.read("vless-qr.png").startswith(b"\x89PNG")
        amneziawg_config = archive.read("amneziawg.conf").decode()
        assert "Jc = 7" in amneziawg_config
        assert "Jmin = 64" in amneziawg_config
        assert "Jmax = 256" in amneziawg_config

    second_download = client.get(download_url)
    assert second_download.status_code == 410


def test_wireguard_connection_list_excludes_stale_handshake(
    authenticated_client: TestClient, monkeypatch
) -> None:
    client = authenticated_client
    created = client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "slug": "connection-test",
            "display_name": "Connection test",
            "comment": "",
        },
        follow_redirects=False,
    )
    user_id = created.headers["location"].rsplit("/", 1)[-1]
    client.post(
        f"/users/{user_id}/devices",
        data={
            "csrf_token": csrf(client),
            "slug": "laptop",
            "display_name": "Laptop",
            "wireguard": "true",
        },
    )
    stale = datetime.now(UTC) - timedelta(minutes=10)
    monkeypatch.setattr(
        client.app.state.admin_service,
        "device_runtime_status",
        lambda _device: DeviceRuntimeStatus(
            wireguard=ProtocolRuntimeStatus(
                active=True,
                enabled=True,
                last_seen_at=stale,
                received_bytes=1024,
                transmitted_bytes=2048,
            )
        ),
    )

    dashboard = client.get("/legacy")
    connections = client.get("/connections/wireguard")

    assert "Подключено пользователей: 0" in dashboard.text
    assert connections.status_code == 200
    assert "Сейчас никто не подключён" in connections.text


def test_csrf_is_required(authenticated_client: TestClient) -> None:
    response = authenticated_client.post(
        "/users",
        data={"slug": "ivan", "display_name": "Иван", "comment": ""},
    )
    assert response.status_code == 403


def test_manual_issuance_generates_ids_and_only_selected_protocols(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    created = client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "display_name": "Manual test",
            "amneziawg": "true",
            "wireguard": "true",  # Tampered old form must not issue WireGuard.
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    user_id = created.headers["location"].rsplit("/", 1)[-1]
    with client.app.state.session_factory() as db:
        user = db.get(UserModel, user_id)
        assert user is not None
        assert user.slug.startswith("manual-")
        assert len(user.devices) == 1
        device = user.devices[0]
        assert device.slug == "device-1"
        assert device.amneziawg is not None
        assert device.vless is None
        assert device.wireguard is None
    detail = client.get(created.headers["location"])
    assert detail.status_code == 200
    assert "WireGuard" not in detail.text
    assert 'name="slug"' not in detail.text


def test_duplicate_user_identifier_returns_a_friendly_notice(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    payload = {
        "csrf_token": csrf(client),
        "slug": "duplicate",
        "display_name": "Первый",
        "comment": "",
    }
    first = client.post("/users", data=payload, follow_redirects=False)
    assert first.status_code == 303

    payload["display_name"] = "Второй"
    second = client.post("/users", data=payload, follow_redirects=False)
    assert second.status_code == 303
    assert second.headers["location"] == "/legacy?notice=user-conflict"

    notice = client.get(second.headers["location"])
    assert notice.status_code == 200
    assert "Идентификатор уже занят" in notice.text


def test_revoked_protocol_is_excluded_from_dashboard_count_and_filter(
    authenticated_client: TestClient, totp_secret: str
) -> None:
    client = authenticated_client
    created = client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "slug": "revoked-filter",
            "display_name": "Фильтр",
            "comment": "",
        },
        follow_redirects=False,
    )
    user_id = created.headers["location"].rsplit("/", 1)[-1]
    client.post(
        f"/users/{user_id}/devices",
        data={
            "csrf_token": csrf(client),
            "slug": "phone",
            "display_name": "Phone",
            "wireguard": "false",
            "vless": "true",
        },
    )
    with client.app.state.session_factory() as db:
        device_id = db.scalar(select(DeviceModel.id))
        assert device_id
    client.post(
        f"/devices/{device_id}/protocol/vless/revoke",
        data={
            "csrf_token": csrf(client),
            "confirmation": "REVOKE",
            **critical(totp_secret),
        },
    )

    dashboard = client.get("/legacy")
    assert dashboard.status_code == 200
    assert "VLESS 0" in dashboard.text
    assert 'data-vless="false"' in dashboard.text
