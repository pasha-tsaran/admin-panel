import re
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from kenai_vpn_admin.application.ports import RouteRuntimeStatus
from kenai_vpn_admin.domain.enums import NodeRole
from kenai_vpn_admin.infrastructure.models import (
    RouteCredentialModel,
    UserModel,
    VpnLocationModel,
    utc_now,
)


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def test_topology_lists_servers_from_the_active_direct_configuration(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    client.app.state.settings.primary_address = "88.218.94.3"
    client.app.state.settings.netherlands_address = "147.45.231.194"
    client.app.state.settings.netherlands_server_name = "www.example.org"
    client.app.state.settings.netherlands_public_key = "A" * 43
    client.app.state.settings.netherlands_short_id = "aabbccdd"

    response = client.get("/topology")

    assert response.status_code == 200
    assert "Действующие серверы" in response.text
    assert "Армения" in response.text
    assert "88.218.94.3" in response.text
    assert "Нидерланды" in response.text
    assert "147.45.231.194" in response.text


def create_subscription(client: TestClient) -> str:
    response = client.post(
        "/subscriptions",
        data={
            "csrf_token": csrf(client),
            "email": "cascade@example.com",
            "telegram_username": "",
            "phone_number": "",
            "comment": "Cascade API test",
        },
    )
    assert response.status_code == 201
    match = re.search(r'value="(\d{12})" readonly', response.text)
    assert match
    return match.group(1)


def create_online_location(client: TestClient) -> str:
    service = client.app.state.cascade_service
    with client.app.state.session_factory() as db:
        ingress = service.create_node(
            db,
            slug="ru-entry-1",
            display_name="Russia entry 1",
            role=NodeRole.INGRESS,
            country_code="RU",
            city="Moscow",
            public_endpoint="ru-entry.example",
            agent_endpoint="https://127.0.0.1:9443",
            certificate_sha256="a" * 64,
        )
        exit_node = service.create_node(
            db,
            slug="am-exit-1",
            display_name="Armenia exit 1",
            role=NodeRole.EXIT,
            country_code="AM",
            city="Yerevan",
            public_endpoint="am-exit.example",
            agent_endpoint="https://am-agent.example:9443",
            certificate_sha256="b" * 64,
        )
        location = service.create_location(
            db,
            slug="armenia",
            country_code="AM",
            country_name="Armenia",
            city="Yerevan",
            display_name="Armenia",
            ingress_node_id=ingress.id,
            exit_node_id=exit_node.id,
            exit_port=443,
            link_uuid="11111111-1111-4111-8111-111111111111",
            server_name="cdn.example.com",
            reality_public_key="example-reality-public-key",
            short_id="01234567",
            sort_order=10,
            is_recommended=True,
        )
        service.refresh_location_health(db, location.id)
        db.commit()
        return location.id


def test_v2_activation_location_profile_and_fail_closed(
    authenticated_client: TestClient, monkeypatch
) -> None:
    client = authenticated_client
    activation_key = create_subscription(client)
    location_id = create_online_location(client)

    assert client.get("/api/v2/subscription").status_code == 401
    activation = client.post("/api/v2/activate", json={"activation_key": activation_key})
    assert activation.status_code == 200
    assert activation.headers["cache-control"] == "no-store"
    access_token = activation.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    second_activation = client.post("/api/v2/activate", json={"activation_key": activation_key})
    assert second_activation.status_code == 401
    subscription = client.get("/api/v2/subscription", headers=headers)
    assert subscription.status_code == 200
    assert subscription.json()["status"] == "active"

    locations = client.get("/api/v2/locations", headers=headers)
    assert locations.status_code == 200
    location = locations.json()["locations"][0]
    assert location["id"] == location_id
    assert location["available"] is True
    assert location["latency_ms"] >= 0

    profile_response = client.get(f"/api/v2/locations/{location_id}/profile", headers=headers)
    assert profile_response.status_code == 200
    client_uri = profile_response.json()["profile"]["client_uri"]
    assert client_uri.startswith("vless://")
    assert "@88.218.94.3:443" in client_uri
    assert "am-exit.example" not in client_uri
    repeated = client.get(f"/api/v2/locations/{location_id}/profile", headers=headers)
    assert repeated.json()["profile"]["client_uri"] == client_uri

    with client.app.state.session_factory() as db:
        credential = db.scalar(select(RouteCredentialModel))
        assert credential is not None
        assert client_uri.encode() not in credential.encrypted_client_uri
        stored_location = db.get(VpnLocationModel, location_id)
        assert stored_location is not None
        assert stored_location.encrypted_exit_link is not None
        assert b"example-reality-public-key" not in stored_location.encrypted_exit_link

    monkeypatch.setattr(
        client.app.state.vpn_manager,
        "route_health",
        lambda outbound_tag: RouteRuntimeStatus(outbound_tag, False, error_code="DOWN"),
    )
    with client.app.state.session_factory() as db:
        client.app.state.cascade_service.refresh_location_health(db, location_id)
        db.commit()

    unavailable = client.get(f"/api/v2/locations/{location_id}/profile", headers=headers)
    assert unavailable.status_code == 409
    assert (
        client.get("/api/v2/locations", headers=headers).json()["locations"][0]["available"]
        is False
    )


def test_expired_subscription_rejects_token_and_disables_route_profile(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    activation_key = create_subscription(client)
    location_id = create_online_location(client)
    activation = client.post("/api/v2/activate", json={"activation_key": activation_key})
    access_token = activation.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    profile = client.get(f"/api/v2/locations/{location_id}/profile", headers=headers)
    assert profile.status_code == 200

    with client.app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.email == "cascade@example.com"))
        assert user is not None
        user.subscription_expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
        credentials = client.app.state.cascade_service.expired_route_credentials(db)
        assert len(credentials) == 1
        client.app.state.cascade_service.disable_route_credential(credentials[0])
        db.commit()
        assert credentials[0].status == "disabled"

    assert client.get("/api/v2/subscription", headers=headers).status_code == 401


def test_stale_probe_is_not_advertised_as_available(authenticated_client: TestClient) -> None:
    client = authenticated_client
    activation_key = create_subscription(client)
    location_id = create_online_location(client)
    token = client.post("/api/v2/activate", json={"activation_key": activation_key}).json()[
        "access_token"
    ]
    headers = {"Authorization": f"Bearer {token}"}

    with client.app.state.session_factory() as db:
        location = client.app.state.cascade_service._location(db, location_id)
        location.last_probe_at = utc_now() - timedelta(minutes=3)
        db.commit()

    assert (
        client.get("/api/v2/locations", headers=headers).json()["locations"][0]["available"]
        is False
    )
    assert (
        client.get(f"/api/v2/locations/{location_id}/profile", headers=headers).status_code == 409
    )
