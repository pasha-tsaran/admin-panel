import json

from kenai_vpn_admin.helper.cascade_config import (
    CascadeExit,
    ExitServer,
    IngressServer,
    RealityPeer,
    render_exit_config,
    render_ingress_base_config,
    render_ingress_config,
)


def exit_peer(slug: str = "armenia") -> CascadeExit:
    return CascadeExit(
        location_slug=slug,
        peer=RealityPeer(
            address="am-exit.example",
            port=443,
            client_uuid="11111111-1111-4111-8111-111111111111",
            server_name="cdn.example.com",
            public_key="reality-public-key",
            short_id="01234567",
        ),
    )


def test_ingress_config_preserves_unmanaged_objects_and_fails_closed() -> None:
    base = {
        "inbounds": [
            {
                "tag": "vless-reality",
                "protocol": "vless",
                "settings": {"clients": []},
            }
        ],
        "outbounds": [{"tag": "existing", "protocol": "freedom"}],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "domain": ["example.com"],
                    "outboundTag": "existing",
                }
            ]
        },
    }

    config = json.loads(render_ingress_config(base, [exit_peer()]))

    assert config["inbounds"] == base["inbounds"]
    assert config["outbounds"][0]["tag"] == "kenai-blocked"
    assert any(item.get("tag") == "existing" for item in config["outbounds"])
    assert config["routing"]["rules"] == base["routing"]["rules"]
    balancer = config["routing"]["balancers"][0]
    assert balancer["selector"] == ["kenai-exit-armenia"]
    assert balancer["fallbackTag"] == "kenai-blocked"
    assert config["observatory"]["subjectSelector"] == ["kenai-exit-"]
    assert config["api"]["listen"] == "127.0.0.1:10085"
    assert "RoutingService" in config["api"]["services"]


def test_ingress_base_is_complete_and_fails_closed_without_routes() -> None:
    config = json.loads(
        render_ingress_base_config(
            IngressServer(
                listen_port=443,
                reality_target="www.example.ru:443",
                reality_private_key="private-key-placeholder",
                server_names=("www.example.ru",),
                short_ids=("89abcdef",),
            )
        )
    )

    inbound = config["inbounds"][0]
    assert inbound["tag"] == "kenai-client-in"
    assert inbound["settings"]["clients"] == []
    assert inbound["streamSettings"]["realitySettings"]["target"] == "www.example.ru:443"
    assert config["outbounds"][0]["protocol"] == "blackhole"
    assert config["routing"]["rules"] == []
    assert config["api"]["listen"] == "127.0.0.1:10085"


def test_exit_config_has_no_access_log_and_blocks_private_destinations() -> None:
    config = json.loads(
        render_exit_config(
            ExitServer(
                location_slug="armenia",
                listen_port=443,
                ingress_uuid="11111111-1111-4111-8111-111111111111",
                ingress_name="ru-entry-1",
                reality_private_key="reality-private-key",
                reality_target="cdn.example.com:443",
                server_names=("cdn.example.com",),
                short_ids=("01234567",),
            )
        )
    )

    assert config["log"]["access"] == "none"
    assert config["inbounds"][0]["streamSettings"]["realitySettings"]["target"] == (
        "cdn.example.com:443"
    )
    assert config["outbounds"][0]["protocol"] == "blackhole"
    assert config["routing"]["rules"][0]["ip"] == ["geoip:private"]
    assert config["routing"]["rules"][0]["outboundTag"] == "kenai-blocked"
    assert config["routing"]["rules"][1]["outboundTag"] == "kenai-internet"
