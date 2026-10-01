import json
from pathlib import Path

from kenai_vpn_admin.helper.cascade_config import (
    CascadeExit,
    RealityPeer,
    render_ingress_config,
)
from kenai_vpn_admin.helper.command_runner import CommandResult
from kenai_vpn_admin.helper.xray_adapter import XrayAdapter, XraySettings


class Executor:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.balancer = "{}"

    def run(self, arguments: tuple[str, ...], *, input_text: str | None = None) -> CommandResult:
        del input_text
        self.commands.append(arguments)
        if arguments[1:3] == ("api", "bi"):
            return CommandResult(self.balancer)
        return CommandResult("")


def test_route_profile_mutates_only_managed_client_and_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    base = {
        "inbounds": [
            {
                "tag": "vless-reality",
                "protocol": "vless",
                "settings": {"clients": []},
            }
        ],
        "outbounds": [],
        "routing": {"rules": []},
    }
    exit_route = CascadeExit(
        "armenia",
        RealityPeer(
            "am.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            "cdn.example.com",
            "public-key-placeholder",
            "01234567",
        ),
    )
    config_path.write_text(render_ingress_config(base, [exit_route]), encoding="utf-8")
    executor = Executor()
    adapter = XrayAdapter(
        XraySettings(
            config_path=config_path,
            state_path=tmp_path / "state.json",
            inbound_tag="vless-reality",
            endpoint="ru-entry.example",
            port=443,
            server_name="cdn.example.ru",
            reality_public_key="ingress-public-key",
            short_id="89abcdef",
            xray_binary=Path("C:/fake/xray.exe"),
            systemctl_binary=Path("C:/fake/systemctl.exe"),
        ),
        executor,
    )

    profile = adapter.issue_route_profile(
        "22222222-2222-4222-8222-222222222222",
        "subscriber-primary",
        "armenia",
        "kenai-exit-armenia",
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert profile.client_uri.startswith("vless://")
    assert config["routing"]["rules"][0]["balancerTag"] == "kenai-balancer-armenia"
    assert config["inbounds"][0]["settings"]["clients"][0]["email"].startswith("route:armenia:")

    adapter.set_route_profile_enabled("22222222-2222-4222-8222-222222222222", False)
    disabled = json.loads(config_path.read_text(encoding="utf-8"))
    assert disabled["routing"]["rules"] == []
    assert disabled["inbounds"][0]["settings"]["clients"] == []

    adapter.set_route_profile_enabled("22222222-2222-4222-8222-222222222222", True)
    adapter.revoke_route_profile("22222222-2222-4222-8222-222222222222")
    revoked = json.loads(config_path.read_text(encoding="utf-8"))
    assert revoked["routing"]["rules"] == []
    assert revoked["inbounds"][0]["settings"]["clients"] == []


def test_observatory_health_parser_accepts_matching_outbound() -> None:
    payload = {
        "balancer": {
            "outboundStatus": [{"outboundTag": "kenai-exit-armenia", "alive": True, "delay": 47}]
        }
    }
    assert XrayAdapter._parse_balancer_health(payload, "kenai-exit-armenia") == (True, 47)
    assert XrayAdapter._parse_balancer_health(payload, "kenai-exit-kazakhstan") == (
        False,
        None,
    )


def test_route_profile_supports_current_users_field(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality",
                        "protocol": "vless",
                        "settings": {"users": []},
                    }
                ],
                "outbounds": [{"tag": "kenai-exit-armenia", "protocol": "vless"}],
                "routing": {"rules": []},
            }
        ),
        encoding="utf-8",
    )
    adapter = XrayAdapter(
        XraySettings(
            config_path=config_path,
            state_path=tmp_path / "state.json",
            inbound_tag="vless-reality",
            endpoint="ru-entry.example",
            port=443,
            server_name="cdn.example.ru",
            reality_public_key="ingress-public-key",
            short_id="89abcdef",
            xray_binary=Path("C:/fake/xray.exe"),
            systemctl_binary=Path("C:/fake/systemctl.exe"),
        ),
        Executor(),
    )

    adapter.issue_route_profile(
        "22222222-2222-4222-8222-222222222222",
        "subscriber-primary",
        "armenia",
        "kenai-exit-armenia",
    )

    updated = json.loads(config_path.read_text(encoding="utf-8"))
    assert updated["inbounds"][0]["settings"]["users"][0]["email"].startswith("route:armenia:")
