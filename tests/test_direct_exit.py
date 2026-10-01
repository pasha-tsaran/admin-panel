import base64
import json
import runpy
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from kenai_vpn_admin.application.direct_locations import DirectAmneziaWgExit, DirectVlessExit

DEPLOY = Path(__file__).parents[1] / "deploy" / "direct-exit"


def test_direct_exit_preserves_per_device_uuid_but_changes_destination() -> None:
    source = (
        "vless://11111111-1111-4111-8111-111111111111@88.218.94.3:443"
        "?security=reality&encryption=none&flow=xtls-rprx-vision"
        "&sni=old.example&pbk=old&sid=aa#Kenai"
    )
    target = DirectVlessExit(
        "147.45.231.194", "www.example.org", "A" * 43, "aabbccdd"
    ).profile_from(source)
    uri = urlsplit(target)
    assert uri.hostname == "147.45.231.194"
    assert uri.username == "11111111-1111-4111-8111-111111111111"
    assert parse_qs(uri.query)["pbk"] == ["A" * 43]
    assert parse_qs(uri.query)["sid"] == ["aabbccdd"]
    assert parse_qs(uri.query)["sni"] == ["www.example.org"]
    assert parse_qs(uri.query)["flow"] == ["xtls-rprx-vision"]


def test_direct_exit_rejects_invalid_source_and_parameters() -> None:
    with pytest.raises(ValueError):
        DirectVlessExit("147.45.231.194", "bad/path", "A" * 43, "aabb")
    exit = DirectVlessExit("147.45.231.194", "www.example.org", "A" * 43, "aabb")
    with pytest.raises(ValueError):
        exit.profile_from("vless://not-a-uuid@example.org?security=reality")


def test_direct_awg_exit_preserves_client_identity_and_adds_31_fields() -> None:
    def key(value: int) -> str:
        return base64.b64encode(bytes([value]) * 32).decode("ascii")

    source = f"""[Interface]
PrivateKey = {key(1)}
Address = 10.67.67.9/32
DNS = 1.1.1.1
Jc = 4
Jmin = 64
Jmax = 128
S1 = 1
S2 = 2
S3 = 3
S4 = 4
H1 = 100
H2 = 200
H3 = 300
H4 = 400

[Peer]
PublicKey = {key(2)}
PresharedKey = {key(3)}
Endpoint = 88.218.94.3:585
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    result = DirectAmneziaWgExit("147.45.231.194", key(4), key(5)).profile_from(source)
    assert f"PrivateKey = {key(1)}" in result
    assert "Address = 10.67.67.9/32" in result
    assert f"PublicKey = {key(4)}" in result
    assert f"PresharedKey = {key(3)}" in result
    assert "Endpoint = 147.45.231.194:443" in result
    assert f"HeaderProtectionKey = {key(5)}" in result
    assert "RandomTrailers = on" in result
    assert "H1 = 100" not in result


def test_export_and_generate_config_use_only_active_clients(tmp_path: Path) -> None:
    exporter = runpy.run_path(str(DEPLOY / "export-active-vless.py"))
    syncer = runpy.run_path(str(DEPLOY / "sync-direct-exit.py"))
    source = tmp_path / "config.json"
    source.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "vless",
                        "port": 443,
                        "settings": {
                            "clients": [
                                {
                                    "id": "11111111-1111-4111-8111-111111111111",
                                    "email": "user-app-one",
                                }
                            ]
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    clients = exporter["active_clients"](source)
    config = syncer["build_config"](
        {
            "target": "www.example.org:443",
            "server_name": "www.example.org",
            "private_key": "B" * 43,
            "short_id": "aabbccdd",
        },
        clients,
    )
    assert config["inbounds"][0]["settings"]["clients"] == [
        {
            "id": "11111111-1111-4111-8111-111111111111",
            "email": "user-app-one",
            "flow": "xtls-rprx-vision",
        }
    ]
