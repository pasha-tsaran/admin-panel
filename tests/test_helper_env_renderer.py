from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kenai_vpn_admin.helper.env_renderer import (
    EnvironmentRenderError,
    RealityPublicParameters,
    derive_reality_public_key,
    load_reality_public_parameters,
    render_environment,
    write_new_environment,
)


def encoded_private_key(private_key: X25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_renderer_derives_public_values_without_writing_private_key(tmp_path: Path) -> None:
    private_key = X25519PrivateKey.generate()
    private_value = encoded_private_key(private_key)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "port": 443,
                        "protocol": "vless",
                        "streamSettings": {
                            "realitySettings": {
                                "privateKey": private_value,
                                "serverNames": ["mirrors.example.test"],
                                "shortIds": ["", "01234567"],
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    reality = load_reality_public_parameters(config, port=443)
    environment = render_environment(
        allowed_uid=991,
        socket_gid=992,
        endpoint="88.218.94.3",
        wireguard_public_key=base64.b64encode(bytes(range(32))).decode("ascii"),
        reality=reality,
    )

    assert reality.public_key == derive_reality_public_key(private_value)
    assert private_value not in environment
    assert "KENAI_HELPER_ALLOWED_UID=991" in environment
    assert "KENAI_HELPER_XRAY_SHORT_ID=01234567" in environment


def test_renderer_requires_exactly_one_matching_vless_inbound(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"inbounds": []}), encoding="utf-8")

    with pytest.raises(EnvironmentRenderError, match="Exactly one"):
        load_reality_public_parameters(config, port=443)


def test_environment_file_is_create_only(tmp_path: Path) -> None:
    environment = tmp_path / "helper.env"
    write_new_environment(environment, "VALUE=first\n")

    with pytest.raises(FileExistsError):
        write_new_environment(environment, "VALUE=second\n")

    assert environment.read_text(encoding="utf-8") == "VALUE=first\n"


def test_vless_only_environment_does_not_require_wireguard_key() -> None:
    environment = render_environment(
        allowed_uid=991,
        socket_gid=992,
        endpoint="ingress.example.test",
        wireguard_public_key=None,
        reality=RealityPublicParameters(
            server_name="camouflage.example.test",
            public_key="a" * 43,
            short_id="0123456789abcdef",
        ),
        wireguard_enabled=False,
    )

    assert "KENAI_HELPER_WIREGUARD_ENABLED=false" in environment
    assert "KENAI_HELPER_AMNEZIAWG_ENABLED=false" in environment
    assert "KENAI_HELPER_WIREGUARD_SERVER_PUBLIC_KEY" not in environment
