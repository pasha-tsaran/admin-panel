from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SHORT_ID_PATTERN = re.compile(r"^[0-9a-f]{2,16}$")


class EnvironmentRenderError(RuntimeError):
    """A non-diagnostic deployment error that never contains key material."""


@dataclass(frozen=True)
class RealityPublicParameters:
    server_name: str
    public_key: str
    short_id: str


def _decode_urlsafe_key(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise EnvironmentRenderError("REALITY private key encoding is invalid") from exc
    if len(decoded) != 32:
        raise EnvironmentRenderError("REALITY private key length is invalid")
    return decoded


def derive_reality_public_key(private_value: str) -> str:
    private_key = X25519PrivateKey.from_private_bytes(_decode_urlsafe_key(private_value))
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(public_bytes).decode("ascii").rstrip("=")


def load_reality_public_parameters(config_path: Path, *, port: int) -> RealityPublicParameters:
    if not config_path.is_file() or config_path.is_symlink():
        raise EnvironmentRenderError("Xray configuration must be a regular non-symlink file")
    try:
        config: Any = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvironmentRenderError("Xray configuration could not be loaded") from exc
    if not isinstance(config, dict):
        raise EnvironmentRenderError("Xray configuration root is invalid")
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise EnvironmentRenderError("Xray inbounds are missing")
    matches = [
        inbound
        for inbound in inbounds
        if isinstance(inbound, dict)
        and inbound.get("protocol") == "vless"
        and inbound.get("port") == port
    ]
    if len(matches) != 1:
        raise EnvironmentRenderError("Exactly one VLESS inbound must match the configured port")
    stream_settings = matches[0].get("streamSettings")
    reality_settings = (
        stream_settings.get("realitySettings") if isinstance(stream_settings, dict) else None
    )
    if not isinstance(reality_settings, dict):
        raise EnvironmentRenderError("REALITY settings are missing")
    private_value = reality_settings.get("privateKey")
    server_names = reality_settings.get("serverNames")
    short_ids = reality_settings.get("shortIds")
    if not isinstance(private_value, str):
        raise EnvironmentRenderError("REALITY private key is missing")
    if not isinstance(server_names, list) or not all(
        isinstance(item, str) for item in server_names
    ):
        raise EnvironmentRenderError("REALITY server names are invalid")
    if not isinstance(short_ids, list) or not all(isinstance(item, str) for item in short_ids):
        raise EnvironmentRenderError("REALITY short IDs are invalid")
    server_name = next(
        (item for item in server_names if item and not any(char in item for char in "\r\n\x00")),
        None,
    )
    short_id = next((item for item in short_ids if SHORT_ID_PATTERN.fullmatch(item)), None)
    if server_name is None or short_id is None:
        raise EnvironmentRenderError("Usable REALITY public parameters are missing")
    return RealityPublicParameters(
        server_name=server_name,
        public_key=derive_reality_public_key(private_value),
        short_id=short_id,
    )


def validate_wireguard_public_key(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EnvironmentRenderError("WireGuard public key encoding is invalid") from exc
    if len(decoded) != 32:
        raise EnvironmentRenderError("WireGuard public key length is invalid")
    return value


def render_environment(
    *,
    allowed_uid: int,
    socket_gid: int,
    endpoint: str,
    wireguard_public_key: str | None,
    reality: RealityPublicParameters,
    wireguard_enabled: bool = True,
    amneziawg_enabled: bool = False,
) -> str:
    if allowed_uid < 1 or socket_gid < 1:
        raise EnvironmentRenderError("Numeric service identities are invalid")
    if not endpoint or any(char in endpoint for char in "\r\n\x00"):
        raise EnvironmentRenderError("Public endpoint is invalid")
    values = {
        "KENAI_HELPER_ALLOWED_UID": str(allowed_uid),
        "KENAI_HELPER_SOCKET_GID": str(socket_gid),
        "KENAI_HELPER_SOCKET_PATH": "/run/kenai-vpn/helper.sock",
        "KENAI_HELPER_STATE_DIRECTORY": "/var/lib/kenai-vpn-helper",
        "KENAI_HELPER_WIREGUARD_ENABLED": str(wireguard_enabled).lower(),
        "KENAI_HELPER_AMNEZIAWG_ENABLED": str(amneziawg_enabled).lower(),
        "KENAI_HELPER_WIREGUARD_CONFIG": "/etc/wireguard/wg0.conf",
        "KENAI_HELPER_WIREGUARD_INTERFACE": "wg0",
        "KENAI_HELPER_WIREGUARD_NETWORK": "10.66.66.0/24",
        "KENAI_HELPER_WIREGUARD_SERVER_ADDRESS": "10.66.66.1",
        "KENAI_HELPER_WIREGUARD_LISTEN_PORT": "51820",
        "KENAI_HELPER_PUBLIC_ENDPOINT": endpoint,
        "KENAI_HELPER_WIREGUARD_DNS": '["1.1.1.1","1.0.0.1"]',
        "KENAI_HELPER_XRAY_CONFIG": "/usr/local/etc/xray/config.json",
        "KENAI_HELPER_XRAY_PORT": "443",
        "KENAI_HELPER_XRAY_SERVER_NAME": reality.server_name,
        "KENAI_HELPER_XRAY_REALITY_PUBLIC_KEY": reality.public_key,
        "KENAI_HELPER_XRAY_SHORT_ID": reality.short_id,
    }
    if wireguard_enabled:
        if wireguard_public_key is None:
            raise EnvironmentRenderError("WireGuard public key is required when enabled")
        values["KENAI_HELPER_WIREGUARD_SERVER_PUBLIC_KEY"] = validate_wireguard_public_key(
            wireguard_public_key
        )
    return "\n".join(f"{name}={shlex.quote(value)}" for name, value in values.items()) + "\n"


def write_new_environment(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render a root-only Kenai helper environment")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allowed-uid", type=int, required=True)
    parser.add_argument("--socket-gid", type=int, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--wireguard-public-key")
    parser.add_argument("--enable-wireguard", action="store_true")
    parser.add_argument("--enable-amneziawg", action="store_true")
    parser.add_argument("--xray-config", type=Path, required=True)
    parser.add_argument("--xray-port", type=int, default=443)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    reality = load_reality_public_parameters(args.xray_config, port=args.xray_port)
    content = render_environment(
        allowed_uid=args.allowed_uid,
        socket_gid=args.socket_gid,
        endpoint=args.endpoint,
        wireguard_public_key=args.wireguard_public_key,
        reality=reality,
        wireguard_enabled=args.enable_wireguard,
        amneziawg_enabled=args.enable_amneziawg,
    )
    write_new_environment(args.output, content)
    print("helper_environment_created=yes")
    print("private_values_printed=0")


if __name__ == "__main__":
    main()
