from __future__ import annotations

import copy
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from kenai_vpn_admin.helper.state_store import StateConflictError

MANAGED_PREFIX = "kenai-"
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True)
class RealityPeer:
    address: str
    port: int
    client_uuid: str
    server_name: str
    public_key: str
    short_id: str
    fingerprint: str = "chrome"


@dataclass(frozen=True)
class CascadeExit:
    location_slug: str
    peer: RealityPeer

    @property
    def outbound_tag(self) -> str:
        return f"kenai-exit-{self.location_slug}"

    @property
    def balancer_tag(self) -> str:
        return f"kenai-balancer-{self.location_slug}"


@dataclass(frozen=True)
class IngressServer:
    listen_port: int
    reality_target: str
    reality_private_key: str
    server_names: tuple[str, ...]
    short_ids: tuple[str, ...]
    inbound_tag: str = "kenai-client-in"


@dataclass(frozen=True)
class ExitServer:
    location_slug: str
    listen_port: int
    ingress_uuid: str
    ingress_name: str
    reality_private_key: str
    reality_target: str
    server_names: tuple[str, ...]
    short_ids: tuple[str, ...]


def render_ingress_base_config(server: IngressServer) -> str:
    """Create a complete fail-closed Russian ingress configuration.

    The generated inbound intentionally starts without subscribers. Route
    profiles are added later by the privileged helper and every unmatched
    connection is sent to the first, blackhole, outbound.
    """

    _validate_port(server.listen_port)
    _validate_tag(server.inbound_tag)
    _validate_reality_server(
        target=server.reality_target,
        private_key=server.reality_private_key,
        server_names=server.server_names,
        short_ids=server.short_ids,
    )
    config: dict[str, Any] = {
        "log": {"loglevel": "warning", "access": "none", "dnsLog": False},
        "api": {
            "tag": "kenai-api",
            "listen": "127.0.0.1:10085",
            "services": ["RoutingService", "StatsService"],
        },
        "inbounds": [
            {
                "tag": server.inbound_tag,
                "listen": "0.0.0.0",
                "port": server.listen_port,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": server.reality_target,
                        "serverNames": list(server.server_names),
                        "privateKey": server.reality_private_key,
                        "shortIds": list(server.short_ids),
                    },
                },
            }
        ],
        "outbounds": [{"tag": "kenai-blocked", "protocol": "blackhole", "settings": {}}],
        "routing": {"domainStrategy": "AsIs", "rules": [], "balancers": []},
        "observatory": _observatory(),
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "statsUserOnline": True,
                }
            }
        },
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def render_ingress_config(base: dict[str, Any], exits: list[CascadeExit]) -> str:
    """Merge managed cascade outbounds into an existing ingress configuration.

    Unmanaged inbounds, outbounds and routing rules are preserved. Managed objects
    are fully regenerated so a removed country cannot remain reachable by accident.
    """

    config = copy.deepcopy(base)
    _validate_exits(exits)
    outbounds = _object_list(config, "outbounds")
    unmanaged_outbounds = [
        item for item in outbounds if not str(item.get("tag", "")).startswith(MANAGED_PREFIX)
    ]
    config["outbounds"] = [
        {"tag": "kenai-blocked", "protocol": "blackhole", "settings": {}},
        *[_outbound(item) for item in exits],
        *unmanaged_outbounds,
    ]

    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise StateConflictError("Xray routing configuration must be an object")
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise StateConflictError("Xray routing rules must be a list of objects")
    routing["rules"] = [
        rule
        for rule in rules
        if not str(rule.get("ruleTag", "")).startswith("kenai-location-")
        and not str(rule.get("balancerTag", "")).startswith("kenai-balancer-")
    ]
    routing["balancers"] = [_balancer(item) for item in exits]
    config["observatory"] = _observatory()
    api = config.setdefault("api", {})
    if not isinstance(api, dict):
        raise StateConflictError("Xray API configuration must be an object")
    api.update(
        {
            "tag": "kenai-api",
            "listen": "127.0.0.1:10085",
            "services": ["RoutingService", "StatsService"],
        }
    )
    config.setdefault("stats", {})
    policy = config.setdefault("policy", {})
    if not isinstance(policy, dict):
        raise StateConflictError("Xray policy configuration must be an object")
    levels = policy.setdefault("levels", {})
    if not isinstance(levels, dict):
        raise StateConflictError("Xray policy levels must be an object")
    level_zero = levels.setdefault("0", {})
    if not isinstance(level_zero, dict):
        raise StateConflictError("Xray policy level zero must be an object")
    level_zero.update({"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True})
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def render_exit_config(server: ExitServer) -> str:
    _validate_slug(server.location_slug)
    _validate_port(server.listen_port)
    _validate_uuid(server.ingress_uuid)
    _validate_reality_server(
        target=server.reality_target,
        private_key=server.reality_private_key,
        server_names=server.server_names,
        short_ids=server.short_ids,
    )
    config: dict[str, Any] = {
        "log": {"loglevel": "warning", "access": "none", "dnsLog": False},
        "inbounds": [
            {
                "tag": f"kenai-link-{server.location_slug}",
                "listen": "0.0.0.0",
                "port": server.listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": server.ingress_uuid,
                            "email": server.ingress_name,
                            "flow": "xtls-rprx-vision",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": server.reality_target,
                        "serverNames": list(server.server_names),
                        "privateKey": server.reality_private_key,
                        "shortIds": list(server.short_ids),
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "kenai-blocked", "protocol": "blackhole", "settings": {}},
            {"tag": "kenai-internet", "protocol": "freedom", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "kenai-blocked",
                    "ruleTag": "kenai-block-private",
                },
                {
                    "type": "field",
                    "inboundTag": [f"kenai-link-{server.location_slug}"],
                    "outboundTag": "kenai-internet",
                    "ruleTag": "kenai-exit-internet",
                },
            ],
        },
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def _outbound(item: CascadeExit) -> dict[str, Any]:
    peer = item.peer
    _validate_port(peer.port)
    return {
        "tag": item.outbound_tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": peer.address,
                    "port": peer.port,
                    "users": [
                        {
                            "id": peer.client_uuid,
                            "encryption": "none",
                            "flow": "xtls-rprx-vision",
                        }
                    ],
                }
            ]
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "fingerprint": peer.fingerprint,
                "serverName": peer.server_name,
                "publicKey": peer.public_key,
                "shortId": peer.short_id,
                "spiderX": "/",
            },
        },
    }


def _balancer(item: CascadeExit) -> dict[str, Any]:
    return {
        "tag": item.balancer_tag,
        "selector": [item.outbound_tag],
        "fallbackTag": "kenai-blocked",
        "strategy": {"type": "roundRobin", "settings": {}},
    }


def _observatory() -> dict[str, object]:
    return {
        "subjectSelector": ["kenai-exit-"],
        "probeUrl": "https://connectivitycheck.gstatic.com/generate_204",
        "probeInterval": "30s",
        "enableConcurrency": True,
    }


def _object_list(config: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = config.setdefault(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise StateConflictError(f"Xray {key} must be a list of objects")
    return value


def _validate_exits(exits: list[CascadeExit]) -> None:
    slugs = [item.location_slug for item in exits]
    for item in exits:
        _validate_slug(item.location_slug)
        _validate_server_name(item.peer.address)
        _validate_port(item.peer.port)
        _validate_uuid(item.peer.client_uuid)
        _validate_server_name(item.peer.server_name)
        if (
            not item.peer.public_key
            or len(item.peer.public_key) > 128
            or any(char.isspace() for char in item.peer.public_key)
        ):
            raise ValueError("REALITY public key is invalid")
        _validate_short_id(item.peer.short_id)
        if item.peer.fingerprint != "chrome":
            raise ValueError("Unsupported REALITY fingerprint")
    if len(slugs) != len(set(slugs)):
        raise ValueError("Cascade location identifiers must be unique")


def _validate_slug(value: str) -> None:
    if len(value) > 64 or not SLUG_PATTERN.fullmatch(value):
        raise ValueError("Cascade location identifier is invalid")


def _validate_port(value: int) -> None:
    if not 1 <= value <= 65535:
        raise ValueError("Cascade port is invalid")


def _validate_uuid(value: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Cascade UUID is invalid") from exc


def _validate_tag(value: str) -> None:
    if not value or len(value) > 128 or any(char.isspace() for char in value):
        raise ValueError("Xray inbound tag is invalid")


def _validate_reality_server(
    *,
    target: str,
    private_key: str,
    server_names: tuple[str, ...],
    short_ids: tuple[str, ...],
) -> None:
    _validate_target(target)
    if not private_key or len(private_key) > 128 or any(char.isspace() for char in private_key):
        raise ValueError("REALITY private key is invalid")
    if not server_names or len(server_names) > 16:
        raise ValueError("REALITY server names are required")
    for name in server_names:
        _validate_server_name(name)
    if not short_ids or len(short_ids) > 16:
        raise ValueError("REALITY short IDs are required")
    for short_id in short_ids:
        _validate_short_id(short_id)


def _validate_short_id(value: str) -> None:
    normalized = value.lower()
    if not 2 <= len(normalized) <= 16 or len(normalized) % 2:
        raise ValueError("REALITY short ID is invalid")
    if any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("REALITY short ID is invalid")


def _validate_target(value: str) -> None:
    if not value or len(value) > 300 or any(char.isspace() for char in value):
        raise ValueError("REALITY target is invalid")
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdecimal():
        raise ValueError("REALITY target must use host:port")
    _validate_port(int(port_text))
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise ValueError("REALITY target is invalid") from exc
        return
    _validate_server_name(host)


def _validate_server_name(value: str) -> None:
    if not value or len(value) > 253 or any(char.isspace() for char in value):
        raise ValueError("REALITY server name is invalid")
    if any(char in value for char in "/?#:@[]"):
        raise ValueError("REALITY server name is invalid")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[A-Za-z0-9-]+", label)
        for label in labels
    ):
        raise ValueError("REALITY server name is invalid")
