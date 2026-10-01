#!/usr/bin/env python3
"""Forced SSH command on Armenia: export only currently enabled Xray users."""

import base64
import ipaddress
import json
import sys
from pathlib import Path
from uuid import UUID


def active_clients(path: Path) -> list[dict[str, str]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    inbounds = [
        inbound
        for inbound in config.get("inbounds", [])
        if inbound.get("protocol") == "vless" and inbound.get("port") == 443
    ]
    if len(inbounds) != 1:
        raise ValueError("Expected exactly one direct VLESS inbound")
    clients = inbounds[0]["settings"]["clients"]
    if not isinstance(clients, list):
        raise ValueError("Invalid VLESS client list")
    result = []
    for client in clients:
        uid = str(UUID(client["id"]))
        email = client["email"]
        if not isinstance(email, str) or not email or len(email) > 253:
            raise ValueError("Invalid VLESS client label")
        result.append({"id": uid, "email": email})
    return sorted(result, key=lambda client: client["email"])


def _key(value: str) -> str:
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Invalid AmneziaWG key")
    return value


def active_awg_peers(path: Path) -> list[dict[str, str | None]]:
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[Interface]":
            current = None
            continue
        if line == "[Peer]":
            current = {}
            peers.append(current)
            continue
        if current is None:
            continue
        if "=" not in line:
            raise ValueError("Invalid AmneziaWG peer")
        name, value = (part.strip() for part in line.split("=", 1))
        if name in current:
            raise ValueError("Duplicate AmneziaWG peer field")
        current[name] = value
    result: list[dict[str, str | None]] = []
    seen: set[str] = set()
    pool = ipaddress.ip_network("10.67.67.0/24")
    for peer in peers:
        public_key = _key(peer.get("PublicKey", ""))
        preshared_value = peer.get("PresharedKey", peer.get("PreSharedKey"))
        preshared_key = _key(preshared_value) if preshared_value is not None else None
        allowed = ipaddress.ip_network(peer.get("AllowedIPs", ""), strict=False)
        if (
            not isinstance(allowed, ipaddress.IPv4Network)
            or allowed.prefixlen != 32
            or not allowed.subnet_of(pool)
            or public_key in seen
        ):
            raise ValueError("Invalid AmneziaWG peer address")
        seen.add(public_key)
        result.append(
            {
                "public_key": public_key,
                "preshared_key": preshared_key,
                "allowed_ips": str(allowed),
            }
        )
    return sorted(result, key=lambda peer: peer["allowed_ips"])


if __name__ == "__main__":
    try:
        print(
            json.dumps(
                {
                    "version": 2,
                    "clients": active_clients(Path("/usr/local/etc/xray/config.json")),
                    "awg_peers": active_awg_peers(Path("/etc/amneziawg/awg0.conf")),
                }
            )
        )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"Direct-exit manifest unavailable: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
