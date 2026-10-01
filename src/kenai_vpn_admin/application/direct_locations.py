"""Build a second direct-exit profile from an existing per-device VLESS UUID.

The Netherlands node mirrors the active UUID allowlist; it has independent
REALITY server parameters. Never derive or expose this URI for an inactive key.
"""

import base64
from dataclasses import dataclass
from ipaddress import IPv4Address
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID


@dataclass(frozen=True)
class DirectVlessExit:
    address: str
    server_name: str
    public_key: str
    short_id: str
    port: int = 443

    def __post_init__(self) -> None:
        if not IPv4Address(self.address).is_global:
            raise ValueError("Direct-exit address must be public")
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid VLESS port")
        if not self.server_name or any(c in self.server_name for c in "/?#@"):
            raise ValueError("Invalid REALITY server name")
        if len(self.public_key) != 43 or any(
            c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for c in self.public_key
        ):
            raise ValueError("Invalid REALITY public key")
        if (
            not 2 <= len(self.short_id) <= 16
            or len(self.short_id) % 2
            or any(c not in "0123456789abcdef" for c in self.short_id)
        ):
            raise ValueError("Invalid REALITY short ID")

    def profile_from(self, armenia_uri: str) -> str:
        source = urlsplit(armenia_uri)
        if source.scheme != "vless" or source.password is not None:
            raise ValueError("Invalid source VLESS URI")
        UUID(source.username or "")
        query = dict(parse_qsl(source.query, keep_blank_values=True))
        if query.get("security") != "reality":
            raise ValueError("Source VLESS URI is not REALITY")
        query.update(sni=self.server_name, pbk=self.public_key, sid=self.short_id)
        return urlunsplit(
            (
                "vless",
                f"{source.username}@{self.address}:{self.port}",
                "",
                urlencode(query),
                "Kenai Netherlands",
            )
        )


def _awg_key(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid AmneziaWG key") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Invalid AmneziaWG key")
    return value


@dataclass(frozen=True)
class DirectAmneziaWgExit:
    address: str
    server_public_key: str
    header_protection_key: str
    port: int = 443

    def __post_init__(self) -> None:
        if not IPv4Address(self.address).is_global:
            raise ValueError("Direct-exit address must be public")
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid AmneziaWG port")
        _awg_key(self.server_public_key)
        _awg_key(self.header_protection_key)

    def profile_from(self, armenia_config: str) -> str:
        if len(armenia_config) > 64 * 1024 or "\x00" in armenia_config:
            raise ValueError("Invalid source AmneziaWG profile")
        sections: dict[str, dict[str, str]] = {"Interface": {}, "Peer": {}}
        section: str | None = None
        for raw in armenia_config.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line in {"[Interface]", "[Peer]"}:
                section = line[1:-1]
                continue
            if section is None or "=" not in line:
                raise ValueError("Invalid source AmneziaWG profile")
            name, value = (part.strip() for part in line.split("=", 1))
            if not name or not value or name in sections[section]:
                raise ValueError("Invalid source AmneziaWG profile")
            sections[section][name] = value
        interface = sections["Interface"]
        peer = sections["Peer"]
        private_key = _awg_key(interface.get("PrivateKey", ""))
        _awg_key(peer.get("PublicKey", ""))
        preshared_key = peer.get("PresharedKey") or peer.get("PreSharedKey")
        if preshared_key is not None:
            _awg_key(preshared_key)
        address = interface.get("Address", "")
        allowed_ips = peer.get("AllowedIPs", "")
        if not address or not allowed_ips or any(c in address + allowed_ips for c in "\r\n\x00"):
            raise ValueError("Invalid source AmneziaWG profile")
        dns = interface.get("DNS", "1.1.1.1, 1.0.0.1")
        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"DNS = {dns}",
            "MTU = 1376",
            "Jc = 6",
            "Jmin = 10",
            "Jmax = 50",
            "S1 = 12",
            "S2 = 12",
            "S3 = 12",
            "S4 = 12",
            "H1 = 1",
            "H2 = 2",
            "H3 = 3",
            "H4 = 4",
            f"HeaderProtectionKey = {self.header_protection_key}",
            "ContentPaddingAddition = 10-100",
            "RekeyAfterTime = 100-120",
            "RekeyTimeout = 3-7",
            "RejectAfterTime = 150-180",
            "KeepaliveTimeout = 5-15",
            "MaxHandshakeAttempts = 15-20",
            "RandomTrailers = on",
            "DisableCookies = on",
            "I1 = <r 2><b 0x858000010001000000000669636c6f7564"
            "03636f6d0000010001c00c000100010000105a00044d583737>",
            "",
            "[Peer]",
            f"PublicKey = {self.server_public_key}",
        ]
        if preshared_key is not None:
            lines.append(f"PresharedKey = {preshared_key}")
        lines.extend(
            [
                f"Endpoint = {self.address}:{self.port}",
                f"AllowedIPs = {allowed_ips}",
                "PersistentKeepalive = 25",
                "",
            ]
        )
        return "\n".join(lines)
