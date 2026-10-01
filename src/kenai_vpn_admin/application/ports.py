from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol as TypingProtocol

from kenai_vpn_admin.domain.enums import Protocol


@dataclass(frozen=True)
class IssuedCredential:
    protocol: Protocol
    public_identifier: str
    client_material: str
    tunnel_address: str | None = None


@dataclass(frozen=True)
class ProtocolRuntimeStatus:
    active: bool
    enabled: bool
    last_seen_at: datetime | None = None
    received_bytes: int = 0
    transmitted_bytes: int = 0
    current_connections: int = 0


@dataclass(frozen=True)
class ServerHealth:
    wireguard: ProtocolRuntimeStatus
    xray: ProtocolRuntimeStatus
    firewall_active: bool
    failed_units: int
    mode: str
    amneziawg: ProtocolRuntimeStatus = field(
        default_factory=lambda: ProtocolRuntimeStatus(False, False)
    )
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_percent: float | None = None
    load_percent: float | None = None


@dataclass(frozen=True)
class DeviceRuntimeStatus:
    wireguard: ProtocolRuntimeStatus | None = None
    amneziawg: ProtocolRuntimeStatus | None = None
    vless: ProtocolRuntimeStatus | None = None


@dataclass(frozen=True)
class IssuedRouteProfile:
    public_identifier: str
    client_email: str
    client_uri: str


@dataclass(frozen=True)
class RouteRuntimeStatus:
    outbound_tag: str
    available: bool
    latency_ms: int | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class CascadeRouteSpec:
    location_slug: str
    address: str
    port: int
    client_uuid: str
    server_name: str
    reality_public_key: str
    short_id: str


class SecretCipher(TypingProtocol):
    def encrypt(self, plaintext: str) -> bytes: ...

    def decrypt(self, ciphertext: bytes) -> str: ...


class VpnManager(TypingProtocol):
    def issue(self, device_ref: str, protocols: set[Protocol]) -> list[IssuedCredential]: ...

    def set_enabled(self, device_ref: str, protocol: Protocol, enabled: bool) -> None: ...

    def revoke(self, device_ref: str, protocol: Protocol) -> None: ...

    def health(self) -> ServerHealth: ...

    def device_status(self, device_ref: str) -> DeviceRuntimeStatus: ...


class CascadeManager(TypingProtocol):
    def issue_route_profile(
        self,
        profile_ref: str,
        device_ref: str,
        location_slug: str,
        outbound_tag: str,
    ) -> IssuedRouteProfile: ...

    def set_route_profile_enabled(self, profile_ref: str, enabled: bool) -> None: ...

    def revoke_route_profile(self, profile_ref: str) -> None: ...

    def route_health(self, outbound_tag: str) -> RouteRuntimeStatus: ...
