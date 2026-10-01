import base64
import hashlib
import ipaddress
import secrets
import uuid
from datetime import UTC, datetime

from kenai_vpn_admin.application.ports import (
    DeviceRuntimeStatus,
    IssuedCredential,
    IssuedRouteProfile,
    ProtocolRuntimeStatus,
    RouteRuntimeStatus,
    ServerHealth,
)
from kenai_vpn_admin.domain.enums import Protocol


class MockVpnManager:
    """Safe deterministic boundary for local UI development and tests."""

    def __init__(self) -> None:
        self._states: dict[tuple[str, Protocol], bool] = {}
        self._route_states: dict[str, bool] = {}
        self._addresses: dict[tuple[str, Protocol], str] = {}

    def _address_for(self, device_ref: str, protocol: Protocol) -> str:
        key = (device_ref, protocol)
        if key in self._addresses:
            return self._addresses[key]
        prefix = "10.66.66" if protocol is Protocol.WIREGUARD else "10.67.67"
        start = int(hashlib.sha256(device_ref.encode()).hexdigest()[:4], 16) % 240
        reserved = set(self._addresses.values())
        for offset in range(240):
            suffix = (start + offset) % 240 + 2
            address = str(ipaddress.ip_address(f"{prefix}.{suffix}")) + "/32"
            if address not in reserved:
                self._addresses[key] = address
                return address
        raise RuntimeError("Mock VPN address pool is exhausted")

    def issue(self, device_ref: str, protocols: set[Protocol]) -> list[IssuedCredential]:
        issued: list[IssuedCredential] = []
        if Protocol.WIREGUARD in protocols:
            address = self._address_for(device_ref, Protocol.WIREGUARD)
            private_key = base64.b64encode(secrets.token_bytes(32)).decode()
            public_key = base64.b64encode(hashlib.sha256(private_key.encode()).digest()).decode()
            config = (
                "[Interface]\n"
                f"PrivateKey = {private_key}\n"
                f"Address = {address}\n"
                "DNS = 1.1.1.1, 1.0.0.1\n\n"
                "[Peer]\n"
                "PublicKey = MOCK_SERVER_PUBLIC_KEY\n"
                "Endpoint = 88.218.94.3:51820\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\n"
                "PersistentKeepalive = 25\n"
            )
            issued.append(IssuedCredential(Protocol.WIREGUARD, public_key, config, address))
            self._states[(device_ref, Protocol.WIREGUARD)] = True
        if Protocol.VLESS in protocols:
            client_uuid = str(uuid.uuid4())
            short_id = secrets.token_hex(4)
            uri = (
                f"vless://{client_uuid}@88.218.94.3:443?type=raw&security=reality"
                "&flow=xtls-rprx-vision&sni=mirrors.teamcloud.am&fp=chrome"
                f"&pbk=MOCK_PUBLIC_KEY&sid={short_id}#{device_ref}"
            )
            issued.append(IssuedCredential(Protocol.VLESS, client_uuid, uri))
            self._states[(device_ref, Protocol.VLESS)] = True
        if Protocol.AMNEZIAWG in protocols:
            address = self._address_for(device_ref, Protocol.AMNEZIAWG)
            private_key = base64.b64encode(secrets.token_bytes(32)).decode()
            public_key = base64.b64encode(hashlib.sha256(private_key.encode()).digest()).decode()
            config = (
                "[Interface]\n"
                f"PrivateKey = {private_key}\n"
                f"Address = {address}\n"
                "DNS = 1.1.1.1, 1.0.0.1\n"
                "Jc = 7\nJmin = 64\nJmax = 256\n"
                "S1 = 32\nS2 = 32\nS3 = 32\nS4 = 16\n"
                "H1 = 100000000-199999999\nH2 = 200000000-299999999\n"
                "H3 = 300000000-399999999\nH4 = 400000000-499999999\n\n"
                "[Peer]\nPublicKey = MOCK_AWG_SERVER_PUBLIC_KEY\n"
                "Endpoint = 88.218.94.3:585\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
            )
            issued.append(IssuedCredential(Protocol.AMNEZIAWG, public_key, config, address))
            self._states[(device_ref, Protocol.AMNEZIAWG)] = True
        return issued

    def set_enabled(self, device_ref: str, protocol: Protocol, enabled: bool) -> None:
        self._states[(device_ref, protocol)] = enabled

    def revoke(self, device_ref: str, protocol: Protocol) -> None:
        self._states[(device_ref, protocol)] = False

    def health(self) -> ServerHealth:
        now = datetime.now(UTC)
        return ServerHealth(
            wireguard=ProtocolRuntimeStatus(True, True, now, 1_572_864, 524_288),
            amneziawg=ProtocolRuntimeStatus(True, True, now, 3_145_728, 1_048_576),
            xray=ProtocolRuntimeStatus(True, True, now, 2_097_152, 786_432),
            firewall_active=True,
            failed_units=0,
            mode="mock",
        )

    def device_status(self, device_ref: str) -> DeviceRuntimeStatus:
        now = datetime.now(UTC)
        wireguard_enabled = self._states.get((device_ref, Protocol.WIREGUARD))
        vless_enabled = self._states.get((device_ref, Protocol.VLESS))
        amneziawg_enabled = self._states.get((device_ref, Protocol.AMNEZIAWG))
        return DeviceRuntimeStatus(
            wireguard=(
                ProtocolRuntimeStatus(
                    active=wireguard_enabled,
                    enabled=wireguard_enabled,
                    last_seen_at=now if wireguard_enabled else None,
                    received_bytes=1_572_864 if wireguard_enabled else 0,
                    transmitted_bytes=524_288 if wireguard_enabled else 0,
                )
                if wireguard_enabled is not None
                else None
            ),
            amneziawg=(
                ProtocolRuntimeStatus(
                    active=amneziawg_enabled,
                    enabled=amneziawg_enabled,
                    last_seen_at=now if amneziawg_enabled else None,
                    received_bytes=3_145_728 if amneziawg_enabled else 0,
                    transmitted_bytes=1_048_576 if amneziawg_enabled else 0,
                )
                if amneziawg_enabled is not None
                else None
            ),
            vless=(
                ProtocolRuntimeStatus(
                    active=vless_enabled,
                    enabled=vless_enabled,
                    received_bytes=2_097_152 if vless_enabled else 0,
                    transmitted_bytes=786_432 if vless_enabled else 0,
                    current_connections=1 if vless_enabled else 0,
                )
                if vless_enabled is not None
                else None
            ),
        )

    def issue_route_profile(
        self,
        profile_ref: str,
        device_ref: str,
        location_slug: str,
        outbound_tag: str,
    ) -> IssuedRouteProfile:
        del outbound_tag
        client_uuid = str(uuid.uuid4())
        client_email = f"route:{location_slug}:{device_ref}"
        uri = (
            f"vless://{client_uuid}@88.218.94.3:443?type=raw&security=reality"
            "&flow=xtls-rprx-vision&sni=mirrors.teamcloud.am&fp=chrome"
            f"&pbk=MOCK_PUBLIC_KEY&sid=01234567#{location_slug}"
        )
        self._route_states[profile_ref] = True
        return IssuedRouteProfile(client_uuid, client_email, uri)

    def set_route_profile_enabled(self, profile_ref: str, enabled: bool) -> None:
        if profile_ref not in self._route_states:
            raise RuntimeError("Route profile does not exist")
        self._route_states[profile_ref] = enabled

    def revoke_route_profile(self, profile_ref: str) -> None:
        if profile_ref not in self._route_states:
            raise RuntimeError("Route profile does not exist")
        self._route_states[profile_ref] = False

    @staticmethod
    def route_health(outbound_tag: str) -> RouteRuntimeStatus:
        seed = int(hashlib.sha256(outbound_tag.encode()).hexdigest()[:4], 16)
        return RouteRuntimeStatus(
            outbound_tag=outbound_tag,
            available=True,
            latency_ms=35 + seed % 70,
        )
