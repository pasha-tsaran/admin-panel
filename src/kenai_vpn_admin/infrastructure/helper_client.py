from __future__ import annotations

import json
import socket
from pathlib import Path

from pydantic import TypeAdapter

from kenai_vpn_admin.application.ports import (
    DeviceRuntimeStatus,
    IssuedCredential,
    IssuedRouteProfile,
    ProtocolRuntimeStatus,
    RouteRuntimeStatus,
    ServerHealth,
)
from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.contracts import (
    MAX_MESSAGE_BYTES,
    DeviceStatusResult,
    ErrorResponse,
    HealthResult,
    HelperOperation,
    HelperRequest,
    HelperResponse,
    IssuedCredentialResult,
    RouteHealthResult,
    RouteProfileResult,
    RuntimeStatusResult,
    SuccessResponse,
)


class HelperUnavailableError(RuntimeError):
    pass


class HelperOperationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class HelperVpnManagerClient:
    """Synchronous typed client for the root-owned Unix-socket helper."""

    def __init__(self, socket_path: Path, *, timeout_seconds: float = 10.0) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self._response_adapter: TypeAdapter[HelperResponse] = TypeAdapter(HelperResponse)

    def issue(self, device_ref: str, protocols: set[Protocol]) -> list[IssuedCredential]:
        response = self._request(
            HelperOperation.ISSUE,
            {
                "device_ref": device_ref,
                "protocols": sorted(protocol.value for protocol in protocols),
            },
        )
        if not isinstance(response.result, list):
            raise HelperOperationError(
                "invalid_response", "Helper returned an invalid issue result"
            )
        return [
            IssuedCredential(
                protocol=item.protocol,
                public_identifier=item.public_identifier,
                client_material=item.client_material,
                tunnel_address=item.tunnel_address,
            )
            for raw in response.result
            for item in [IssuedCredentialResult.model_validate_json(json.dumps(raw))]
        ]

    def set_enabled(self, device_ref: str, protocol: Protocol, enabled: bool) -> None:
        self._request(
            HelperOperation.SET_ENABLED,
            {"device_ref": device_ref, "protocol": protocol.value, "enabled": enabled},
        )

    def revoke(self, device_ref: str, protocol: Protocol) -> None:
        self._request(
            HelperOperation.REVOKE,
            {"device_ref": device_ref, "protocol": protocol.value},
        )

    def health(self) -> ServerHealth:
        response = self._request(HelperOperation.HEALTH, {})
        if not isinstance(response.result, dict):
            raise HelperOperationError(
                "invalid_response", "Helper returned an invalid health result"
            )
        result = HealthResult.model_validate(response.result)
        return ServerHealth(
            wireguard=self._runtime_status(result.wireguard),
            amneziawg=self._runtime_status(result.amneziawg),
            xray=self._runtime_status(result.xray),
            firewall_active=result.firewall_active,
            failed_units=result.failed_units,
            mode=result.mode,
            cpu_percent=result.cpu_percent,
            memory_percent=result.memory_percent,
            disk_percent=result.disk_percent,
            load_percent=result.load_percent,
        )

    def device_status(self, device_ref: str) -> DeviceRuntimeStatus:
        response = self._request(HelperOperation.DEVICE_STATUS, {"device_ref": device_ref})
        if not isinstance(response.result, dict):
            raise HelperOperationError(
                "invalid_response", "Helper returned an invalid device status result"
            )
        result = DeviceStatusResult.model_validate_json(json.dumps(response.result))
        return DeviceRuntimeStatus(
            wireguard=(self._runtime_status(result.wireguard) if result.wireguard else None),
            amneziawg=(self._runtime_status(result.amneziawg) if result.amneziawg else None),
            vless=self._runtime_status(result.vless) if result.vless else None,
        )

    def issue_route_profile(
        self,
        profile_ref: str,
        device_ref: str,
        location_slug: str,
        outbound_tag: str,
    ) -> IssuedRouteProfile:
        response = self._request(
            HelperOperation.ISSUE_ROUTE_PROFILE,
            {
                "profile_ref": profile_ref,
                "device_ref": device_ref,
                "location_slug": location_slug,
                "outbound_tag": outbound_tag,
            },
        )
        if not isinstance(response.result, dict):
            raise HelperOperationError(
                "invalid_response", "Helper returned an invalid route profile result"
            )
        result = RouteProfileResult.model_validate(response.result)
        return IssuedRouteProfile(
            public_identifier=str(result.public_identifier),
            client_email=result.client_email,
            client_uri=result.client_uri,
        )

    def set_route_profile_enabled(self, profile_ref: str, enabled: bool) -> None:
        self._request(
            HelperOperation.SET_ROUTE_PROFILE_ENABLED,
            {"profile_ref": profile_ref, "enabled": enabled},
        )

    def revoke_route_profile(self, profile_ref: str) -> None:
        self._request(HelperOperation.REVOKE_ROUTE_PROFILE, {"profile_ref": profile_ref})

    def route_health(self, outbound_tag: str) -> RouteRuntimeStatus:
        response = self._request(HelperOperation.ROUTE_HEALTH, {"outbound_tag": outbound_tag})
        if not isinstance(response.result, dict):
            raise HelperOperationError(
                "invalid_response", "Helper returned an invalid route health result"
            )
        result = RouteHealthResult.model_validate(response.result)
        return RouteRuntimeStatus(
            outbound_tag=result.outbound_tag,
            available=result.available,
            latency_ms=result.latency_ms,
            error_code=result.error_code,
        )

    @staticmethod
    def _runtime_status(value: RuntimeStatusResult) -> ProtocolRuntimeStatus:
        return ProtocolRuntimeStatus(
            active=value.active,
            enabled=value.enabled,
            last_seen_at=value.last_seen_at,
            received_bytes=value.received_bytes,
            transmitted_bytes=value.transmitted_bytes,
            current_connections=value.current_connections,
        )

    def _request(self, operation: HelperOperation, payload: dict[str, object]) -> SuccessResponse:
        request = HelperRequest(operation=operation, payload=payload)
        encoded = request.model_dump_json().encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise ValueError("Helper request exceeds the maximum message size")
        try:
            address_family: int = getattr(socket, "AF_" + "UNIX")
            with socket.socket(address_family, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(encoded)
                raw = self._receive_line(connection)
        except (OSError, TimeoutError) as exc:
            raise HelperUnavailableError("VPN helper is unavailable") from exc
        response = self._response_adapter.validate_json(raw)
        if isinstance(response, ErrorResponse):
            raise HelperOperationError(response.error_code, response.message)
        return response

    @staticmethod
    def _receive_line(connection: socket.socket) -> bytes:
        buffer = bytearray()
        while len(buffer) <= MAX_MESSAGE_BYTES:
            chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES - len(buffer) + 1))
            if not chunk:
                break
            buffer.extend(chunk)
            newline = buffer.find(b"\n")
            if newline >= 0:
                return bytes(buffer[:newline])
        if len(buffer) > MAX_MESSAGE_BYTES:
            raise HelperUnavailableError("VPN helper response is too large")
        raise HelperUnavailableError("VPN helper closed the connection without a response")
