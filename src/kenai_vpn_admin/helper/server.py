from __future__ import annotations

import os
import socket
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol as TypingProtocol
from typing import cast

from pydantic import ValidationError

from kenai_vpn_admin.application.ports import (
    DeviceRuntimeStatus,
    IssuedCredential,
    IssuedRouteProfile,
    RouteRuntimeStatus,
    ServerHealth,
)
from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.contracts import (
    MAX_MESSAGE_BYTES,
    DeviceStatusPayload,
    ErrorResponse,
    HealthPayload,
    HelperErrorCode,
    HelperOperation,
    HelperRequest,
    IssuePayload,
    ProtocolActionPayload,
    RouteHealthPayload,
    RouteProfileActionPayload,
    RouteProfileIssuePayload,
    SetEnabledPayload,
    SetRouteProfileEnabledPayload,
    SuccessResponse,
    parse_operation_payload,
)
from kenai_vpn_admin.helper.state_store import StateConflictError


class HelperOperations(TypingProtocol):
    def issue(self, device_ref: str, protocols: set[Protocol]) -> list[IssuedCredential]: ...

    def set_enabled(self, device_ref: str, protocol: Protocol, enabled: bool) -> None: ...

    def revoke(self, device_ref: str, protocol: Protocol) -> None: ...

    def health(self) -> ServerHealth: ...

    def device_status(self, device_ref: str) -> DeviceRuntimeStatus: ...

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


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


class HelperServer:
    def __init__(
        self,
        socket_path: Path,
        operations: HelperOperations,
        *,
        allowed_uid: int,
        socket_gid: int,
        socket_mode: int = 0o660,
    ) -> None:
        self.socket_path = socket_path
        self.operations = operations
        self.allowed_uid = allowed_uid
        self.socket_gid = socket_gid
        self.socket_mode = socket_mode

    def serve_forever(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            raise RuntimeError(f"Refusing to replace existing helper socket: {self.socket_path}")
        address_family: int = getattr(socket, "AF_" + "UNIX")
        with socket.socket(address_family, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.socket_path))
            chown = cast(Callable[[object, int, int], None], getattr(os, "chown"))  # noqa: B009
            chown(self.socket_path, 0, self.socket_gid)
            os.chmod(self.socket_path, self.socket_mode)
            listener.listen(16)
            try:
                while True:
                    connection, _ = listener.accept()
                    with connection:
                        self._handle_connection(connection)
            finally:
                if self.socket_path.exists() and self.socket_path.is_socket():
                    self.socket_path.unlink()

    def _handle_connection(self, connection: socket.socket) -> None:
        request_id = uuid.uuid4()
        try:
            peer = self._peer_credentials(connection)
            if peer.uid != self.allowed_uid:
                self._send_error(connection, request_id, "permission_denied", "Peer is not allowed")
                return
            raw = self._receive_line(connection)
            request = HelperRequest.model_validate_json(raw)
            request_id = request.request_id
            result = self._dispatch(request)
            response = SuccessResponse(request_id=request_id, result=result)
            self._send(connection, response.model_dump_json())
        except ValidationError:
            self._send_error(connection, request_id, "invalid_request", "Invalid helper request")
        except StateConflictError:
            self._send_error(connection, request_id, "conflict", "Requested state conflicts")
        except Exception:
            self._send_error(connection, request_id, "internal_error", "Helper operation failed")

    def _dispatch(self, request: HelperRequest) -> dict[str, object] | list[dict[str, object]]:
        payload = parse_operation_payload(request)
        if request.operation is HelperOperation.ISSUE:
            assert isinstance(payload, IssuePayload)
            return [
                {
                    "protocol": item.protocol.value,
                    "public_identifier": item.public_identifier,
                    "client_material": item.client_material,
                    "tunnel_address": item.tunnel_address,
                }
                for item in self.operations.issue(payload.device_ref, payload.protocols)
            ]
        if request.operation is HelperOperation.SET_ENABLED:
            assert isinstance(payload, SetEnabledPayload)
            self.operations.set_enabled(payload.device_ref, payload.protocol, payload.enabled)
            return {"changed": True}
        if request.operation is HelperOperation.REVOKE:
            assert isinstance(payload, ProtocolActionPayload)
            self.operations.revoke(payload.device_ref, payload.protocol)
            return {"changed": True}
        if request.operation is HelperOperation.DEVICE_STATUS:
            assert isinstance(payload, DeviceStatusPayload)
            status = self.operations.device_status(payload.device_ref)
            return {
                "wireguard": status.wireguard.__dict__ if status.wireguard else None,
                "amneziawg": status.amneziawg.__dict__ if status.amneziawg else None,
                "vless": status.vless.__dict__ if status.vless else None,
            }
        if request.operation is HelperOperation.ISSUE_ROUTE_PROFILE:
            assert isinstance(payload, RouteProfileIssuePayload)
            profile = self.operations.issue_route_profile(
                str(payload.profile_ref),
                payload.device_ref,
                payload.location_slug,
                payload.outbound_tag,
            )
            return {
                "public_identifier": profile.public_identifier,
                "client_email": profile.client_email,
                "client_uri": profile.client_uri,
            }
        if request.operation is HelperOperation.SET_ROUTE_PROFILE_ENABLED:
            assert isinstance(payload, SetRouteProfileEnabledPayload)
            self.operations.set_route_profile_enabled(str(payload.profile_ref), payload.enabled)
            return {"changed": True}
        if request.operation is HelperOperation.REVOKE_ROUTE_PROFILE:
            assert isinstance(payload, RouteProfileActionPayload)
            self.operations.revoke_route_profile(str(payload.profile_ref))
            return {"changed": True}
        if request.operation is HelperOperation.ROUTE_HEALTH:
            assert isinstance(payload, RouteHealthPayload)
            route_status = self.operations.route_health(payload.outbound_tag)
            return {
                "outbound_tag": route_status.outbound_tag,
                "available": route_status.available,
                "latency_ms": route_status.latency_ms,
                "error_code": route_status.error_code,
            }
        assert isinstance(payload, HealthPayload)
        health = self.operations.health()
        return {
            "wireguard": health.wireguard.__dict__,
            "amneziawg": health.amneziawg.__dict__,
            "xray": health.xray.__dict__,
            "firewall_active": health.firewall_active,
            "failed_units": health.failed_units,
            "mode": "helper",
            "cpu_percent": health.cpu_percent,
            "memory_percent": health.memory_percent,
            "disk_percent": health.disk_percent,
            "load_percent": health.load_percent,
        }

    @staticmethod
    def _peer_credentials(connection: socket.socket) -> PeerCredentials:
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("SO_PEERCRED is required; helper must run on Linux")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return PeerCredentials(*struct.unpack("3i", raw))

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
            raise ValueError("Request exceeds maximum message size")
        raise ValueError("Incomplete helper request")

    @staticmethod
    def _send(connection: socket.socket, serialized: str) -> None:
        connection.sendall(serialized.encode("utf-8") + b"\n")

    def _send_error(
        self,
        connection: socket.socket,
        request_id: uuid.UUID,
        code: HelperErrorCode,
        message: str,
    ) -> None:
        response = ErrorResponse(
            request_id=request_id,
            error_code=code,
            message=message,
        )
        self._send(connection, response.model_dump_json())
