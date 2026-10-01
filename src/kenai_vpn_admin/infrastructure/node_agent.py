from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class AgentEndpoint:
    host: str
    port: int
    certificate_sha256: str


class NodeAgentClient:
    """Narrow HTTPS client for an already installed Kenai node agent."""

    def __init__(self, endpoint: str, certificate_sha256: str) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.hostname is None
        ):
            raise ValueError("Agent endpoint must be an HTTPS origin without a path")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError("Agent endpoint must use an explicit IP address") from exc
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError("Agent endpoint address is not allowed")
        fingerprint = certificate_sha256.lower().replace(":", "")
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise ValueError("Certificate SHA-256 fingerprint is invalid")
        self.endpoint = AgentEndpoint(parsed.hostname, parsed.port or 443, fingerprint)

    def preflight(self, enrollment_token: str) -> dict[str, Any]:
        return self._request("GET", "/v1/onboarding/preflight", enrollment_token, None)

    def register(self, enrollment_token: str, *, node_slug: str, role: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/onboarding/register",
            enrollment_token,
            {"node_slug": node_slug, "role": role},
        )

    def rollback(self, enrollment_token: str, *, node_slug: str) -> None:
        self._request("POST", "/v1/onboarding/rollback", enrollment_token, {"node_slug": node_slug})

    def _request(
        self, method: str, path: str, enrollment_token: str, payload: dict[str, str] | None
    ) -> dict[str, Any]:
        if not enrollment_token or len(enrollment_token) > 512:
            raise ValueError("Enrollment token is invalid")
        # The node agent may use a private CA. Identity is established by the
        # administrator-confirmed SHA-256 certificate pin below.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            self.endpoint.host, self.endpoint.port, timeout=8, context=context
        )
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {
            "Authorization": f"Bearer {enrollment_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            connection.connect()
            assert connection.sock is not None
            certificate = connection.sock.getpeercert(binary_form=True)
            if certificate is None:
                raise RuntimeError("agent_certificate_unavailable")
            actual = hashlib.sha256(certificate).hexdigest()
            if actual != self.endpoint.certificate_sha256:
                raise RuntimeError("agent_certificate_mismatch")
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(32_769)
            if len(raw) > 32_768:
                raise RuntimeError("agent_response_too_large")
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"agent_http_{response.status}")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise RuntimeError("agent_response_invalid")
            return data
        finally:
            connection.close()
