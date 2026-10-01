from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kenai_vpn_admin.domain.enums import Protocol

PROTOCOL_VERSION: Literal[1] = 1
MAX_MESSAGE_BYTES = 64 * 1024
DEVICE_REF_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class HelperOperation(StrEnum):
    ISSUE = "issue"
    SET_ENABLED = "set_enabled"
    REVOKE = "revoke"
    HEALTH = "health"
    DEVICE_STATUS = "device_status"
    ISSUE_ROUTE_PROFILE = "issue_route_profile"
    SET_ROUTE_PROFILE_ENABLED = "set_route_profile_enabled"
    REVOKE_ROUTE_PROFILE = "revoke_route_profile"
    ROUTE_HEALTH = "route_health"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IssuePayload(StrictModel):
    device_ref: str = Field(min_length=3, max_length=129)
    protocols: set[Protocol] = Field(min_length=1, max_length=3)

    @field_validator("device_ref")
    @classmethod
    def validate_device_ref(cls, value: str) -> str:
        if not DEVICE_REF_PATTERN.fullmatch(value):
            raise ValueError("Invalid device reference")
        return value


class ProtocolActionPayload(StrictModel):
    device_ref: str = Field(min_length=3, max_length=129)
    protocol: Protocol

    @field_validator("device_ref")
    @classmethod
    def validate_device_ref(cls, value: str) -> str:
        if not DEVICE_REF_PATTERN.fullmatch(value):
            raise ValueError("Invalid device reference")
        return value


class SetEnabledPayload(ProtocolActionPayload):
    enabled: bool


class HealthPayload(StrictModel):
    pass


class DeviceStatusPayload(StrictModel):
    device_ref: str = Field(min_length=3, max_length=129)

    @field_validator("device_ref")
    @classmethod
    def validate_device_ref(cls, value: str) -> str:
        if not DEVICE_REF_PATTERN.fullmatch(value):
            raise ValueError("Invalid device reference")
        return value


class RouteProfileIssuePayload(StrictModel):
    profile_ref: uuid.UUID
    device_ref: str = Field(min_length=3, max_length=129)
    location_slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=64)
    outbound_tag: str = Field(pattern=r"^kenai-exit-[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=128)

    @field_validator("device_ref")
    @classmethod
    def validate_device_ref(cls, value: str) -> str:
        if not DEVICE_REF_PATTERN.fullmatch(value):
            raise ValueError("Invalid device reference")
        return value


class RouteProfileActionPayload(StrictModel):
    profile_ref: uuid.UUID


class SetRouteProfileEnabledPayload(RouteProfileActionPayload):
    enabled: bool


class RouteHealthPayload(StrictModel):
    outbound_tag: str = Field(pattern=r"^kenai-exit-[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=128)


class HelperRequest(StrictModel):
    version: Literal[1] = PROTOCOL_VERSION
    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    operation: HelperOperation
    payload: dict[str, object]


class IssuedCredentialResult(StrictModel):
    protocol: Protocol
    public_identifier: str = Field(min_length=1, max_length=512)
    client_material: str = Field(min_length=1, max_length=32_768)
    tunnel_address: str | None = Field(default=None, max_length=64)


class RuntimeStatusResult(StrictModel):
    active: bool
    enabled: bool
    last_seen_at: datetime | None = None
    received_bytes: int = Field(default=0, ge=0)
    transmitted_bytes: int = Field(default=0, ge=0)
    current_connections: int = Field(default=0, ge=0)


class HealthResult(StrictModel):
    wireguard: RuntimeStatusResult
    xray: RuntimeStatusResult
    firewall_active: bool
    failed_units: int = Field(ge=0)
    mode: Literal["helper"] = "helper"
    amneziawg: RuntimeStatusResult = Field(
        default_factory=lambda: RuntimeStatusResult(active=False, enabled=False)
    )
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    disk_percent: float | None = Field(default=None, ge=0, le=100)
    load_percent: float | None = Field(default=None, ge=0, le=100)


class DeviceStatusResult(StrictModel):
    wireguard: RuntimeStatusResult | None = None
    amneziawg: RuntimeStatusResult | None = None
    vless: RuntimeStatusResult | None = None


class RouteProfileResult(StrictModel):
    public_identifier: uuid.UUID
    client_email: str = Field(min_length=1, max_length=253)
    client_uri: str = Field(min_length=1, max_length=32_768)


class RouteHealthResult(StrictModel):
    outbound_tag: str = Field(min_length=1, max_length=128)
    available: bool
    latency_ms: int | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=64)


class SuccessResponse(StrictModel):
    version: Literal[1] = PROTOCOL_VERSION
    request_id: uuid.UUID
    ok: Literal[True] = True
    result: dict[str, object] | list[dict[str, object]]


class ErrorResponse(StrictModel):
    version: Literal[1] = PROTOCOL_VERSION
    request_id: uuid.UUID
    ok: Literal[False] = False
    error_code: Literal[
        "invalid_request",
        "permission_denied",
        "conflict",
        "not_found",
        "verification_failed",
        "internal_error",
    ]
    message: str = Field(min_length=1, max_length=300)


HelperErrorCode = Literal[
    "invalid_request",
    "permission_denied",
    "conflict",
    "not_found",
    "verification_failed",
    "internal_error",
]


HelperResponse = Annotated[SuccessResponse | ErrorResponse, Field(discriminator="ok")]


def parse_operation_payload(request: HelperRequest) -> StrictModel:
    model_by_operation: dict[HelperOperation, type[StrictModel]] = {
        HelperOperation.ISSUE: IssuePayload,
        HelperOperation.SET_ENABLED: SetEnabledPayload,
        HelperOperation.REVOKE: ProtocolActionPayload,
        HelperOperation.HEALTH: HealthPayload,
        HelperOperation.DEVICE_STATUS: DeviceStatusPayload,
        HelperOperation.ISSUE_ROUTE_PROFILE: RouteProfileIssuePayload,
        HelperOperation.SET_ROUTE_PROFILE_ENABLED: SetRouteProfileEnabledPayload,
        HelperOperation.REVOKE_ROUTE_PROFILE: RouteProfileActionPayload,
        HelperOperation.ROUTE_HEALTH: RouteHealthPayload,
    }
    return model_by_operation[request.operation].model_validate_json(json.dumps(request.payload))
