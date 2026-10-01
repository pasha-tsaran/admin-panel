from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.contracts import (
    DeviceStatusPayload,
    HelperOperation,
    HelperRequest,
    IssuePayload,
    SuccessResponse,
    parse_operation_payload,
)
from kenai_vpn_admin.infrastructure.helper_client import HelperVpnManagerClient


def test_issue_payload_survives_json_round_trip() -> None:
    outgoing = HelperRequest(
        operation=HelperOperation.ISSUE,
        payload={
            "device_ref": "diagnostic-device",
            "protocols": [Protocol.WIREGUARD.value, Protocol.VLESS.value],
        },
    )

    incoming = HelperRequest.model_validate_json(outgoing.model_dump_json())
    payload = parse_operation_payload(incoming)

    assert isinstance(payload, IssuePayload)
    assert payload.device_ref == "diagnostic-device"
    assert payload.protocols == {Protocol.WIREGUARD, Protocol.VLESS}


def test_issue_payload_still_rejects_unknown_protocol() -> None:
    request = HelperRequest(
        operation=HelperOperation.ISSUE,
        payload={"device_ref": "diagnostic-device", "protocols": ["unknown"]},
    )

    with pytest.raises(ValidationError):
        parse_operation_payload(request)


def test_issue_payload_still_rejects_extra_fields() -> None:
    request = HelperRequest(
        operation=HelperOperation.ISSUE,
        payload={
            "device_ref": "diagnostic-device",
            "protocols": [Protocol.WIREGUARD.value],
            "unexpected": True,
        },
    )

    with pytest.raises(ValidationError):
        parse_operation_payload(request)


def test_helper_client_parses_wireguard_and_vless_results_in_json_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = SuccessResponse.model_validate_json(
        json.dumps(
            {
                "version": 1,
                "request_id": str(uuid.uuid4()),
                "ok": True,
                "result": [
                    {
                        "protocol": "wireguard",
                        "public_identifier": "wireguard-public-identifier",
                        "client_material": "wireguard-client-material",
                        "tunnel_address": "10.66.66.2/32",
                    },
                    {
                        "protocol": "vless",
                        "public_identifier": "vless-public-identifier",
                        "client_material": "vless-client-material",
                        "tunnel_address": None,
                    },
                ],
            }
        )
    )
    client = HelperVpnManagerClient(socket_path=None)  # type: ignore[arg-type]
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: response)

    issued = client.issue("diagnostic-device", {Protocol.WIREGUARD, Protocol.VLESS})

    assert [credential.protocol for credential in issued] == [
        Protocol.WIREGUARD,
        Protocol.VLESS,
    ]


def test_device_status_payload_validates_device_reference() -> None:
    request = HelperRequest(
        operation=HelperOperation.DEVICE_STATUS,
        payload={"device_ref": "test-win-pc"},
    )

    payload = parse_operation_payload(request)

    assert isinstance(payload, DeviceStatusPayload)
    assert payload.device_ref == "test-win-pc"


def test_helper_client_parses_device_status_in_json_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = SuccessResponse.model_validate_json(
        json.dumps(
            {
                "version": 1,
                "request_id": str(uuid.uuid4()),
                "ok": True,
                "result": {
                    "wireguard": {
                        "active": True,
                        "enabled": True,
                        "last_seen_at": "2026-08-29T12:00:00Z",
                        "received_bytes": 1572864,
                        "transmitted_bytes": 524288,
                    },
                    "vless": {
                        "active": True,
                        "enabled": True,
                        "last_seen_at": None,
                        "received_bytes": 0,
                        "transmitted_bytes": 0,
                    },
                },
            }
        )
    )
    client = HelperVpnManagerClient(socket_path=None)  # type: ignore[arg-type]
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: response)

    status = client.device_status("test-win-pc")

    assert status.wireguard is not None
    assert status.wireguard.received_bytes == 1_572_864
    assert status.vless is not None
    assert status.vless.active is True
