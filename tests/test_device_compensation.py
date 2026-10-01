from __future__ import annotations

from types import SimpleNamespace
from typing import Never, cast

import pytest
from fastapi import Request
from sqlalchemy.orm import Session

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.web.dependencies import AuthenticatedAdmin
from kenai_vpn_admin.web.routes import create_device


class CommitFailureSession:
    def __init__(self) -> None:
        self.rollback_calls = 0

    def commit(self) -> Never:
        raise RuntimeError("simulated commit failure")

    def rollback(self) -> None:
        self.rollback_calls += 1


class RecordingAdminService:
    def __init__(self) -> None:
        self.compensations: list[tuple[str, set[Protocol]]] = []

    def create_device(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            slug="windows-pc-test",
            user=SimpleNamespace(slug="existing-user"),
        )

    def compensate_device_creation(self, device_ref: str, protocols: set[Protocol]) -> None:
        self.compensations.append((device_ref, protocols))


def test_create_device_compensates_both_protocols_when_commit_fails() -> None:
    service = RecordingAdminService()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                admin_service=service,
                settings=SimpleNamespace(
                    issuable_protocol_set={Protocol.AMNEZIAWG, Protocol.VLESS}
                ),
            )
        ),
        state=SimpleNamespace(correlation_id="test-correlation"),
    )
    session = CommitFailureSession()
    current = SimpleNamespace(administrator=SimpleNamespace(id="test-administrator"))

    with pytest.raises(RuntimeError, match="simulated commit failure"):
        create_device(
            request=cast(Request, request),
            user_id="existing-user-id",
            db=cast(Session, session),
            current=cast(AuthenticatedAdmin, current),
            slug="windows-pc-test",
            display_name="Windows PC test",
            amneziawg=True,
            vless=True,
        )

    assert session.rollback_calls == 1
    assert service.compensations == [
        ("existing-user-windows-pc-test", {Protocol.AMNEZIAWG, Protocol.VLESS})
    ]
