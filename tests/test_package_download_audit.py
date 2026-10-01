from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from kenai_vpn_admin.application.services import AdminService, DomainConflictError
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.crypto import FernetCipher
from kenai_vpn_admin.infrastructure.database import Base, build_engine, build_session_factory
from kenai_vpn_admin.infrastructure.mock_vpn import MockVpnManager
from kenai_vpn_admin.infrastructure.models import (
    AdministratorModel,
    AuditEventModel,
    DeviceModel,
    OneTimeTokenModel,
    ProvisioningPackageModel,
    UserModel,
    utc_now,
)
from kenai_vpn_admin.security import hash_token


def test_package_download_audit_is_single_and_secret_free() -> None:
    settings = Settings(
        env="test",
        database_url="sqlite:///:memory:",
        secret_key="test-secret-key-with-at-least-32-characters",
    )
    cipher = FernetCipher(None, settings.secret_key, allow_derived=True)
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)
    service = AdminService(settings, cipher, MockVpnManager())
    token = "one-time-test-token-that-is-not-a-production-secret"
    payload = b"test package bytes"

    with session_factory() as db:
        administrator = AdministratorModel(
            username="test-admin",
            password_hash="test-password-hash",
            encrypted_totp_secret=b"test-encrypted-totp",
        )
        user = UserModel(slug="test-user", display_name="Test user")
        db.add_all([administrator, user])
        db.flush()
        device = DeviceModel(user_id=user.id, slug="test-device", display_name="Test device")
        db.add(device)
        db.flush()
        expires_at = utc_now() + timedelta(minutes=15)
        package = ProvisioningPackageModel(
            device_id=device.id,
            includes_wireguard=True,
            includes_vless=True,
            encrypted_payload=cipher.encrypt(payload.hex()),
            expires_at=expires_at,
        )
        package.tokens.append(
            OneTimeTokenModel(token_hash=hash_token(token), expires_at=expires_at)
        )
        db.add(package)
        db.commit()

        downloaded, _ = service.consume_package(
            db,
            token,
            administrator_id=administrator.id,
            correlation_id="test-download-correlation",
        )
        db.commit()

        assert downloaded == payload
        events = list(
            db.scalars(select(AuditEventModel).where(AuditEventModel.action == "package.download"))
        )
        assert len(events) == 1
        assert events[0].metadata_json == {
            "includes_wireguard": True,
            "includes_amneziawg": False,
            "includes_vless": True,
        }
        serialized_metadata = json.dumps(events[0].metadata_json)
        assert token not in serialized_metadata
        assert payload.hex() not in serialized_metadata

        with pytest.raises(DomainConflictError, match="already been used"):
            service.consume_package(
                db,
                token,
                administrator_id=administrator.id,
                correlation_id="test-replay-correlation",
            )
        db.commit()

        token_model = db.scalar(
            select(OneTimeTokenModel).where(OneTimeTokenModel.package_id == package.id)
        )
        assert token_model is not None
        assert token_model.consumed_at is not None
        assert package.status == "consumed"
        assert (
            len(
                list(
                    db.scalars(
                        select(AuditEventModel).where(AuditEventModel.action == "package.download")
                    )
                )
            )
            == 1
        )
