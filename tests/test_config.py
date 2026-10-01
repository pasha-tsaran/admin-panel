import pytest
from pydantic import ValidationError

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.domain.enums import Protocol


def test_vless_only_subscription_protocols() -> None:
    settings = Settings(subscription_protocols=" VLESS ")

    assert settings.subscription_protocols == "vless"
    assert settings.subscription_protocol_set == {Protocol.VLESS}


def test_subscription_protocols_reject_duplicates() -> None:
    with pytest.raises(ValidationError):
        Settings(subscription_protocols="vless,vless")


def test_backup_protocols_are_independent_of_new_subscriptions() -> None:
    settings = Settings(
        subscription_protocols="vless", backup_protocols="wireguard,amneziawg,vless"
    )

    assert settings.subscription_protocol_set == {Protocol.VLESS}
    assert settings.backup_protocol_set == set(Protocol)


def test_backup_protocols_reject_duplicates() -> None:
    with pytest.raises(ValidationError, match="KENAI_BACKUP_PROTOCOLS"):
        Settings(backup_protocols="vless,vless")
