import hashlib

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.infrastructure.mock_vpn import MockVpnManager


def test_mock_addresses_resolve_hash_collisions_and_stay_stable() -> None:
    refs: dict[int, str] = {}
    first = second = ""
    for number in range(241):
        candidate = f"mock-device-{number}"
        bucket = int(hashlib.sha256(candidate.encode()).hexdigest()[:4], 16) % 240
        if bucket in refs:
            first, second = refs[bucket], candidate
            break
        refs[bucket] = candidate
    assert first and second

    vpn = MockVpnManager()
    first_address = vpn.issue(first, {Protocol.AMNEZIAWG})[0].tunnel_address
    second_address = vpn.issue(second, {Protocol.AMNEZIAWG})[0].tunnel_address
    assert first_address != second_address
    assert vpn.issue(first, {Protocol.AMNEZIAWG})[0].tunnel_address == first_address
