import pyotp

from kenai_vpn_admin.cli.main import verify_totp_enrollment


def test_totp_enrollment_requires_current_six_digit_code() -> None:
    secret = pyotp.random_base32()
    current = pyotp.TOTP(secret).now()

    assert verify_totp_enrollment(secret, current) is True
    assert verify_totp_enrollment(secret, "12345") is False
    assert verify_totp_enrollment(secret, "abcdef") is False
