import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.crypto import FernetCipher
from kenai_vpn_admin.infrastructure.models import (
    AdministratorModel,
    LoginAttemptModel,
    SessionModel,
    utc_now,
)

password_hasher = PasswordHasher()


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters")
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


@dataclass(frozen=True)
class NewSession:
    cookie_token: str
    csrf_token: str
    model: SessionModel


class AuthenticationService:
    def __init__(self, settings: Settings, cipher: FernetCipher) -> None:
        self.settings = settings
        self.cipher = cipher

    def is_rate_limited(self, db: Session, username: str, remote_address: str) -> bool:
        cutoff = utc_now() - timedelta(minutes=self.settings.login_window_minutes)
        failures = db.scalar(
            select(func.count(LoginAttemptModel.id)).where(
                LoginAttemptModel.username == username,
                LoginAttemptModel.remote_address == remote_address,
                LoginAttemptModel.attempted_at >= cutoff,
                LoginAttemptModel.succeeded.is_(False),
            )
        )
        return int(failures or 0) >= self.settings.login_max_attempts

    def record_attempt(
        self, db: Session, username: str, remote_address: str, *, succeeded: bool
    ) -> None:
        db.add(
            LoginAttemptModel(username=username, remote_address=remote_address, succeeded=succeeded)
        )

    def verify_totp(self, administrator: AdministratorModel, code: str) -> bool:
        secret = self.cipher.decrypt(administrator.encrypted_totp_secret)
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)

    def create_session(
        self,
        db: Session,
        administrator: AdministratorModel,
        remote_address: str | None,
        user_agent: str | None,
    ) -> NewSession:
        cookie_token = secrets.token_urlsafe(48)
        csrf_token = secrets.token_urlsafe(32)
        model = SessionModel(
            administrator_id=administrator.id,
            token_hash=hash_token(cookie_token),
            csrf_token_hash=hash_token(csrf_token),
            expires_at=utc_now() + timedelta(minutes=self.settings.session_ttl_minutes),
            remote_address=remote_address,
            user_agent=(user_agent or "")[:512] or None,
        )
        db.add(model)
        administrator.last_login_at = utc_now()
        return NewSession(cookie_token, csrf_token, model)

    def resolve_session(self, db: Session, cookie_token: str | None) -> SessionModel | None:
        if not cookie_token:
            return None
        model = db.scalar(
            select(SessionModel).where(
                SessionModel.token_hash == hash_token(cookie_token),
                SessionModel.revoked_at.is_(None),
                SessionModel.expires_at > utc_now(),
            )
        )
        if not model or not model.administrator.is_active:
            return None
        model.last_seen_at = utc_now()
        return model

    def validate_csrf(self, model: SessionModel, supplied_token: str | None) -> bool:
        if not supplied_token:
            return False
        return hmac.compare_digest(model.csrf_token_hash, hash_token(supplied_token))

    def revoke_session(self, model: SessionModel) -> None:
        model.revoked_at = utc_now()
