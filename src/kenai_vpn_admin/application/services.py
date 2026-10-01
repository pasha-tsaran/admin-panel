from __future__ import annotations

import io
import json
import secrets
import uuid
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pyotp
import qrcode
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from kenai_vpn_admin.application.ports import DeviceRuntimeStatus, SecretCipher, VpnManager
from kenai_vpn_admin.application.rbac import ROLE_DEFAULTS, normalize_permissions
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.domain.enums import AuditOutcome, LifecycleStatus, PackageStatus, Protocol
from kenai_vpn_admin.domain.validation import validate_display_name, validate_slug
from kenai_vpn_admin.infrastructure.models import (
    ActivationAttemptModel,
    AdministratorModel,
    AmneziaWgCredentialModel,
    AuditEventModel,
    DeviceModel,
    OneTimeTokenModel,
    ProvisioningPackageModel,
    SessionModel,
    SubscriptionEventModel,
    SubscriptionModel,
    UserModel,
    VlessCredentialModel,
    WireGuardCredentialModel,
    naive_utc,
    utc_now,
)
from kenai_vpn_admin.security import hash_password, hash_token, verify_password


class DomainConflictError(RuntimeError):
    pass


class NotFoundError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProvisioningResult:
    token: str
    package_id: str
    expires_at: datetime


@dataclass(frozen=True)
class SubscriptionCreationResult:
    user: UserModel
    activation_key: str
    device_ref: str


@dataclass(frozen=True)
class ActivatedAccount:
    user_id: str
    email: str | None
    telegram_username: str | None
    phone_number: str | None
    wireguard_config: str | None
    amneziawg_config: str | None
    vless_uri: str | None
    subscription_expires_at: datetime


@dataclass(frozen=True)
class DashboardRuntimeSummary:
    configured_wireguard: int = 0
    configured_amneziawg: int = 0
    configured_vless: int = 0
    wireguard_with_handshake: int = 0
    amneziawg_with_handshake: int = 0
    amneziawg_connected_users: int = 0
    vless_connected: int = 0
    vless_connected_users: int = 0
    received_bytes: int = 0
    transmitted_bytes: int = 0
    amneziawg_received_bytes: int = 0
    amneziawg_transmitted_bytes: int = 0
    vless_received_bytes: int = 0
    vless_transmitted_bytes: int = 0
    latest_handshake_at: datetime | None = None
    latest_amneziawg_handshake_at: datetime | None = None


@dataclass(frozen=True)
class ConnectedWireGuardDevice:
    user_id: str
    user_name: str
    user_slug: str
    device_name: str
    device_slug: str
    is_subscription: bool
    last_handshake_at: datetime
    received_bytes: int
    transmitted_bytes: int


@dataclass(frozen=True)
class ConnectedVlessDevice:
    user_id: str
    user_name: str
    user_slug: str
    device_name: str
    device_slug: str
    is_subscription: bool
    current_connections: int
    received_bytes: int
    transmitted_bytes: int


@dataclass(frozen=True)
class TotpEnrollment:
    administrator_id: str
    provisioning_uri: str
    qr_png: bytes


class AdminService:
    def __init__(self, settings: Settings, cipher: SecretCipher, vpn: VpnManager) -> None:
        self.settings = settings
        self.cipher = cipher
        self.vpn = vpn

    def list_users(self, db: Session) -> list[UserModel]:
        return list(
            db.scalars(
                select(UserModel)
                .options(
                    selectinload(UserModel.devices).selectinload(DeviceModel.wireguard),
                    selectinload(UserModel.devices).selectinload(DeviceModel.amneziawg),
                    selectinload(UserModel.devices).selectinload(DeviceModel.vless),
                )
                .order_by(UserModel.display_name)
            )
        )

    def list_administrators(self, db: Session) -> list[AdministratorModel]:
        return list(db.scalars(select(AdministratorModel).order_by(AdministratorModel.username)))

    def create_administrator(
        self,
        db: Session,
        *,
        username: str,
        password: str,
        acting_administrator: AdministratorModel,
        acting_password: str,
        acting_totp: str,
        correlation_id: str,
        role: str = "admin",
        permissions: list[str] | None = None,
    ) -> TotpEnrollment:
        self._verify_sensitive_action(acting_administrator, acting_password, acting_totp)
        username = username.strip().lower()
        if not username or len(username) > 80 or not username.replace("-", "").isalnum():
            raise ValueError("Administrator username is invalid")
        if db.scalar(select(AdministratorModel.id).where(AdministratorModel.username == username)):
            raise DomainConflictError("Administrator username already exists")
        secret = pyotp.random_base32()
        if role not in ROLE_DEFAULTS:
            raise ValueError("Administrator role is invalid")
        selected_permissions = normalize_permissions(permissions or ROLE_DEFAULTS[role])
        administrator = AdministratorModel(
            username=username,
            password_hash=hash_password(password),
            encrypted_totp_secret=self.cipher.encrypt(secret),
            totp_confirmed=False,
            is_active=False,
            role=role,
            permissions_json=selected_permissions,
        )
        db.add(administrator)
        db.flush()
        self._audit(
            db,
            acting_administrator.id,
            "administrator.create",
            correlation_id,
            metadata={"target_username": username},
        )
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Kenai VPN Admin")
        return TotpEnrollment(administrator.id, uri, self._build_qr(uri))

    def set_administrator_access(
        self,
        db: Session,
        *,
        target_id: str,
        role: str,
        permissions: list[str],
        acting_administrator: AdministratorModel,
        acting_password: str,
        acting_totp: str,
        current_session_id: str,
        correlation_id: str,
    ) -> None:
        self._verify_sensitive_action(acting_administrator, acting_password, acting_totp)
        if role not in ROLE_DEFAULTS:
            raise ValueError("Administrator role is invalid")
        target = db.get(AdministratorModel, target_id)
        if target is None:
            raise NotFoundError("Administrator not found")
        if target.id == acting_administrator.id and role != "super_admin":
            raise DomainConflictError("Super Admin cannot remove their own full access")
        target.role = role
        target.permissions_json = normalize_permissions(permissions or ROLE_DEFAULTS[role])
        for session in db.scalars(
            select(SessionModel).where(
                SessionModel.administrator_id == target.id,
                SessionModel.revoked_at.is_(None),
                SessionModel.id != current_session_id,
            )
        ):
            session.revoked_at = utc_now()
        self._audit(
            db,
            acting_administrator.id,
            "administrator.permissions_change",
            correlation_id,
            metadata={"target_username": target.username, "role": role},
        )

    def confirm_administrator_totp(
        self,
        db: Session,
        *,
        administrator_id: str,
        code: str,
        acting_administrator_id: str,
        correlation_id: str,
    ) -> None:
        administrator = db.get(AdministratorModel, administrator_id)
        if administrator is None:
            raise NotFoundError("Administrator not found")
        encrypted_secret = (
            administrator.pending_encrypted_totp_secret or administrator.encrypted_totp_secret
        )
        secret = self.cipher.decrypt(encrypted_secret)
        if not pyotp.TOTP(secret).verify(code.strip(), valid_window=1):
            raise ValueError("TOTP verification failed")
        administrator.totp_confirmed = True
        administrator.is_active = True
        if administrator.pending_encrypted_totp_secret is not None:
            administrator.encrypted_totp_secret = administrator.pending_encrypted_totp_secret
            administrator.pending_encrypted_totp_secret = None
        self._audit(
            db,
            acting_administrator_id,
            "administrator.totp_confirm",
            correlation_id,
            metadata={"target_username": administrator.username},
        )

    def change_password(
        self,
        db: Session,
        *,
        administrator: AdministratorModel,
        current_password: str,
        current_totp: str,
        new_password: str,
        current_session_id: str,
        correlation_id: str,
    ) -> None:
        self._verify_sensitive_action(administrator, current_password, current_totp)
        administrator.password_hash = hash_password(new_password)
        for session in db.scalars(
            select(SessionModel).where(
                SessionModel.administrator_id == administrator.id,
                SessionModel.id != current_session_id,
                SessionModel.revoked_at.is_(None),
            )
        ):
            session.revoked_at = utc_now()
        self._audit(
            db,
            administrator.id,
            "administrator.password_change",
            correlation_id,
        )

    def reset_totp(
        self,
        db: Session,
        *,
        administrator: AdministratorModel,
        current_password: str,
        current_totp: str,
        correlation_id: str,
    ) -> TotpEnrollment:
        self._verify_sensitive_action(administrator, current_password, current_totp)
        secret = pyotp.random_base32()
        administrator.pending_encrypted_totp_secret = self.cipher.encrypt(secret)
        self._audit(
            db,
            administrator.id,
            "administrator.totp_reset",
            correlation_id,
        )
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=administrator.username, issuer_name="Kenai VPN Admin"
        )
        return TotpEnrollment(administrator.id, uri, self._build_qr(uri))

    def set_administrator_active(
        self,
        db: Session,
        *,
        target_id: str,
        active: bool,
        acting_administrator: AdministratorModel,
        acting_password: str,
        acting_totp: str,
        correlation_id: str,
    ) -> None:
        self._verify_sensitive_action(acting_administrator, acting_password, acting_totp)
        target = db.get(AdministratorModel, target_id)
        if target is None:
            raise NotFoundError("Administrator not found")
        if target.id == acting_administrator.id and not active:
            raise DomainConflictError("You cannot disable your own administrator account")
        active_count = db.scalar(
            select(func.count(AdministratorModel.id)).where(AdministratorModel.is_active.is_(True))
        )
        if not active and int(active_count or 0) <= 1:
            raise DomainConflictError("The last active administrator cannot be disabled")
        if active and not target.totp_confirmed:
            raise DomainConflictError("TOTP enrollment must be confirmed first")
        target.is_active = active
        if not active:
            for session in target.sessions:
                if session.revoked_at is None:
                    session.revoked_at = utc_now()
        self._audit(
            db,
            acting_administrator.id,
            f"administrator.{'enable' if active else 'disable'}",
            correlation_id,
            metadata={"target_username": target.username},
        )

    def get_user(self, db: Session, user_id: str) -> UserModel:
        user = db.scalar(
            select(UserModel)
            .where(UserModel.id == user_id)
            .options(
                selectinload(UserModel.devices).selectinload(DeviceModel.wireguard),
                selectinload(UserModel.devices).selectinload(DeviceModel.amneziawg),
                selectinload(UserModel.devices).selectinload(DeviceModel.vless),
            )
        )
        if not user:
            raise NotFoundError("User not found")
        return user

    def device_runtime_status(self, device: DeviceModel) -> DeviceRuntimeStatus:
        return self.vpn.device_status(self._device_ref(device))

    def dashboard_runtime_summary(self, users: list[UserModel]) -> DashboardRuntimeSummary:
        configured_wireguard = 0
        configured_amneziawg = 0
        configured_vless = 0
        wireguard_with_handshake = 0
        amneziawg_with_handshake = 0
        received_bytes = 0
        transmitted_bytes = 0
        amneziawg_received_bytes = 0
        amneziawg_transmitted_bytes = 0
        vless_received_bytes = 0
        vless_transmitted_bytes = 0
        vless_connected = 0
        latest_handshake_at: datetime | None = None
        latest_amneziawg_handshake_at: datetime | None = None
        amneziawg_connected_user_ids: set[str] = set()
        vless_connected_user_ids: set[str] = set()
        for user in users:
            for device in user.devices:
                if device.wireguard and device.wireguard.status != LifecycleStatus.REVOKED.value:
                    configured_wireguard += 1
                if device.vless and device.vless.status != LifecycleStatus.REVOKED.value:
                    configured_vless += 1
                if device.amneziawg and device.amneziawg.status != LifecycleStatus.REVOKED.value:
                    configured_amneziawg += 1
                runtime = self.device_runtime_status(device)
                if runtime.wireguard is not None:
                    received_bytes += runtime.wireguard.received_bytes
                    transmitted_bytes += runtime.wireguard.transmitted_bytes
                    last_seen_at = runtime.wireguard.last_seen_at
                    if self._wireguard_is_connected(last_seen_at):
                        assert last_seen_at is not None
                        wireguard_with_handshake += 1
                        if latest_handshake_at is None or last_seen_at > latest_handshake_at:
                            latest_handshake_at = last_seen_at
                if runtime.amneziawg is not None:
                    amneziawg_received_bytes += runtime.amneziawg.received_bytes
                    amneziawg_transmitted_bytes += runtime.amneziawg.transmitted_bytes
                    if self._wireguard_is_connected(runtime.amneziawg.last_seen_at):
                        awg_last_seen_at = runtime.amneziawg.last_seen_at
                        assert awg_last_seen_at is not None
                        amneziawg_with_handshake += 1
                        amneziawg_connected_user_ids.add(user.id)
                        if (
                            latest_amneziawg_handshake_at is None
                            or awg_last_seen_at > latest_amneziawg_handshake_at
                        ):
                            latest_amneziawg_handshake_at = awg_last_seen_at
                if runtime.vless is not None:
                    vless_received_bytes += runtime.vless.received_bytes
                    vless_transmitted_bytes += runtime.vless.transmitted_bytes
                    if runtime.vless.current_connections > 0:
                        vless_connected += 1
                        vless_connected_user_ids.add(user.id)
        return DashboardRuntimeSummary(
            configured_wireguard=configured_wireguard,
            configured_amneziawg=configured_amneziawg,
            configured_vless=configured_vless,
            wireguard_with_handshake=wireguard_with_handshake,
            amneziawg_with_handshake=amneziawg_with_handshake,
            amneziawg_connected_users=len(amneziawg_connected_user_ids),
            vless_connected=vless_connected,
            vless_connected_users=len(vless_connected_user_ids),
            received_bytes=received_bytes,
            transmitted_bytes=transmitted_bytes,
            amneziawg_received_bytes=amneziawg_received_bytes,
            amneziawg_transmitted_bytes=amneziawg_transmitted_bytes,
            vless_received_bytes=vless_received_bytes,
            vless_transmitted_bytes=vless_transmitted_bytes,
            latest_handshake_at=latest_handshake_at,
            latest_amneziawg_handshake_at=latest_amneziawg_handshake_at,
        )

    def connected_wireguard_devices(self, users: list[UserModel]) -> list[ConnectedWireGuardDevice]:
        return self._connected_wireguard_like_devices(users, Protocol.WIREGUARD)

    def connected_amneziawg_devices(self, users: list[UserModel]) -> list[ConnectedWireGuardDevice]:
        return self._connected_wireguard_like_devices(users, Protocol.AMNEZIAWG)

    def _connected_wireguard_like_devices(
        self, users: list[UserModel], protocol: Protocol
    ) -> list[ConnectedWireGuardDevice]:
        connected: list[ConnectedWireGuardDevice] = []
        for user in users:
            for device in user.devices:
                credential = (
                    device.wireguard if protocol is Protocol.WIREGUARD else device.amneziawg
                )
                if credential is None or credential.status != LifecycleStatus.ACTIVE.value:
                    continue
                device_runtime = self.device_runtime_status(device)
                runtime = (
                    device_runtime.wireguard
                    if protocol is Protocol.WIREGUARD
                    else device_runtime.amneziawg
                )
                if runtime is None or not self._wireguard_is_connected(runtime.last_seen_at):
                    continue
                assert runtime.last_seen_at is not None
                connected.append(
                    ConnectedWireGuardDevice(
                        user_id=user.id,
                        user_name=user.display_name,
                        user_slug=user.slug,
                        device_name=device.display_name,
                        device_slug=device.slug,
                        is_subscription=user.activation_key_hash is not None,
                        last_handshake_at=runtime.last_seen_at,
                        received_bytes=runtime.received_bytes,
                        transmitted_bytes=runtime.transmitted_bytes,
                    )
                )
        return sorted(connected, key=lambda item: item.last_handshake_at, reverse=True)

    def connected_vless_devices(self, users: list[UserModel]) -> list[ConnectedVlessDevice]:
        devices: list[ConnectedVlessDevice] = []
        for user in users:
            for device in user.devices:
                if device.vless is None or device.vless.status == LifecycleStatus.REVOKED.value:
                    continue
                runtime = self.device_runtime_status(device).vless
                if runtime is None or runtime.current_connections <= 0:
                    continue
                devices.append(
                    ConnectedVlessDevice(
                        user_id=user.id,
                        user_name=user.display_name,
                        user_slug=user.slug,
                        device_name=device.display_name,
                        device_slug=device.slug,
                        is_subscription=user.activation_key_hash is not None,
                        current_connections=runtime.current_connections,
                        received_bytes=runtime.received_bytes,
                        transmitted_bytes=runtime.transmitted_bytes,
                    )
                )
        return sorted(
            devices,
            key=lambda item: item.received_bytes + item.transmitted_bytes,
            reverse=True,
        )

    def _wireguard_is_connected(self, last_handshake_at: datetime | None) -> bool:
        if last_handshake_at is None:
            return False
        if last_handshake_at.tzinfo is None:
            last_handshake_at = last_handshake_at.replace(tzinfo=UTC)
        cutoff = datetime.now(UTC) - timedelta(
            seconds=self.settings.wireguard_connected_window_seconds
        )
        return last_handshake_at >= cutoff

    def create_user(
        self,
        db: Session,
        *,
        slug: str | None,
        display_name: str,
        comment: str | None,
        administrator_id: str,
        correlation_id: str,
    ) -> UserModel:
        slug = validate_slug(slug or f"manual-{secrets.token_hex(8)}")
        display_name = validate_display_name(display_name)
        if db.scalar(select(UserModel.id).where(UserModel.slug == slug)):
            raise DomainConflictError("A user with this identifier already exists")
        user = UserModel(
            slug=slug, display_name=display_name, comment=(comment or "").strip() or None
        )
        db.add(user)
        db.flush()
        self._audit(
            db,
            administrator_id,
            "user.create",
            correlation_id,
            user_id=user.id,
            metadata={"slug": slug},
        )
        return user

    def create_subscription(
        self,
        db: Session,
        *,
        email: str,
        telegram_username: str,
        phone_number: str,
        comment: str,
        subscription_days: int | None,
        subscription_until: date | None,
        administrator_id: str,
        correlation_id: str,
        display_name: str = "",
        device_limit: int | None = None,
    ) -> SubscriptionCreationResult:
        email = email.strip().lower()
        telegram_username = telegram_username.strip().lstrip("@")
        phone_number = phone_number.strip()
        if email and (len(email) > 254 or "@" not in email):
            raise ValueError("Email is invalid")
        if len(telegram_username) > 64 or any(char.isspace() for char in telegram_username):
            raise ValueError("Telegram username is invalid")
        if len(phone_number) > 32:
            raise ValueError("Phone number is invalid")
        display_name = display_name.strip()
        if not display_name and not any((email, telegram_username, phone_number)):
            raise ValueError("A name or contact is required")
        display_name = validate_display_name(
            display_name or telegram_username or email or phone_number
        )
        protocols = self.settings.issuable_protocol_set
        if not protocols:
            raise ValueError("No active protocol is configured for new subscriptions")
        effective_device_limit = device_limit or self.settings.max_subscription_devices
        if (
            effective_device_limit < 1
            or effective_device_limit > self.settings.max_subscription_devices
        ):
            raise ValueError("Device limit is invalid")

        suffix = secrets.token_hex(6)
        slug = f"subscriber-{suffix}"
        activation_key = self._new_activation_key(db)
        subscription_expires_at = self.subscription_expiry(
            days=subscription_days, until=subscription_until
        )
        user = UserModel(
            slug=slug,
            display_name=display_name,
            email=email or None,
            telegram_username=telegram_username or None,
            phone_number=phone_number or None,
            comment=comment.strip() or None,
            activation_key_hash=hash_token(activation_key),
            encrypted_activation_key=self.cipher.encrypt(activation_key),
            subscription_expires_at=subscription_expires_at,
            device_limit=effective_device_limit,
        )
        db.add(user)
        db.flush()
        subscription = SubscriptionModel(
            user_id=user.id,
            status="active",
            starts_at=utc_now(),
            ends_at=subscription_expires_at,
            price_minor=0,
            currency="RUB",
            confirmed_at=utc_now(),
            confirmed_by_id=administrator_id,
            note="Ручное подтверждение администратором",
        )
        db.add(subscription)
        db.flush()
        db.add(
            SubscriptionEventModel(
                subscription_id=subscription.id,
                administrator_id=administrator_id,
                event_type="manual_confirm",
                new_status="active",
                details_json={"provider": None, "automatic_payment": False},
            )
        )
        device = self.create_device(
            db,
            user_id=user.id,
            slug="primary",
            display_name="Приложение",
            protocols=protocols,
            administrator_id=administrator_id,
            correlation_id=correlation_id,
        )
        self._audit(
            db,
            administrator_id,
            "subscription.create",
            correlation_id,
            user_id=user.id,
            device_id=device.id,
            metadata={"protocols": sorted(protocol.value for protocol in protocols)},
        )
        return SubscriptionCreationResult(user, activation_key, self._device_ref(device))

    def activation_key_for_admin(self, user: UserModel) -> str | None:
        if user.encrypted_activation_key is None:
            return None
        return self.cipher.decrypt(user.encrypted_activation_key)

    def activation_is_rate_limited(self, db: Session, remote_address: str) -> bool:
        cutoff = utc_now() - timedelta(minutes=self.settings.activation_window_minutes)
        failures = db.scalar(
            select(func.count(ActivationAttemptModel.id)).where(
                ActivationAttemptModel.remote_address == remote_address,
                ActivationAttemptModel.attempted_at >= cutoff,
                ActivationAttemptModel.succeeded.is_(False),
            )
        )
        return int(failures or 0) >= self.settings.activation_max_attempts

    @staticmethod
    def record_activation_attempt(db: Session, remote_address: str, succeeded: bool) -> None:
        db.add(ActivationAttemptModel(remote_address=remote_address, succeeded=succeeded))

    @staticmethod
    def _new_activation_key(db: Session) -> str:
        for _ in range(20):
            key = f"{secrets.randbelow(10**12):012d}"
            if not db.scalar(
                select(UserModel.id).where(UserModel.activation_key_hash == hash_token(key))
            ):
                return key
        raise RuntimeError("Could not allocate a unique activation key")

    def activate_account(self, db: Session, activation_key: str) -> ActivatedAccount | None:
        normalized = activation_key.strip()
        if not normalized or len(normalized) > 128:
            return None
        user = db.scalar(
            select(UserModel)
            .where(
                UserModel.activation_key_hash == hash_token(normalized),
                UserModel.status == LifecycleStatus.ACTIVE.value,
                UserModel.subscription_expires_at > utc_now(),
            )
            .options(
                selectinload(UserModel.devices).selectinload(DeviceModel.wireguard),
                selectinload(UserModel.devices).selectinload(DeviceModel.amneziawg),
                selectinload(UserModel.devices).selectinload(DeviceModel.vless),
            )
        )
        if user is None or user.subscription_expires_at is None:
            return None
        device = next((item for item in user.devices if item.slug == "primary"), None)
        if device is None or device.status != LifecycleStatus.ACTIVE.value:
            return None
        credentials = {
            Protocol.WIREGUARD: device.wireguard,
            Protocol.AMNEZIAWG: device.amneziawg,
            Protocol.VLESS: device.vless,
        }
        for protocol in self.settings.issuable_protocol_set:
            credential = credentials[protocol]
            if credential is None or credential.status != LifecycleStatus.ACTIVE.value:
                return None
        return ActivatedAccount(
            user_id=user.id,
            email=user.email,
            telegram_username=user.telegram_username,
            phone_number=user.phone_number,
            wireguard_config=(
                self.cipher.decrypt(device.wireguard.encrypted_client_config)
                if device.wireguard is not None
                else None
            ),
            amneziawg_config=(
                self.cipher.decrypt(device.amneziawg.encrypted_client_config)
                if device.amneziawg is not None
                else None
            ),
            vless_uri=(
                self.cipher.decrypt(device.vless.encrypted_client_uri)
                if device.vless is not None
                else None
            ),
            subscription_expires_at=user.subscription_expires_at,
        )

    def activate_subscription_device(
        self, db: Session, activation_key: str, installation_id: str
    ) -> tuple[ActivatedAccount, str | None, set[Protocol]] | None:
        """Issue independent enabled protocol credentials for one installation."""
        normalized = activation_key.strip()
        if not normalized or len(normalized) > 128:
            return None
        slug = validate_slug(f"app-{installation_id}")
        user = db.scalar(
            select(UserModel)
            .where(
                UserModel.activation_key_hash == hash_token(normalized),
                UserModel.status == LifecycleStatus.ACTIVE.value,
                UserModel.subscription_expires_at > utc_now(),
            )
            .options(
                selectinload(UserModel.devices).selectinload(DeviceModel.vless),
                selectinload(UserModel.devices).selectinload(DeviceModel.amneziawg),
            )
            .with_for_update()
        )
        if user is None or user.subscription_expires_at is None:
            return None
        device = next((item for item in user.devices if item.slug == slug), None)
        new_ref: str | None = None
        issued_protocols: set[Protocol] = set()
        app_protocols = self.settings.subscription_protocol_set & {
            Protocol.VLESS,
            Protocol.AMNEZIAWG,
        }
        if Protocol.VLESS not in app_protocols:
            raise RuntimeError("Application subscriptions require VLESS")
        if device is None:
            active_installs = sum(
                item.slug.startswith("app-") and item.status == LifecycleStatus.ACTIVE.value
                for item in user.devices
            )
            if active_installs >= min(user.device_limit, self.settings.max_subscription_devices):
                raise DomainConflictError("Device limit reached")
            device = DeviceModel(user_id=user.id, slug=slug, display_name="Приложение")
            db.add(device)
            db.flush()
            new_ref = f"{user.slug}-{slug}"
        if device.status != LifecycleStatus.ACTIVE.value:
            return None
        if new_ref is None and (
            device.vless is None or device.vless.status != LifecycleStatus.ACTIVE.value
        ):
            return None
        if new_ref is not None:
            issued_protocols = app_protocols
        elif Protocol.AMNEZIAWG in app_protocols and device.amneziawg is None:
            # Existing VLESS-only installations receive AWG without rotating
            # their VLESS UUID or requiring a new account key.
            issued_protocols = {Protocol.AMNEZIAWG}
        if issued_protocols:
            device_ref = new_ref or f"{user.slug}-{slug}"
            try:
                issued = self.vpn.issue(device_ref, issued_protocols)
                by_protocol = {item.protocol: item for item in issued}
                if len(issued) != len(issued_protocols) or set(by_protocol) != issued_protocols:
                    raise RuntimeError("VPN adapter returned invalid app credentials")
                if Protocol.VLESS in by_protocol:
                    vless = by_protocol[Protocol.VLESS]
                    device.vless = VlessCredentialModel(
                        client_uuid=vless.public_identifier,
                        encrypted_client_uri=self.cipher.encrypt(vless.client_material),
                    )
                if Protocol.AMNEZIAWG in by_protocol:
                    awg = by_protocol[Protocol.AMNEZIAWG]
                    device.amneziawg = AmneziaWgCredentialModel(
                        public_key=awg.public_identifier,
                        tunnel_address=awg.tunnel_address,
                        encrypted_client_config=self.cipher.encrypt(awg.client_material),
                    )
                db.flush()
            except Exception:
                self.compensate_device_creation(device_ref, issued_protocols)
                raise
            self._audit(
                db,
                None,
                "subscription.device.activate",
                str(uuid.uuid4()),
                user_id=user.id,
                device_id=device.id,
                metadata={"protocols": sorted(item.value for item in issued_protocols)},
            )
        if device.vless is None or device.vless.status != LifecycleStatus.ACTIVE.value:
            return None
        account = ActivatedAccount(
            user_id=user.id,
            email=user.email,
            telegram_username=user.telegram_username,
            phone_number=user.phone_number,
            wireguard_config=None,
            amneziawg_config=(
                self.cipher.decrypt(device.amneziawg.encrypted_client_config)
                if device.amneziawg is not None
                and device.amneziawg.status == LifecycleStatus.ACTIVE.value
                and Protocol.AMNEZIAWG in app_protocols
                else None
            ),
            vless_uri=self.cipher.decrypt(device.vless.encrypted_client_uri),
            subscription_expires_at=user.subscription_expires_at,
        )
        return (
            account,
            (new_ref or f"{user.slug}-{slug}") if issued_protocols else None,
            issued_protocols,
        )

    @staticmethod
    def subscription_expiry(*, days: int | None, until: date | None) -> datetime:
        if (days is None) == (until is None):
            raise ValueError("Choose either subscription days or an expiry date")
        now = datetime.now(UTC)
        if days is not None:
            if days < 1 or days > 3650:
                raise ValueError("Subscription duration is invalid")
            return (now + timedelta(days=days)).replace(tzinfo=None)
        assert until is not None
        moscow = ZoneInfo("Europe/Moscow")
        end_local = datetime.combine(until, time(23, 59, 59), tzinfo=moscow)
        result = end_local.astimezone(UTC)
        if result <= now:
            raise ValueError("Subscription expiry must be in the future")
        return result.replace(tzinfo=None)

    def renew_subscription(
        self,
        db: Session,
        *,
        user_id: str,
        subscription_days: int | None,
        subscription_until: date | None,
        administrator_id: str,
        correlation_id: str,
    ) -> None:
        user = self.get_user(db, user_id)
        if user.activation_key_hash is None or not user.devices:
            raise DomainConflictError("This user is not an application subscription")
        user.subscription_expires_at = self.subscription_expiry(
            days=subscription_days, until=subscription_until
        )
        subscription = db.scalar(
            select(SubscriptionModel).where(SubscriptionModel.user_id == user.id)
        )
        old_status = subscription.status if subscription is not None else None
        if subscription is None:
            subscription = SubscriptionModel(
                user_id=user.id,
                starts_at=utc_now(),
                ends_at=user.subscription_expires_at,
                price_minor=0,
                currency="RUB",
            )
            db.add(subscription)
            db.flush()
        subscription.status = "active"
        subscription.ends_at = user.subscription_expires_at
        subscription.confirmed_at = utc_now()
        subscription.confirmed_by_id = administrator_id
        db.add(
            SubscriptionEventModel(
                subscription_id=subscription.id,
                administrator_id=administrator_id,
                event_type="manual_renew",
                old_status=old_status,
                new_status="active",
                details_json={"provider": None, "automatic_payment": False},
            )
        )
        for device in user.devices:
            if device.status != LifecycleStatus.ACTIVE.value:
                continue
            protocols = self.settings.issuable_protocol_set
            for protocol in protocols:
                credential = self._credential(device, protocol)
                if credential is None or credential.status == LifecycleStatus.REVOKED.value:
                    self.issue_protocol(
                        db,
                        device_id=device.id,
                        protocol=protocol,
                        administrator_id=administrator_id,
                        correlation_id=correlation_id,
                    )
                elif credential.status == LifecycleStatus.DISABLED.value:
                    self.set_protocol_enabled(
                        db,
                        device_id=device.id,
                        protocol=protocol,
                        enabled=True,
                        administrator_id=administrator_id,
                        correlation_id=correlation_id,
                    )
        self._audit(
            db,
            administrator_id,
            "subscription.renew",
            correlation_id,
            user_id=user.id,
            metadata={"expires_at": user.subscription_expires_at.isoformat()},
        )

    def expired_subscription_targets(self, db: Session) -> list[tuple[str, Protocol]]:
        users = db.scalars(
            select(UserModel)
            .where(
                UserModel.activation_key_hash.is_not(None),
                UserModel.subscription_expires_at <= utc_now(),
            )
            .options(
                selectinload(UserModel.devices).selectinload(DeviceModel.wireguard),
                selectinload(UserModel.devices).selectinload(DeviceModel.amneziawg),
                selectinload(UserModel.devices).selectinload(DeviceModel.vless),
            )
        )
        targets: list[tuple[str, Protocol]] = []
        for user in users:
            for device in user.devices:
                for protocol in (Protocol.WIREGUARD, Protocol.AMNEZIAWG, Protocol.VLESS):
                    credential = self._credential(device, protocol)
                    if credential and credential.status == LifecycleStatus.ACTIVE.value:
                        targets.append((device.id, protocol))
        return targets

    def create_device(
        self,
        db: Session,
        *,
        user_id: str,
        slug: str | None,
        display_name: str,
        protocols: set[Protocol],
        administrator_id: str,
        correlation_id: str,
    ) -> DeviceModel:
        user = self.get_user(db, user_id)
        slug = validate_slug(slug or f"device-{secrets.token_hex(8)}")
        display_name = validate_display_name(display_name)
        if not protocols:
            raise ValueError("Select at least one protocol")
        if db.scalar(
            select(DeviceModel.id).where(DeviceModel.user_id == user.id, DeviceModel.slug == slug)
        ):
            raise DomainConflictError("This user already has a device with that identifier")
        device = DeviceModel(user_id=user.id, slug=slug, display_name=display_name)
        db.add(device)
        db.flush()
        device_ref = f"{user.slug}-{device.slug}"
        credentials = self.vpn.issue(device_ref, protocols)
        for credential in credentials:
            if credential.protocol is Protocol.WIREGUARD:
                if not credential.tunnel_address:
                    raise RuntimeError("WireGuard adapter did not return a tunnel address")
                device.wireguard = WireGuardCredentialModel(
                    public_key=credential.public_identifier,
                    tunnel_address=credential.tunnel_address,
                    encrypted_client_config=self.cipher.encrypt(credential.client_material),
                )
            elif credential.protocol is Protocol.AMNEZIAWG:
                if not credential.tunnel_address:
                    raise RuntimeError("AmneziaWG adapter did not return a tunnel address")
                device.amneziawg = AmneziaWgCredentialModel(
                    public_key=credential.public_identifier,
                    tunnel_address=credential.tunnel_address,
                    encrypted_client_config=self.cipher.encrypt(credential.client_material),
                )
            elif credential.protocol is Protocol.VLESS:
                device.vless = VlessCredentialModel(
                    client_uuid=credential.public_identifier,
                    encrypted_client_uri=self.cipher.encrypt(credential.client_material),
                )
        self._audit(
            db,
            administrator_id,
            "device.create",
            correlation_id,
            user_id=user.id,
            device_id=device.id,
            metadata={"protocols": sorted(protocol.value for protocol in protocols)},
        )
        return device

    def compensate_device_creation(self, device_ref: str, protocols: set[Protocol]) -> None:
        failures: list[Protocol] = []
        for protocol in sorted(protocols, key=lambda value: value.value):
            try:
                self.vpn.revoke(device_ref, protocol)
            except Exception:
                failures.append(protocol)
        if failures:
            failed_names = ", ".join(protocol.value for protocol in failures)
            raise RuntimeError(f"Failed to compensate protocols: {failed_names}")

    def set_protocol_enabled(
        self,
        db: Session,
        *,
        device_id: str,
        protocol: Protocol,
        enabled: bool,
        administrator_id: str | None,
        correlation_id: str,
    ) -> None:
        device = self._get_device(db, device_id)
        credential = self._credential(device, protocol)
        if not credential:
            raise NotFoundError("Protocol is not configured for this device")
        if credential.status == LifecycleStatus.REVOKED.value:
            raise DomainConflictError("Revoked credentials cannot be enabled")
        self.vpn.set_enabled(self._device_ref(device), protocol, enabled)
        credential.status = (
            LifecycleStatus.ACTIVE.value if enabled else LifecycleStatus.DISABLED.value
        )
        self._audit(
            db,
            administrator_id,
            f"protocol.{'enable' if enabled else 'disable'}",
            correlation_id,
            user_id=device.user_id,
            device_id=device.id,
            metadata={"protocol": protocol.value},
        )

    def issue_protocol(
        self,
        db: Session,
        *,
        device_id: str,
        protocol: Protocol,
        administrator_id: str,
        correlation_id: str,
    ) -> None:
        device = self._get_device(db, device_id)
        existing = self._credential(device, protocol)
        if existing and existing.status != LifecycleStatus.REVOKED.value:
            raise DomainConflictError("Protocol credentials already exist")
        issued = self.vpn.issue(self._device_ref(device), {protocol})
        if len(issued) != 1 or issued[0].protocol is not protocol:
            raise RuntimeError("VPN adapter returned an invalid credential result")
        credential = issued[0]
        if protocol is Protocol.WIREGUARD:
            if not credential.tunnel_address:
                raise RuntimeError("WireGuard adapter did not return a tunnel address")
            if device.wireguard:
                device.wireguard.public_key = credential.public_identifier
                device.wireguard.tunnel_address = credential.tunnel_address
                device.wireguard.encrypted_client_config = self.cipher.encrypt(
                    credential.client_material
                )
                device.wireguard.status = LifecycleStatus.ACTIVE.value
                device.wireguard.last_handshake_at = None
                device.wireguard.received_bytes = 0
                device.wireguard.transmitted_bytes = 0
            else:
                device.wireguard = WireGuardCredentialModel(
                    public_key=credential.public_identifier,
                    tunnel_address=credential.tunnel_address,
                    encrypted_client_config=self.cipher.encrypt(credential.client_material),
                )
        elif protocol is Protocol.AMNEZIAWG:
            if not credential.tunnel_address:
                raise RuntimeError("AmneziaWG adapter did not return a tunnel address")
            if device.amneziawg:
                device.amneziawg.public_key = credential.public_identifier
                device.amneziawg.tunnel_address = credential.tunnel_address
                device.amneziawg.encrypted_client_config = self.cipher.encrypt(
                    credential.client_material
                )
                device.amneziawg.status = LifecycleStatus.ACTIVE.value
                device.amneziawg.last_handshake_at = None
                device.amneziawg.received_bytes = 0
                device.amneziawg.transmitted_bytes = 0
            else:
                device.amneziawg = AmneziaWgCredentialModel(
                    public_key=credential.public_identifier,
                    tunnel_address=credential.tunnel_address,
                    encrypted_client_config=self.cipher.encrypt(credential.client_material),
                )
        elif device.vless:
            device.vless.client_uuid = credential.public_identifier
            device.vless.encrypted_client_uri = self.cipher.encrypt(credential.client_material)
            device.vless.status = LifecycleStatus.ACTIVE.value
            device.vless.last_seen_at = None
            device.vless.received_bytes = 0
            device.vless.transmitted_bytes = 0
        else:
            device.vless = VlessCredentialModel(
                client_uuid=credential.public_identifier,
                encrypted_client_uri=self.cipher.encrypt(credential.client_material),
            )
        self._audit(
            db,
            administrator_id,
            "protocol.issue",
            correlation_id,
            user_id=device.user_id,
            device_id=device.id,
            metadata={"protocol": protocol.value, "reissued": existing is not None},
        )

    def revoke_protocol(
        self,
        db: Session,
        *,
        device_id: str,
        protocol: Protocol,
        administrator_id: str,
        correlation_id: str,
    ) -> None:
        device = self._get_device(db, device_id)
        credential = self._credential(device, protocol)
        if not credential:
            raise NotFoundError("Protocol is not configured for this device")
        self.vpn.revoke(self._device_ref(device), protocol)
        credential.status = LifecycleStatus.REVOKED.value
        self._audit(
            db,
            administrator_id,
            "protocol.revoke",
            correlation_id,
            user_id=device.user_id,
            device_id=device.id,
            metadata={"protocol": protocol.value},
        )

    def delete_device(
        self,
        db: Session,
        *,
        device_id: str,
        administrator_id: str,
        correlation_id: str,
    ) -> str:
        device = self._get_device(db, device_id)
        credentials = [
            credential
            for credential in (device.wireguard, device.amneziawg, device.vless)
            if credential
        ]
        if any(credential.status != LifecycleStatus.REVOKED.value for credential in credentials):
            raise DomainConflictError("Revoke every device protocol before deletion")
        user_id = device.user_id
        self._audit(
            db,
            administrator_id,
            "device.delete",
            correlation_id,
            user_id=user_id,
            metadata={"device_slug": device.slug},
        )
        db.delete(device)
        return user_id

    def device_revocation_targets(self, db: Session, device_id: str) -> tuple[str, list[Protocol]]:
        device = self._get_device(db, device_id)
        targets: list[Protocol] = []
        if device.wireguard and device.wireguard.status != LifecycleStatus.REVOKED.value:
            targets.append(Protocol.WIREGUARD)
        if device.amneziawg and device.amneziawg.status != LifecycleStatus.REVOKED.value:
            targets.append(Protocol.AMNEZIAWG)
        if device.vless and device.vless.status != LifecycleStatus.REVOKED.value:
            targets.append(Protocol.VLESS)
        return device.user_id, targets

    def delete_user(
        self,
        db: Session,
        *,
        user_id: str,
        administrator_id: str,
        correlation_id: str,
    ) -> None:
        user = self.get_user(db, user_id)
        for device in user.devices:
            credentials = [
                credential
                for credential in (device.wireguard, device.amneziawg, device.vless)
                if credential
            ]
            if any(
                credential.status != LifecycleStatus.REVOKED.value for credential in credentials
            ):
                raise DomainConflictError(
                    "Revoke every protocol on every device before deleting the user"
                )
        self._audit(
            db,
            administrator_id,
            "user.delete",
            correlation_id,
            metadata={"user_slug": user.slug, "device_count": len(user.devices)},
        )
        db.delete(user)

    def user_revocation_targets(self, db: Session, user_id: str) -> list[tuple[str, Protocol]]:
        user = self.get_user(db, user_id)
        targets: list[tuple[str, Protocol]] = []
        for device in user.devices:
            if (
                device.wireguard is not None
                and device.wireguard.status != LifecycleStatus.REVOKED.value
            ):
                targets.append((device.id, Protocol.WIREGUARD))
            if device.vless is not None and device.vless.status != LifecycleStatus.REVOKED.value:
                targets.append((device.id, Protocol.VLESS))
            if (
                device.amneziawg is not None
                and device.amneziawg.status != LifecycleStatus.REVOKED.value
            ):
                targets.append((device.id, Protocol.AMNEZIAWG))
        return targets

    def create_package(
        self,
        db: Session,
        *,
        device_id: str,
        protocols: set[Protocol],
        administrator_id: str,
        correlation_id: str,
    ) -> ProvisioningResult:
        device = self._get_device(db, device_id)
        files: dict[str, str | bytes] = {}
        if Protocol.WIREGUARD in protocols:
            if not device.wireguard or device.wireguard.status == LifecycleStatus.REVOKED.value:
                raise DomainConflictError("Active WireGuard credentials are unavailable")
            wireguard_config = self.cipher.decrypt(device.wireguard.encrypted_client_config)
            files["wireguard.conf"] = wireguard_config
            files["wireguard-qr.png"] = self._build_qr(wireguard_config)
        if Protocol.VLESS in protocols:
            if not device.vless or device.vless.status == LifecycleStatus.REVOKED.value:
                raise DomainConflictError("Active VLESS credentials are unavailable")
            vless_uri = self.cipher.decrypt(device.vless.encrypted_client_uri)
            files["vless.txt"] = vless_uri
            files["vless-qr.png"] = self._build_qr(vless_uri)
        if Protocol.AMNEZIAWG in protocols:
            if not device.amneziawg or device.amneziawg.status == LifecycleStatus.REVOKED.value:
                raise DomainConflictError("Active AmneziaWG credentials are unavailable")
            amneziawg_config = self.cipher.decrypt(device.amneziawg.encrypted_client_config)
            files["amneziawg.conf"] = amneziawg_config
            files["amneziawg-qr.png"] = self._build_qr(amneziawg_config)
        if not files:
            raise ValueError("Select at least one available protocol")
        files["README.txt"] = (
            "Kenai VPN access package\n"
            f"Device: {device.user.display_name} / {device.display_name}\n"
            "Keep these files private. Do not reuse them on another device.\n"
        )
        payload = self._build_zip(files)
        expires_at = utc_now() + timedelta(minutes=self.settings.provisioning_ttl_minutes)
        package = ProvisioningPackageModel(
            device_id=device.id,
            includes_wireguard=Protocol.WIREGUARD in protocols,
            includes_amneziawg=Protocol.AMNEZIAWG in protocols,
            includes_vless=Protocol.VLESS in protocols,
            encrypted_payload=self.cipher.encrypt(payload.hex()),
            expires_at=expires_at,
        )
        token = secrets.token_urlsafe(48)
        package.tokens.append(
            OneTimeTokenModel(token_hash=hash_token(token), expires_at=expires_at)
        )
        db.add(package)
        db.flush()
        self._audit(
            db,
            administrator_id,
            "package.create",
            correlation_id,
            user_id=device.user_id,
            device_id=device.id,
            metadata={"protocols": sorted(protocol.value for protocol in protocols)},
        )
        return ProvisioningResult(token, package.id, expires_at)

    def qr_code(
        self,
        db: Session,
        *,
        device_id: str,
        protocol: Protocol,
        administrator_id: str,
        correlation_id: str,
    ) -> bytes:
        device = self._get_device(db, device_id)
        if protocol is Protocol.WIREGUARD:
            if not device.wireguard or device.wireguard.status == LifecycleStatus.REVOKED.value:
                raise NotFoundError("WireGuard credentials are unavailable")
            material = self.cipher.decrypt(device.wireguard.encrypted_client_config)
        elif protocol is Protocol.AMNEZIAWG:
            if not device.amneziawg or device.amneziawg.status == LifecycleStatus.REVOKED.value:
                raise NotFoundError("AmneziaWG credentials are unavailable")
            material = self.cipher.decrypt(device.amneziawg.encrypted_client_config)
        else:
            if not device.vless or device.vless.status == LifecycleStatus.REVOKED.value:
                raise NotFoundError("VLESS credentials are unavailable")
            material = self.cipher.decrypt(device.vless.encrypted_client_uri)
        self._audit(
            db,
            administrator_id,
            "credential.qr_view",
            correlation_id,
            user_id=device.user_id,
            device_id=device.id,
            metadata={"protocol": protocol.value},
        )
        return self._build_qr(material)

    def consume_package(
        self,
        db: Session,
        token: str,
        *,
        administrator_id: str,
        correlation_id: str,
    ) -> tuple[bytes, str]:
        token_model = db.scalar(
            select(OneTimeTokenModel)
            .where(OneTimeTokenModel.token_hash == hash_token(token))
            .options(
                selectinload(OneTimeTokenModel.package)
                .selectinload(ProvisioningPackageModel.device)
                .selectinload(DeviceModel.user)
            )
        )
        if not token_model:
            raise NotFoundError("Provisioning package is unavailable")
        token_model.attempts += 1
        package = token_model.package
        now = utc_now()
        if token_model.consumed_at or package.status != PackageStatus.READY.value:
            raise DomainConflictError("Provisioning package has already been used")
        if naive_utc(token_model.expires_at) <= now or naive_utc(package.expires_at) <= now:
            package.status = PackageStatus.EXPIRED.value
            raise DomainConflictError("Provisioning package has expired")
        payload = bytes.fromhex(self.cipher.decrypt(package.encrypted_payload))
        token_model.consumed_at = now
        package.downloaded_at = now
        package.status = PackageStatus.CONSUMED.value
        package.encrypted_payload = self.cipher.encrypt("")
        self._audit(
            db,
            administrator_id,
            "package.download",
            correlation_id,
            user_id=package.device.user_id,
            device_id=package.device_id,
            metadata={
                "includes_wireguard": package.includes_wireguard,
                "includes_amneziawg": package.includes_amneziawg,
                "includes_vless": package.includes_vless,
            },
        )
        filename = f"{package.device.user.slug}-{package.device.slug}-vpn.zip"
        return payload, filename

    def _get_device(self, db: Session, device_id: str) -> DeviceModel:
        device = db.scalar(
            select(DeviceModel)
            .where(DeviceModel.id == device_id)
            .options(
                selectinload(DeviceModel.user),
                selectinload(DeviceModel.wireguard),
                selectinload(DeviceModel.amneziawg),
                selectinload(DeviceModel.vless),
            )
        )
        if not device:
            raise NotFoundError("Device not found")
        return device

    @staticmethod
    def _device_ref(device: DeviceModel) -> str:
        return f"{device.user.slug}-{device.slug}"

    @staticmethod
    def _credential(
        device: DeviceModel, protocol: Protocol
    ) -> WireGuardCredentialModel | AmneziaWgCredentialModel | VlessCredentialModel | None:
        if protocol is Protocol.WIREGUARD:
            return device.wireguard
        if protocol is Protocol.AMNEZIAWG:
            return device.amneziawg
        return device.vless

    @staticmethod
    def _build_zip(files: Mapping[str, str | bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return buffer.getvalue()

    @staticmethod
    def _build_qr(material: str) -> bytes:
        image = qrcode.make(material)
        buffer = io.BytesIO()
        image.save(buffer)
        return buffer.getvalue()

    def _verify_sensitive_action(
        self, administrator: AdministratorModel, password: str, totp_code: str
    ) -> None:
        secret = self.cipher.decrypt(administrator.encrypted_totp_secret)
        if not verify_password(administrator.password_hash, password) or not pyotp.TOTP(
            secret
        ).verify(totp_code.strip(), valid_window=1):
            raise ValueError("Administrator verification failed")

    @staticmethod
    def _audit(
        db: Session,
        administrator_id: str | None,
        action: str,
        correlation_id: str,
        *,
        user_id: str | None = None,
        device_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        safe_metadata = json.loads(json.dumps(metadata or {}))
        db.add(
            AuditEventModel(
                administrator_id=administrator_id,
                user_id=user_id,
                device_id=device_id,
                action=action,
                outcome=AuditOutcome.SUCCESS.value,
                correlation_id=correlation_id or str(uuid.uuid4()),
                metadata_json=safe_metadata,
            )
        )
