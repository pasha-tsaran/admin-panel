from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kenai_vpn_admin.domain.enums import (
    LifecycleStatus,
    OperationalStatus,
    PackageStatus,
)
from kenai_vpn_admin.infrastructure.database import Base


def uuid_text() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    # SQLite stores datetimes without timezone information. The project stores
    # every database timestamp as naive UTC and only localizes it at UI edges.
    return datetime.now(UTC).replace(tzinfo=None)


def naive_utc(value: datetime) -> datetime:
    """Normalize SQLite-naive and PostgreSQL-aware timestamps to naive UTC."""
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class AdministratorModel(Base, TimestampMixin):
    __tablename__ = "administrators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    encrypted_totp_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    pending_encrypted_totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="super_admin", index=True)
    permissions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list[SessionModel]] = relationship(
        back_populates="administrator", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEventModel]] = relationship(back_populates="administrator")


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    administrator_id: Mapped[str] = mapped_column(
        ForeignKey("administrators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    remote_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))

    administrator: Mapped[AdministratorModel] = relationship(back_populates="sessions")


class UserModel(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(String(254))
    telegram_username: Mapped[str | None] = mapped_column(String(64))
    phone_number: Mapped[str | None] = mapped_column(String(32))
    activation_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    encrypted_activation_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    subscription_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    activation_key_consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )

    devices: Mapped[list[DeviceModel]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="DeviceModel.created_at"
    )
    audit_events: Mapped[list[AuditEventModel]] = relationship(back_populates="user")

    __table_args__ = (
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_users_status"),
        CheckConstraint("device_limit >= 1 AND device_limit <= 1000", name="ck_users_device_limit"),
    )


class ActivationAttemptModel(Base):
    __tablename__ = "activation_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    remote_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)


class DeviceModel(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )

    user: Mapped[UserModel] = relationship(back_populates="devices")
    wireguard: Mapped[WireGuardCredentialModel | None] = relationship(
        back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    amneziawg: Mapped[AmneziaWgCredentialModel | None] = relationship(
        back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    vless: Mapped[VlessCredentialModel | None] = relationship(
        back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    packages: Mapped[list[ProvisioningPackageModel]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEventModel]] = relationship(back_populates="device")
    access_tokens: Mapped[list[DeviceAccessTokenModel]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    route_credentials: Mapped[list[RouteCredentialModel]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("user_id", "slug", name="uq_devices_user_slug"),
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_devices_status"),
    )


class VpnNodeModel(Base, TimestampMixin):
    __tablename__ = "vpn_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(2), nullable=False)
    city: Mapped[str] = mapped_column(String(120), nullable=False)
    public_endpoint: Mapped[str] = mapped_column(String(253), nullable=False)
    agent_endpoint: Mapped[str | None] = mapped_column(String(512))
    certificate_sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=OperationalStatus.OFFLINE.value, index=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    load_percent: Mapped[int | None] = mapped_column(Integer)
    current_users: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transmitted_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    config_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    ingress_locations: Mapped[list[VpnLocationModel]] = relationship(
        back_populates="ingress_node", foreign_keys="VpnLocationModel.ingress_node_id"
    )
    exit_locations: Mapped[list[VpnLocationModel]] = relationship(
        back_populates="exit_node", foreign_keys="VpnLocationModel.exit_node_id"
    )

    __table_args__ = (
        CheckConstraint("role IN ('ingress','exit')", name="ck_vpn_nodes_role"),
        CheckConstraint(
            "status IN ('online','degraded','offline','disabled')",
            name="ck_vpn_nodes_status",
        ),
        CheckConstraint("length(country_code) = 2", name="ck_vpn_nodes_country_code"),
        CheckConstraint(
            "load_percent IS NULL OR (load_percent >= 0 AND load_percent <= 100)",
            name="ck_vpn_nodes_load_percent",
        ),
        CheckConstraint("current_users >= 0", name="ck_vpn_nodes_current_users"),
        CheckConstraint("received_bytes >= 0", name="ck_vpn_nodes_received_bytes"),
        CheckConstraint("transmitted_bytes >= 0", name="ck_vpn_nodes_transmitted_bytes"),
        CheckConstraint("config_revision >= 0", name="ck_vpn_nodes_config_revision"),
    )


class VpnLocationModel(Base, TimestampMixin):
    __tablename__ = "vpn_locations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    country_code: Mapped[str] = mapped_column(String(2), nullable=False)
    country_name: Mapped[str] = mapped_column(String(120), nullable=False)
    city: Mapped[str] = mapped_column(String(120), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    ingress_node_id: Mapped[str] = mapped_column(
        ForeignKey("vpn_nodes.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    exit_node_id: Mapped[str] = mapped_column(
        ForeignKey("vpn_nodes.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    outbound_tag: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    encrypted_exit_link: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=OperationalStatus.OFFLINE.value, index=True
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    last_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    is_recommended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    ingress_node: Mapped[VpnNodeModel] = relationship(
        back_populates="ingress_locations", foreign_keys=[ingress_node_id]
    )
    exit_node: Mapped[VpnNodeModel] = relationship(
        back_populates="exit_locations", foreign_keys=[exit_node_id]
    )
    route_credentials: Mapped[list[RouteCredentialModel]] = relationship(
        back_populates="location", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("length(country_code) = 2", name="ck_vpn_locations_country_code"),
        CheckConstraint(
            "status IN ('online','degraded','offline','disabled')",
            name="ck_vpn_locations_status",
        ),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_location_latency"),
        CheckConstraint("sort_order >= 0", name="ck_location_sort_order"),
    )


class DeviceAccessTokenModel(Base):
    __tablename__ = "device_access_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    device: Mapped[DeviceModel] = relationship(back_populates="access_tokens")


class RouteCredentialModel(Base, TimestampMixin):
    __tablename__ = "route_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    location_id: Mapped[str] = mapped_column(
        ForeignKey("vpn_locations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    client_email: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    encrypted_client_uri: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )

    device: Mapped[DeviceModel] = relationship(back_populates="route_credentials")
    location: Mapped[VpnLocationModel] = relationship(back_populates="route_credentials")

    __table_args__ = (
        UniqueConstraint("device_id", "location_id", name="uq_route_credentials_device_location"),
        CheckConstraint(
            "status IN ('active','disabled','revoked')", name="ck_route_credentials_status"
        ),
    )


class WireGuardCredentialModel(Base, TimestampMixin):
    __tablename__ = "wireguard_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    tunnel_address: Mapped[str] = mapped_column(String(18), unique=True, nullable=False)
    encrypted_client_config: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )
    last_handshake_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transmitted_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    device: Mapped[DeviceModel] = relationship(back_populates="wireguard")

    __table_args__ = (
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_wg_status"),
        CheckConstraint("received_bytes >= 0", name="ck_wg_received_nonnegative"),
        CheckConstraint("transmitted_bytes >= 0", name="ck_wg_transmitted_nonnegative"),
    )


class VlessCredentialModel(Base, TimestampMixin):
    __tablename__ = "vless_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    client_uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    encrypted_client_uri: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transmitted_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    device: Mapped[DeviceModel] = relationship(back_populates="vless")

    __table_args__ = (
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_vless_status"),
        CheckConstraint("received_bytes >= 0", name="ck_vless_received_nonnegative"),
        CheckConstraint("transmitted_bytes >= 0", name="ck_vless_transmitted_nonnegative"),
    )


class AmneziaWgCredentialModel(Base, TimestampMixin):
    __tablename__ = "amneziawg_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    tunnel_address: Mapped[str] = mapped_column(String(18), unique=True, nullable=False)
    encrypted_client_config: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=LifecycleStatus.ACTIVE.value, index=True
    )
    last_handshake_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transmitted_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    device: Mapped[DeviceModel] = relationship(back_populates="amneziawg")

    __table_args__ = (
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_awg_status"),
        CheckConstraint("received_bytes >= 0", name="ck_awg_received_nonnegative"),
        CheckConstraint("transmitted_bytes >= 0", name="ck_awg_transmitted_nonnegative"),
    )


class ProvisioningPackageModel(Base):
    __tablename__ = "provisioning_packages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    includes_wireguard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    includes_amneziawg: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    includes_vless: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PackageStatus.READY.value, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device: Mapped[DeviceModel] = relationship(back_populates="packages")
    tokens: Mapped[list[OneTimeTokenModel]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "includes_wireguard OR includes_amneziawg OR includes_vless",
            name="ck_package_has_protocol",
        ),
        CheckConstraint(
            "status IN ('ready','consumed','expired','purged')", name="ck_package_status"
        ),
    )


class OneTimeTokenModel(Base):
    __tablename__ = "one_time_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    package_id: Mapped[str] = mapped_column(
        ForeignKey("provisioning_packages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    package: Mapped[ProvisioningPackageModel] = relationship(back_populates="tokens")

    __table_args__ = (CheckConstraint("attempts >= 0", name="ck_token_attempts_nonnegative"),)


class SubscriptionPlanModel(Base, TimestampMixin):
    __tablename__ = "subscription_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    price_minor: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="RUB")
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    __table_args__ = (
        CheckConstraint("duration_days > 0", name="ck_subscription_plans_duration"),
        CheckConstraint("price_minor >= 0", name="ck_subscription_plans_price"),
        CheckConstraint("device_limit > 0", name="ck_subscription_plans_device_limit"),
        CheckConstraint("length(currency) = 3", name="ck_subscription_plans_currency"),
    )


class SubscriptionModel(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True
    )
    plan_id: Mapped[str | None] = mapped_column(
        ForeignKey("subscription_plans.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    price_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="RUB")
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmed_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )
    note: Mapped[str | None] = mapped_column(Text)

    user: Mapped[UserModel] = relationship()
    plan: Mapped[SubscriptionPlanModel | None] = relationship()

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','active','expired','cancelled')",
            name="ck_subscriptions_status",
        ),
        CheckConstraint("price_minor >= 0", name="ck_subscriptions_price"),
        CheckConstraint("length(currency) = 3", name="ck_subscriptions_currency"),
        Index("ix_subscriptions_status_ends", "status", "ends_at"),
    )


class SubscriptionEventModel(Base):
    __tablename__ = "subscription_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    subscription_id: Mapped[str] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    administrator_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    old_status: Mapped[str | None] = mapped_column(String(24))
    new_status: Mapped[str] = mapped_column(String(24), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ServerMetricModel(Base):
    __tablename__ = "server_metrics"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    node_id: Mapped[str | None] = mapped_column(
        ForeignKey("vpn_nodes.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="primary")
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    health_status: Mapped[str | None] = mapped_column(String(16))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    load_percent: Mapped[int | None] = mapped_column(Integer)
    cpu_percent: Mapped[int | None] = mapped_column(Integer)
    memory_percent: Mapped[int | None] = mapped_column(Integer)
    disk_percent: Mapped[int | None] = mapped_column(Integer)
    current_connections: Mapped[int | None] = mapped_column(Integer)
    received_bytes: Mapped[int | None] = mapped_column(BigInteger)
    transmitted_bytes: Mapped[int | None] = mapped_column(BigInteger)

    __table_args__ = (
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_metrics_latency"),
        CheckConstraint(
            "load_percent IS NULL OR (load_percent >= 0 AND load_percent <= 100)",
            name="ck_metrics_load",
        ),
        CheckConstraint(
            "cpu_percent IS NULL OR (cpu_percent >= 0 AND cpu_percent <= 100)",
            name="ck_metrics_cpu",
        ),
        CheckConstraint(
            "memory_percent IS NULL OR (memory_percent >= 0 AND memory_percent <= 100)",
            name="ck_metrics_memory",
        ),
        CheckConstraint(
            "disk_percent IS NULL OR (disk_percent >= 0 AND disk_percent <= 100)",
            name="ck_metrics_disk",
        ),
        CheckConstraint(
            "current_connections IS NULL OR current_connections >= 0",
            name="ck_metrics_connections",
        ),
        CheckConstraint(
            "received_bytes IS NULL OR received_bytes >= 0", name="ck_metrics_received"
        ),
        CheckConstraint(
            "transmitted_bytes IS NULL OR transmitted_bytes >= 0",
            name="ck_metrics_transmitted",
        ),
        Index("ix_server_metrics_node_captured", "node_id", "captured_at"),
        Index("ix_server_metrics_source_captured", "source", "captured_at"),
    )


class SystemSettingModel(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    updated_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )


class TelegramRecipientModel(Base, TimestampMixin):
    __tablename__ = "telegram_recipients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    chat_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    categories_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)


class NotificationDeliveryModel(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    recipient_id: Mapped[str | None] = mapped_column(
        ForeignKey("telegram_recipients.id", ondelete="SET NULL"), index=True
    )
    category: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response_code: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(80))

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','retry','sent','failed')",
            name="ck_notification_delivery_status",
        ),
        CheckConstraint("attempts >= 0 AND attempts <= 5", name="ck_notification_attempts"),
    )


class ApiTokenModel(Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    permissions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class NodeOnboardingModel(Base):
    __tablename__ = "node_onboarding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    administrator_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )
    node_slug: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    expected_certificate_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    stage: Mapped[str] = mapped_column(
        String(32), nullable=False, default="connectivity", index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    preview_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "stage IN ('connectivity','identity','preview','registration',"
            "'health','complete','rollback')",
            name="ck_node_onboarding_stage",
        ),
        CheckConstraint(
            "status IN ('pending','running','passed','failed','rolled_back')",
            name="ck_node_onboarding_status",
        ),
    )


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    administrator_id: Mapped[str | None] = mapped_column(
        ForeignKey("administrators.id", ondelete="SET NULL"), index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    administrator: Mapped[AdministratorModel | None] = relationship(back_populates="audit_events")
    user: Mapped[UserModel | None] = relationship(back_populates="audit_events")
    device: Mapped[DeviceModel | None] = relationship(back_populates="audit_events")

    __table_args__ = (
        CheckConstraint("outcome IN ('success','denied','failure')", name="ck_audit_outcome"),
        Index("ix_audit_actor_time", "administrator_id", "occurred_at"),
    )


class LoginAttemptModel(Base):
    __tablename__ = "login_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    username: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    remote_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index("ix_login_attempt_lookup", "username", "remote_address", "attempted_at"),
    )
