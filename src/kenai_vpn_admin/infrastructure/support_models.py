"""Support persistence; independent from VPN credentials and device provisioning."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from kenai_vpn_admin.infrastructure.database import Base
from kenai_vpn_admin.infrastructure.models import utc_now, uuid_text


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True
    )
    guest_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    guest_ip_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    guest_name: Mapped[str | None] = mapped_column(String(80))
    request_id: Mapped[str] = mapped_column(String(36))
    key_mask: Mapped[str] = mapped_column(String(12))
    subject: Mapped[str] = mapped_column(String(120))
    client_version: Mapped[str] = mapped_column(String(40))
    platform: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16), default="waiting")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        UniqueConstraint("user_id", "request_id", name="uq_support_request"),
        CheckConstraint(
            "(user_id IS NOT NULL AND guest_token_hash IS NULL) OR "
            "(user_id IS NULL AND guest_token_hash IS NOT NULL)",
            name="ck_support_owner",
        ),
        CheckConstraint("status IN ('waiting','in_progress','closed')", name="ck_support_status"),
        Index(
            "uq_support_active_user",
            "user_id",
            unique=True,
            sqlite_where=text("status != 'closed'"),
            postgresql_where=text("status != 'closed'"),
        ),
        Index(
            "uq_support_guest_request",
            "guest_token_hash",
            "request_id",
            unique=True,
            sqlite_where=text("guest_token_hash IS NOT NULL"),
            postgresql_where=text("guest_token_hash IS NOT NULL"),
        ),
        Index(
            "uq_support_active_guest",
            "guest_token_hash",
            unique=True,
            sqlite_where=text("guest_token_hash IS NOT NULL AND status != 'closed'"),
            postgresql_where=text("guest_token_hash IS NOT NULL AND status != 'closed'"),
        ),
    )


class SupportMessage(Base):
    __tablename__ = "support_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(
        ForeignKey("support_tickets.id", ondelete="CASCADE"), index=True
    )
    request_id: Mapped[str] = mapped_column(String(80))
    author: Mapped[str] = mapped_column(String(16))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        UniqueConstraint("ticket_id", "request_id", name="uq_support_message_request"),
        CheckConstraint("author IN ('user','support','system')", name="ck_support_author"),
    )


class SupportOutbox(Base):
    __tablename__ = "support_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(
        ForeignKey("support_tickets.id", ondelete="CASCADE"), index=True
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSON)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    telegram_message_id: Mapped[int | None] = mapped_column(BigInteger, index=True)


class SupportTelegramState(Base):
    __tablename__ = "support_telegram_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    next_update_id: Mapped[int] = mapped_column(BigInteger, default=0)


class SupportOperatorSession(Base):
    __tablename__ = "support_operator_sessions"
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    operator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Retain a closed/deleted selection: never silently switch to another customer.
    ticket_id: Mapped[str | None] = mapped_column(
        ForeignKey("support_tickets.id", ondelete="SET NULL")
    )
