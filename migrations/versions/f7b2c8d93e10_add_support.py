"""Support tickets, durable messages and Telegram delivery queue."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7b2c8d93e10"
down_revision: str | None = "e6a1b7c42d90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "support_tickets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("key_mask", sa.String(12), nullable=False),
        sa.Column("subject", sa.String(120), nullable=False),
        sa.Column("client_version", sa.String(40), nullable=False),
        sa.Column("platform", sa.String(40), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "request_id", name="uq_support_request"),
        sa.CheckConstraint(
            "status IN ('waiting','in_progress','closed')", name="ck_support_status"
        ),
    )
    op.create_index("ix_support_tickets_user_id", "support_tickets", ["user_id"])
    op.create_index(
        "uq_support_active_user",
        "support_tickets",
        ["user_id"],
        unique=True,
        sqlite_where=sa.text("status != 'closed'"),
        postgresql_where=sa.text("status != 'closed'"),
    )
    op.create_table(
        "support_messages",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "ticket_id",
            sa.String(36),
            sa.ForeignKey("support_tickets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(80), nullable=False),
        sa.Column("author", sa.String(16), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("ticket_id", "request_id", name="uq_support_message_request"),
        sa.CheckConstraint("author IN ('user','support','system')", name="ck_support_author"),
    )
    op.create_index("ix_support_messages_ticket_id", "support_messages", ["ticket_id"])
    op.create_table(
        "support_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "ticket_id",
            sa.String(36),
            sa.ForeignKey("support_tickets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("telegram_message_id", sa.BigInteger()),
    )
    op.create_index("ix_support_outbox_ticket_id", "support_outbox", ["ticket_id"])
    op.create_index("ix_support_outbox_next_attempt_at", "support_outbox", ["next_attempt_at"])
    op.create_index(
        "ix_support_outbox_telegram_message_id", "support_outbox", ["telegram_message_id"]
    )
    op.create_table(
        "support_telegram_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("next_update_id", sa.BigInteger(), nullable=False),
    )


def downgrade() -> None:
    for table in [
        "support_telegram_state",
        "support_outbox",
        "support_messages",
        "support_tickets",
    ]:
        op.drop_table(table)
