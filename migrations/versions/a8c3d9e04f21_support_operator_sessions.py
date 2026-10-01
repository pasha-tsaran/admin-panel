"""Persist the selected support conversation for each Telegram operator."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8c3d9e04f21"
down_revision: str | None = "f7b2c8d93e10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "support_operator_sessions",
        sa.Column("chat_id", sa.BigInteger(), primary_key=True),
        sa.Column("operator_id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "ticket_id",
            sa.String(36),
            sa.ForeignKey("support_tickets.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("support_operator_sessions")
