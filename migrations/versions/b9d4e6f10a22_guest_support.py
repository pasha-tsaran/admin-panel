"""Allow isolated two-way support conversations without an activation key."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b9d4e6f10a22"
down_revision: str | None = "a8c3d9e04f21"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("support_tickets") as batch:
        batch.alter_column("user_id", existing_type=sa.String(36), nullable=True)
        batch.add_column(sa.Column("guest_token_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("guest_ip_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("guest_name", sa.String(80), nullable=True))
        batch.create_check_constraint(
            "ck_support_owner",
            "(user_id IS NOT NULL AND guest_token_hash IS NULL) OR "
            "(user_id IS NULL AND guest_token_hash IS NOT NULL)",
        )
    op.create_index("ix_support_tickets_guest_token_hash", "support_tickets", ["guest_token_hash"])
    op.create_index("ix_support_tickets_guest_ip_hash", "support_tickets", ["guest_ip_hash"])
    op.create_index(
        "uq_support_guest_request",
        "support_tickets",
        ["guest_token_hash", "request_id"],
        unique=True,
        sqlite_where=sa.text("guest_token_hash IS NOT NULL"),
        postgresql_where=sa.text("guest_token_hash IS NOT NULL"),
    )
    op.create_index(
        "uq_support_active_guest",
        "support_tickets",
        ["guest_token_hash"],
        unique=True,
        sqlite_where=sa.text("guest_token_hash IS NOT NULL AND status != 'closed'"),
        postgresql_where=sa.text("guest_token_hash IS NOT NULL AND status != 'closed'"),
    )


def downgrade() -> None:
    # A downgrade must not silently discard anonymous conversations.
    connection = op.get_bind()
    guests = connection.execute(
        sa.text("SELECT COUNT(*) FROM support_tickets WHERE guest_token_hash IS NOT NULL")
    ).scalar_one()
    if guests:
        raise RuntimeError("Guest support tickets must be archived before downgrade")
    op.drop_index("uq_support_active_guest", table_name="support_tickets")
    op.drop_index("uq_support_guest_request", table_name="support_tickets")
    op.drop_index("ix_support_tickets_guest_ip_hash", table_name="support_tickets")
    op.drop_index("ix_support_tickets_guest_token_hash", table_name="support_tickets")
    with op.batch_alter_table("support_tickets") as batch:
        batch.drop_constraint("ck_support_owner", type_="check")
        batch.drop_column("guest_name")
        batch.drop_column("guest_ip_hash")
        batch.drop_column("guest_token_hash")
        batch.alter_column("user_id", existing_type=sa.String(36), nullable=False)
