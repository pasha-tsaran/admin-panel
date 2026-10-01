"""add subscription expiry

Revision ID: d4c8f31a62b9
Revises: b7e2a91d4c60
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4c8f31a62b9"
down_revision: str | None = "b7e2a91d4c60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("subscription_expires_at", sa.DateTime(timezone=True)))
        batch_op.create_index(
            "ix_users_subscription_expires_at", ["subscription_expires_at"], unique=False
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "UPDATE users SET subscription_expires_at = CURRENT_TIMESTAMP + INTERVAL '30 days' "
            "WHERE activation_key_hash IS NOT NULL"
        )
    else:
        op.execute(
            "UPDATE users SET subscription_expires_at = datetime('now', '+30 days') "
            "WHERE activation_key_hash IS NOT NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_subscription_expires_at")
        batch_op.drop_column("subscription_expires_at")
