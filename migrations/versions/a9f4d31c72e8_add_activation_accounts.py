"""add activation accounts

Revision ID: a9f4d31c72e8
Revises: c2a4e6f91b30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a9f4d31c72e8"
down_revision: str | None = "c2a4e6f91b30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("email", sa.String(length=254), nullable=True))
        batch_op.add_column(sa.Column("telegram_username", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("phone_number", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("activation_key_hash", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_users_activation_key_hash", ["activation_key_hash"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_activation_key_hash")
        batch_op.drop_column("activation_key_hash")
        batch_op.drop_column("phone_number")
        batch_op.drop_column("telegram_username")
        batch_op.drop_column("email")
