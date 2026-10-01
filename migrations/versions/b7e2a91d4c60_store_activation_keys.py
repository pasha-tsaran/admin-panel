"""store encrypted activation keys and attempts

Revision ID: b7e2a91d4c60
Revises: a9f4d31c72e8
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7e2a91d4c60"
down_revision: str | None = "a9f4d31c72e8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("encrypted_activation_key", sa.LargeBinary(), nullable=True))
    op.create_table(
        "activation_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("remote_address", sa.String(length=64), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_activation_attempts_remote_address", "activation_attempts", ["remote_address"]
    )
    op.create_index("ix_activation_attempts_attempted_at", "activation_attempts", ["attempted_at"])


def downgrade() -> None:
    op.drop_index("ix_activation_attempts_attempted_at", table_name="activation_attempts")
    op.drop_index("ix_activation_attempts_remote_address", table_name="activation_attempts")
    op.drop_table("activation_attempts")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("encrypted_activation_key")
