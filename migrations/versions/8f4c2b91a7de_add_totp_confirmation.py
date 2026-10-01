"""add administrator TOTP confirmation state

Revision ID: 8f4c2b91a7de
Revises: 36368bd3c193
Create Date: 2026-08-29 18:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8f4c2b91a7de"
down_revision: str | None = "36368bd3c193"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("administrators") as batch_op:
        batch_op.add_column(
            sa.Column(
                "totp_confirmed",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            )
        )
        batch_op.add_column(
            sa.Column("pending_encrypted_totp_secret", sa.LargeBinary(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("administrators") as batch_op:
        batch_op.drop_column("pending_encrypted_totp_secret")
        batch_op.drop_column("totp_confirmed")
