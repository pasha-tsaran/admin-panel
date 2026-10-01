"""add independent AmneziaWG credentials

Revision ID: c2a4e6f91b30
Revises: 8f4c2b91a7de
Create Date: 2026-08-31 01:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c2a4e6f91b30"
down_revision: str | None = "8f4c2b91a7de"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "amneziawg_credentials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("tunnel_address", sa.String(length=18), nullable=False),
        sa.Column("encrypted_client_config", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_handshake_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("received_bytes", sa.BigInteger(), nullable=False),
        sa.Column("transmitted_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active','disabled','revoked')", name="ck_awg_status"),
        sa.CheckConstraint("received_bytes >= 0", name="ck_awg_received_nonnegative"),
        sa.CheckConstraint("transmitted_bytes >= 0", name="ck_awg_transmitted_nonnegative"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id"),
        sa.UniqueConstraint("public_key"),
        sa.UniqueConstraint("tunnel_address"),
    )
    op.create_index(
        op.f("ix_amneziawg_credentials_status"),
        "amneziawg_credentials",
        ["status"],
        unique=False,
    )
    with op.batch_alter_table("provisioning_packages") as batch_op:
        batch_op.drop_constraint("ck_package_has_protocol", type_="check")
        batch_op.add_column(
            sa.Column(
                "includes_amneziawg",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.create_check_constraint(
            "ck_package_has_protocol",
            "includes_wireguard OR includes_amneziawg OR includes_vless",
        )


def downgrade() -> None:
    with op.batch_alter_table("provisioning_packages") as batch_op:
        batch_op.drop_constraint("ck_package_has_protocol", type_="check")
        batch_op.drop_column("includes_amneziawg")
        batch_op.create_check_constraint(
            "ck_package_has_protocol", "includes_wireguard OR includes_vless"
        )
    op.drop_index(op.f("ix_amneziawg_credentials_status"), table_name="amneziawg_credentials")
    op.drop_table("amneziawg_credentials")
