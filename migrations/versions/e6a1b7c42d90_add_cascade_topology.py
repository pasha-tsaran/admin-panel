"""add cascade topology and device API credentials

Revision ID: e6a1b7c42d90
Revises: d4c8f31a62b9
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e6a1b7c42d90"
down_revision: str | None = "d4c8f31a62b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("activation_key_consumed_at", sa.DateTime(timezone=True)))

    op.create_table(
        "vpn_nodes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=False),
        sa.Column("city", sa.String(length=120), nullable=False),
        sa.Column("public_endpoint", sa.String(length=253), nullable=False),
        sa.Column("agent_endpoint", sa.String(length=512)),
        sa.Column("certificate_sha256", sa.String(length=64)),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("load_percent", sa.Integer()),
        sa.Column("current_users", sa.Integer(), nullable=False),
        sa.Column("received_bytes", sa.BigInteger(), nullable=False),
        sa.Column("transmitted_bytes", sa.BigInteger(), nullable=False),
        sa.Column("config_revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('ingress','exit')", name="ck_vpn_nodes_role"),
        sa.CheckConstraint(
            "status IN ('online','degraded','offline','disabled')", name="ck_vpn_nodes_status"
        ),
        sa.CheckConstraint("length(country_code) = 2", name="ck_vpn_nodes_country_code"),
        sa.CheckConstraint(
            "load_percent IS NULL OR (load_percent >= 0 AND load_percent <= 100)",
            name="ck_vpn_nodes_load_percent",
        ),
        sa.CheckConstraint("current_users >= 0", name="ck_vpn_nodes_current_users"),
        sa.CheckConstraint("received_bytes >= 0", name="ck_vpn_nodes_received_bytes"),
        sa.CheckConstraint("transmitted_bytes >= 0", name="ck_vpn_nodes_transmitted_bytes"),
        sa.CheckConstraint("config_revision >= 0", name="ck_vpn_nodes_config_revision"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_vpn_nodes_role", "vpn_nodes", ["role"])
    op.create_index("ix_vpn_nodes_status", "vpn_nodes", ["status"])

    op.create_table(
        "vpn_locations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=False),
        sa.Column("country_name", sa.String(length=120), nullable=False),
        sa.Column("city", sa.String(length=120), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("ingress_node_id", sa.String(length=36), nullable=False),
        sa.Column("exit_node_id", sa.String(length=36), nullable=False),
        sa.Column("outbound_tag", sa.String(length=128), nullable=False),
        sa.Column("encrypted_exit_link", sa.LargeBinary()),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("last_probe_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("sort_order", sa.Integer(), nullable=False),
        sa.Column("is_recommended", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(country_code) = 2", name="ck_vpn_locations_country_code"),
        sa.CheckConstraint(
            "status IN ('online','degraded','offline','disabled')",
            name="ck_vpn_locations_status",
        ),
        sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_location_latency"),
        sa.CheckConstraint("sort_order >= 0", name="ck_location_sort_order"),
        sa.ForeignKeyConstraint(["exit_node_id"], ["vpn_nodes.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["ingress_node_id"], ["vpn_nodes.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("outbound_tag"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_vpn_locations_exit_node_id", "vpn_locations", ["exit_node_id"])
    op.create_index("ix_vpn_locations_ingress_node_id", "vpn_locations", ["ingress_node_id"])
    op.create_index("ix_vpn_locations_status", "vpn_locations", ["status"])

    op.create_table(
        "device_access_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_device_access_tokens_device_id", "device_access_tokens", ["device_id"])
    op.create_index("ix_device_access_tokens_revoked_at", "device_access_tokens", ["revoked_at"])

    op.create_table(
        "route_credentials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("location_id", sa.String(length=36), nullable=False),
        sa.Column("client_uuid", sa.String(length=36), nullable=False),
        sa.Column("client_email", sa.String(length=253), nullable=False),
        sa.Column("encrypted_client_uri", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active','disabled','revoked')", name="ck_route_credentials_status"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["location_id"], ["vpn_locations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_email"),
        sa.UniqueConstraint("client_uuid"),
        sa.UniqueConstraint(
            "device_id", "location_id", name="uq_route_credentials_device_location"
        ),
    )
    op.create_index("ix_route_credentials_device_id", "route_credentials", ["device_id"])
    op.create_index("ix_route_credentials_location_id", "route_credentials", ["location_id"])
    op.create_index("ix_route_credentials_status", "route_credentials", ["status"])


def downgrade() -> None:
    op.drop_index("ix_route_credentials_status", table_name="route_credentials")
    op.drop_index("ix_route_credentials_location_id", table_name="route_credentials")
    op.drop_index("ix_route_credentials_device_id", table_name="route_credentials")
    op.drop_table("route_credentials")
    op.drop_index("ix_device_access_tokens_revoked_at", table_name="device_access_tokens")
    op.drop_index("ix_device_access_tokens_device_id", table_name="device_access_tokens")
    op.drop_table("device_access_tokens")
    op.drop_index("ix_vpn_locations_status", table_name="vpn_locations")
    op.drop_index("ix_vpn_locations_ingress_node_id", table_name="vpn_locations")
    op.drop_index("ix_vpn_locations_exit_node_id", table_name="vpn_locations")
    op.drop_table("vpn_locations")
    op.drop_index("ix_vpn_nodes_status", table_name="vpn_nodes")
    op.drop_index("ix_vpn_nodes_role", table_name="vpn_nodes")
    op.drop_table("vpn_nodes")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("activation_key_consumed_at")
