"""admin console RBAC, subscriptions, metrics and integrations

Revision ID: c4f8d2a71e90
Revises: b9d4e6f10a22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4f8d2a71e90"
down_revision: str | None = "b9d4e6f10a22"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("administrators") as batch:
        batch.add_column(
            sa.Column("role", sa.String(32), nullable=False, server_default="super_admin")
        )
        batch.add_column(
            sa.Column("permissions_json", sa.JSON(), nullable=False, server_default="[]")
        )
        batch.create_index("ix_administrators_role", ["role"])
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("device_limit", sa.Integer(), nullable=False, server_default="1")
        )
        batch.create_check_constraint(
            "ck_users_device_limit", "device_limit >= 1 AND device_limit <= 1000"
        )

    op.create_table(
        "subscription_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("price_minor", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("device_limit", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("duration_days > 0", name="ck_subscription_plans_duration"),
        sa.CheckConstraint("price_minor >= 0", name="ck_subscription_plans_price"),
        sa.CheckConstraint("device_limit > 0", name="ck_subscription_plans_device_limit"),
        sa.CheckConstraint("length(currency) = 3", name="ck_subscription_plans_currency"),
    )
    op.create_index("ix_subscription_plans_is_active", "subscription_plans", ["is_active"])
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "plan_id", sa.String(36), sa.ForeignKey("subscription_plans.id", ondelete="SET NULL")
        ),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("price_minor", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "confirmed_by_id",
            sa.String(36),
            sa.ForeignKey("administrators.id", ondelete="SET NULL"),
        ),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending','active','expired','cancelled')",
            name="ck_subscriptions_status",
        ),
        sa.CheckConstraint("price_minor >= 0", name="ck_subscriptions_price"),
        sa.CheckConstraint("length(currency) = 3", name="ck_subscriptions_currency"),
    )
    op.create_index("ix_subscriptions_user_id", "subscriptions", ["user_id"])
    op.create_index("ix_subscriptions_plan_id", "subscriptions", ["plan_id"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])
    op.create_index("ix_subscriptions_ends_at", "subscriptions", ["ends_at"])
    op.create_index("ix_subscriptions_confirmed_by_id", "subscriptions", ["confirmed_by_id"])
    op.create_index("ix_subscriptions_status_ends", "subscriptions", ["status", "ends_at"])
    op.create_table(
        "subscription_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "subscription_id",
            sa.String(36),
            sa.ForeignKey("subscriptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "administrator_id",
            sa.String(36),
            sa.ForeignKey("administrators.id", ondelete="SET NULL"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("old_status", sa.String(24)),
        sa.Column("new_status", sa.String(24), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
    )
    for name in ("subscription_id", "administrator_id", "occurred_at", "event_type"):
        op.create_index(f"ix_subscription_events_{name}", "subscription_events", [name])

    op.create_table(
        "server_metrics",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("node_id", sa.String(36), sa.ForeignKey("vpn_nodes.id", ondelete="CASCADE")),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("health_status", sa.String(16)),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("load_percent", sa.Integer()),
        sa.Column("cpu_percent", sa.Integer()),
        sa.Column("memory_percent", sa.Integer()),
        sa.Column("disk_percent", sa.Integer()),
        sa.Column("current_connections", sa.Integer()),
        sa.Column("received_bytes", sa.BigInteger()),
        sa.Column("transmitted_bytes", sa.BigInteger()),
        sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_metrics_latency"),
        sa.CheckConstraint(
            "load_percent IS NULL OR (load_percent >= 0 AND load_percent <= 100)",
            name="ck_metrics_load",
        ),
        sa.CheckConstraint(
            "cpu_percent IS NULL OR (cpu_percent >= 0 AND cpu_percent <= 100)",
            name="ck_metrics_cpu",
        ),
        sa.CheckConstraint(
            "memory_percent IS NULL OR (memory_percent >= 0 AND memory_percent <= 100)",
            name="ck_metrics_memory",
        ),
        sa.CheckConstraint(
            "disk_percent IS NULL OR (disk_percent >= 0 AND disk_percent <= 100)",
            name="ck_metrics_disk",
        ),
        sa.CheckConstraint(
            "current_connections IS NULL OR current_connections >= 0",
            name="ck_metrics_connections",
        ),
        sa.CheckConstraint(
            "received_bytes IS NULL OR received_bytes >= 0", name="ck_metrics_received"
        ),
        sa.CheckConstraint(
            "transmitted_bytes IS NULL OR transmitted_bytes >= 0",
            name="ck_metrics_transmitted",
        ),
    )
    op.create_index("ix_server_metrics_node_id", "server_metrics", ["node_id"])
    op.create_index("ix_server_metrics_captured_at", "server_metrics", ["captured_at"])
    op.create_index("ix_server_metrics_node_captured", "server_metrics", ["node_id", "captured_at"])
    op.create_index(
        "ix_server_metrics_source_captured", "server_metrics", ["source", "captured_at"]
    )

    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_by_id",
            sa.String(36),
            sa.ForeignKey("administrators.id", ondelete="SET NULL"),
        ),
    )
    op.create_index("ix_system_settings_updated_by_id", "system_settings", ["updated_by_id"])
    op.create_table(
        "telegram_recipients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("chat_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("categories_json", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_telegram_recipients_is_active", "telegram_recipients", ["is_active"])
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "recipient_id",
            sa.String(36),
            sa.ForeignKey("telegram_recipients.id", ondelete="SET NULL"),
        ),
        sa.Column("category", sa.String(48), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("response_code", sa.Integer()),
        sa.Column("error_code", sa.String(80)),
        sa.CheckConstraint(
            "status IN ('pending','retry','sent','failed')",
            name="ck_notification_delivery_status",
        ),
        sa.CheckConstraint("attempts >= 0 AND attempts <= 5", name="ck_notification_attempts"),
    )
    for name in ("recipient_id", "category", "status", "next_attempt_at"):
        op.create_index(f"ix_notification_deliveries_{name}", "notification_deliveries", [name])

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("token_prefix", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("permissions_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_by_id",
            sa.String(36),
            sa.ForeignKey("administrators.id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    for name in ("token_prefix", "created_by_id", "expires_at", "revoked_at"):
        op.create_index(f"ix_api_tokens_{name}", "api_tokens", [name])

    op.create_table(
        "node_onboarding",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "administrator_id",
            sa.String(36),
            sa.ForeignKey("administrators.id", ondelete="SET NULL"),
        ),
        sa.Column("node_slug", sa.String(64), nullable=False),
        sa.Column("agent_endpoint", sa.String(512), nullable=False),
        sa.Column("expected_certificate_sha256", sa.String(64), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("preview_json", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "stage IN ('connectivity','identity','preview','registration',"
            "'health','complete','rollback')",
            name="ck_node_onboarding_stage",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','passed','failed','rolled_back')",
            name="ck_node_onboarding_status",
        ),
    )
    for name in ("administrator_id", "node_slug", "stage", "status"):
        op.create_index(f"ix_node_onboarding_{name}", "node_onboarding", [name])


def downgrade() -> None:
    op.drop_table("node_onboarding")
    op.drop_table("api_tokens")
    op.drop_table("notification_deliveries")
    op.drop_table("telegram_recipients")
    op.drop_table("system_settings")
    op.drop_table("server_metrics")
    op.drop_table("subscription_events")
    op.drop_table("subscriptions")
    op.drop_table("subscription_plans")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("ck_users_device_limit", type_="check")
        batch.drop_column("device_limit")
    with op.batch_alter_table("administrators") as batch:
        batch.drop_index("ix_administrators_role")
        batch.drop_column("permissions_json")
        batch.drop_column("role")
