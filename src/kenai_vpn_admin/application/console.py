from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from kenai_vpn_admin.application.ports import VpnManager
from kenai_vpn_admin.application.rbac import normalize_permissions
from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.models import (
    ApiTokenModel,
    AuditEventModel,
    NotificationDeliveryModel,
    ServerMetricModel,
    SessionModel,
    SubscriptionModel,
    SubscriptionPlanModel,
    SystemSettingModel,
    TelegramRecipientModel,
    UserModel,
    VpnNodeModel,
    utc_now,
)
from kenai_vpn_admin.security import hash_token

NOTIFICATION_CATEGORIES = frozenset(
    {
        "server_unavailable",
        "high_load",
        "subscription_expiring",
        "backup_failed",
        "suspicious_login",
        "critical_admin_action",
    }
)


@dataclass(frozen=True)
class ConsoleSummary:
    users: int
    active_users: int
    devices: int
    active_sessions: int
    audit_events_24h: int
    latest_metric: ServerMetricModel | None


class ConsoleService:
    def __init__(self, settings: Settings, vpn: VpnManager) -> None:
        self.settings = settings
        self.vpn = vpn

    def summary(self, db: Session) -> ConsoleSummary:
        now = utc_now()
        return ConsoleSummary(
            users=int(db.scalar(select(func.count(UserModel.id))) or 0),
            active_users=int(
                db.scalar(
                    select(func.count(UserModel.id)).where(
                        UserModel.status == "active",
                        (UserModel.subscription_expires_at.is_(None))
                        | (UserModel.subscription_expires_at > now),
                    )
                )
                or 0
            ),
            devices=int(
                db.scalar(select(func.count()).select_from(UserModel).join(UserModel.devices)) or 0
            ),
            active_sessions=int(
                db.scalar(
                    select(func.count(SessionModel.id)).where(
                        SessionModel.revoked_at.is_(None), SessionModel.expires_at > now
                    )
                )
                or 0
            ),
            audit_events_24h=int(
                db.scalar(
                    select(func.count(AuditEventModel.id)).where(
                        AuditEventModel.occurred_at >= now - timedelta(hours=24)
                    )
                )
                or 0
            ),
            latest_metric=db.scalar(
                select(ServerMetricModel)
                .where(ServerMetricModel.source == "primary")
                .order_by(desc(ServerMetricModel.captured_at))
                .limit(1)
            ),
        )

    def collect_metrics(self, db: Session) -> ServerMetricModel:
        health = self.vpn.health()
        protocols = (health.amneziawg, health.xray)
        metric = ServerMetricModel(
            source="primary",
            health_status=(
                "online"
                if health.firewall_active and all(item.active for item in protocols)
                else "degraded"
            ),
            current_connections=sum(item.current_connections for item in protocols),
            received_bytes=sum(item.received_bytes for item in protocols),
            transmitted_bytes=sum(item.transmitted_bytes for item in protocols),
            cpu_percent=(round(health.cpu_percent) if health.cpu_percent is not None else None),
            memory_percent=(
                round(health.memory_percent) if health.memory_percent is not None else None
            ),
            disk_percent=(round(health.disk_percent) if health.disk_percent is not None else None),
            load_percent=(round(health.load_percent) if health.load_percent is not None else None),
        )
        db.add(metric)
        if metric.health_status != "online":
            self.queue_notification_once(
                db,
                category="server_unavailable",
                message="Kenai VPN: основной VPN-сервер работает в режиме деградации.",
                cooldown=timedelta(hours=1),
            )
        resource_values = [
            value
            for value in (
                health.cpu_percent,
                health.memory_percent,
                health.disk_percent,
                health.load_percent,
            )
            if value is not None
        ]
        if resource_values and max(resource_values) >= 85:
            self.queue_notification_once(
                db,
                category="high_load",
                message="Kenai VPN: нагрузка основного сервера достигла 85% или выше.",
                cooldown=timedelta(hours=1),
            )
        for node in db.scalars(select(VpnNodeModel)):
            db.add(
                ServerMetricModel(
                    node_id=node.id,
                    source=node.slug,
                    health_status=node.status,
                    load_percent=node.load_percent,
                    current_connections=node.current_users,
                    received_bytes=node.received_bytes,
                    transmitted_bytes=node.transmitted_bytes,
                )
            )
        cutoff = utc_now() - timedelta(days=self.settings.metrics_retention_days)
        db.execute(delete(ServerMetricModel).where(ServerMetricModel.captured_at < cutoff))
        expiring_cutoff = utc_now() + timedelta(days=3)
        for user in db.scalars(
            select(UserModel).where(
                UserModel.status == "active",
                UserModel.subscription_expires_at.is_not(None),
                UserModel.subscription_expires_at > utc_now(),
                UserModel.subscription_expires_at <= expiring_cutoff,
            )
        ):
            self.queue_notification_once(
                db,
                category="subscription_expiring",
                message=(
                    f"Kenai VPN: подписка пользователя {user.display_name} "
                    f"истекает {user.subscription_expires_at:%Y-%m-%d}."
                ),
                cooldown=timedelta(hours=24),
            )
        return metric

    @staticmethod
    def metrics(
        db: Session, *, source: str = "primary", hours: int = 24
    ) -> list[ServerMetricModel]:
        cutoff = utc_now() - timedelta(hours=max(1, min(hours, 24 * 30)))
        return list(
            db.scalars(
                select(ServerMetricModel)
                .where(
                    ServerMetricModel.source == source,
                    ServerMetricModel.captured_at >= cutoff,
                )
                .order_by(ServerMetricModel.captured_at)
            )
        )

    @staticmethod
    def set_setting(
        db: Session, *, key: str, value: dict[str, Any], administrator_id: str
    ) -> SystemSettingModel:
        model = db.get(SystemSettingModel, key)
        if model is None:
            model = SystemSettingModel(key=key)
            db.add(model)
        model.value_json = value
        model.updated_by_id = administrator_id
        return model

    @staticmethod
    def settings_map(db: Session) -> dict[str, dict[str, Any]]:
        return {item.key: item.value_json for item in db.scalars(select(SystemSettingModel))}

    @staticmethod
    def create_api_token(
        db: Session,
        *,
        name: str,
        permissions: list[str],
        created_by_id: str,
        expires_in_days: int | None,
    ) -> tuple[ApiTokenModel, str]:
        normalized_name = name.strip()
        if not normalized_name or len(normalized_name) > 120:
            raise ValueError("API token name is invalid")
        token = f"kn_{secrets.token_urlsafe(36)}"
        model = ApiTokenModel(
            name=normalized_name,
            token_prefix=token[:12],
            token_hash=hash_token(token),
            permissions_json=normalize_permissions(permissions),
            created_by_id=created_by_id,
            expires_at=(utc_now() + timedelta(days=expires_in_days) if expires_in_days else None),
        )
        db.add(model)
        return model, token

    @staticmethod
    def revoke_api_token(db: Session, token_id: str) -> None:
        token = db.get(ApiTokenModel, token_id)
        if token is None:
            raise ValueError("API token not found")
        token.revoked_at = utc_now()

    @staticmethod
    def save_recipient(
        db: Session, *, label: str, chat_id: int, categories: list[str]
    ) -> TelegramRecipientModel:
        selected = sorted(set(categories) & NOTIFICATION_CATEGORIES)
        if not label.strip() or not selected:
            raise ValueError("Telegram recipient is invalid")
        recipient = db.scalar(
            select(TelegramRecipientModel).where(TelegramRecipientModel.chat_id == chat_id)
        )
        if recipient is None:
            recipient = TelegramRecipientModel(chat_id=chat_id)
            db.add(recipient)
        recipient.label = label.strip()
        recipient.categories_json = selected
        recipient.is_active = True
        return recipient

    @staticmethod
    def queue_notification(db: Session, *, category: str, message: str) -> int:
        if category not in NOTIFICATION_CATEGORIES:
            raise ValueError("Unknown notification category")
        safe_message = message.strip()[:2000]
        recipients = list(
            db.scalars(
                select(TelegramRecipientModel).where(TelegramRecipientModel.is_active.is_(True))
            )
        )
        queued = 0
        for recipient in recipients:
            if category not in recipient.categories_json:
                continue
            db.add(
                NotificationDeliveryModel(
                    recipient_id=recipient.id,
                    category=category,
                    message=safe_message,
                )
            )
            queued += 1
        return queued

    @classmethod
    def queue_notification_once(
        cls,
        db: Session,
        *,
        category: str,
        message: str,
        cooldown: timedelta,
    ) -> int:
        safe_message = message.strip()[:2000]
        cutoff = utc_now() - cooldown
        exists = db.scalar(
            select(NotificationDeliveryModel.id).where(
                NotificationDeliveryModel.category == category,
                NotificationDeliveryModel.message == safe_message,
                NotificationDeliveryModel.created_at >= cutoff,
            )
        )
        if exists:
            return 0
        return cls.queue_notification(db, category=category, message=safe_message)

    def send_pending_notifications(self, db: Session) -> int:
        token = self.settings.notification_telegram_bot_token.get_secret_value()
        if not token:
            return 0
        pending = list(
            db.scalars(
                select(NotificationDeliveryModel)
                .where(
                    NotificationDeliveryModel.status.in_(("pending", "retry")),
                    NotificationDeliveryModel.next_attempt_at <= utc_now(),
                )
                .order_by(NotificationDeliveryModel.created_at)
                .limit(50)
            )
        )
        sent = 0
        for delivery in pending:
            recipient = db.get(TelegramRecipientModel, delivery.recipient_id)
            if recipient is None or not recipient.is_active:
                delivery.status = "failed"
                delivery.error_code = "recipient_unavailable"
                continue
            body = urllib.parse.urlencode(
                {"chat_id": str(recipient.chat_id), "text": delivery.message}
            ).encode()
            request = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data=body,
                method="POST",
            )
            delivery.attempts += 1
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    payload = json.loads(response.read(4096))
                    delivery.response_code = response.status
                    if not payload.get("ok"):
                        raise RuntimeError("telegram_rejected")
                delivery.status = "sent"
                delivery.sent_at = utc_now()
                delivery.error_code = None
                sent += 1
            except (urllib.error.URLError, TimeoutError, RuntimeError, ValueError) as exc:
                delivery.error_code = type(exc).__name__[:80]
                if delivery.attempts >= self.settings.notification_retry_limit:
                    delivery.status = "failed"
                else:
                    delivery.status = "retry"
                    delivery.next_attempt_at = utc_now() + timedelta(minutes=2**delivery.attempts)
        return sent

    @staticmethod
    def plans(db: Session) -> list[SubscriptionPlanModel]:
        return list(
            db.scalars(
                select(SubscriptionPlanModel).order_by(
                    SubscriptionPlanModel.is_active.desc(), SubscriptionPlanModel.duration_days
                )
            )
        )

    @staticmethod
    def subscriptions(db: Session, *, limit: int = 100) -> list[SubscriptionModel]:
        return list(
            db.scalars(
                select(SubscriptionModel)
                .order_by(desc(SubscriptionModel.updated_at))
                .limit(max(1, min(limit, 500)))
            )
        )
