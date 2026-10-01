# Russian product copy intentionally uses Cyrillic.
# ruff: noqa: RUF001
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kenai_vpn_admin.config import Settings
from kenai_vpn_admin.infrastructure.models import UserModel, naive_utc, utc_now
from kenai_vpn_admin.infrastructure.support_models import (
    SupportMessage,
    SupportOutbox,
    SupportTicket,
)
from kenai_vpn_admin.security import hash_token

STATUS_LABELS = {"waiting": "Ожидает специалиста", "in_progress": "В работе", "closed": "Закрыто"}


class SupportError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SupportPrincipal:
    user: UserModel | None = None
    key_mask: str = ""
    guest_hash: str | None = None

    def __post_init__(self) -> None:
        if (self.user is None) == (self.guest_hash is None):
            raise ValueError("Exactly one support identity is required")


def guest_token_hash(settings: Settings, token: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise SupportError(401, "invalid_guest_token")
    return hmac.new(
        settings.secret_key.encode(), ("support-guest:" + token).encode(), hashlib.sha256
    ).hexdigest()


def guest_remote_hash(settings: Settings, address: str) -> str:
    return hmac.new(
        settings.secret_key.encode(), ("support-remote:" + address).encode(), hashlib.sha256
    ).hexdigest()


class TelegramTransport(Protocol):
    def call(self, method: str, payload: dict[str, Any]) -> Any: ...


def safe_text(value: str) -> str:
    # Activation keys and common VPN secrets must not escape into operator chats.
    value = re.sub(r"(?<!\d)(\d{2})[\s-]?(?:\d[\s-]?){6}(\d{4})(?!\d)", r"\1******\2", value)
    value = re.sub(r"(?i)(?:vless|ss|vmess)://\S+", "[VPN-профиль скрыт]", value)
    value = re.sub(
        r"(?im)((?:privatekey|presharedkey|password|authorization)\s*[:=]\s*)\S+",
        r"\1[скрыто]",
        value,
    )
    return value.strip()


def issue_session(db: Session, settings: Settings, key: str) -> str:
    user = db.scalar(
        select(UserModel).where(
            UserModel.activation_key_hash == hash_token(key), UserModel.status != "revoked"
        )
    )
    if user is None:
        raise SupportError(401, "invalid_account")
    # The session cannot be used to provision or control a VPN.
    claims = json.dumps(
        [
            user.id,
            _key_version(settings, user),
            key[:2] + "******" + key[-4:],
            int(time.time()) + 3600,
        ],
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(claims).decode().rstrip("=")
    signature = hmac.new(
        settings.secret_key.encode(), ("support:" + encoded).encode(), hashlib.sha256
    ).hexdigest()
    return encoded + "." + signature


def _key_version(settings: Settings, user: UserModel) -> str:
    # Do not expose a fast activation-key hash in readable session claims.
    return hmac.new(
        settings.secret_key.encode(),
        ("support-key:" + str(user.activation_key_hash)).encode(),
        hashlib.sha256,
    ).hexdigest()


def resolve_session(db: Session, settings: Settings, token: str) -> tuple[UserModel, str]:
    try:
        encoded, signature = token.split(".")
        expected = hmac.new(
            settings.secret_key.encode(), ("support:" + encoded).encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        user_id, key_hash, mask, expiry = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        if not isinstance(expiry, int) or expiry <= time.time():
            raise ValueError
        user = db.get(UserModel, user_id)
        if user is None or user.status == "revoked" or _key_version(settings, user) != key_hash:
            raise ValueError
        return user, str(mask)
    except (ValueError, TypeError, KeyError):
        raise SupportError(401, "invalid_session") from None


class SupportService:
    def __init__(self, db: Session):
        self.db = db

    def owned(
        self, principal: SupportPrincipal, ticket_id: str, *, lock: bool = False
    ) -> SupportTicket:
        owner = (
            SupportTicket.user_id == principal.user.id
            if principal.user is not None
            else SupportTicket.guest_token_hash == principal.guest_hash
        )
        query = select(SupportTicket).where(SupportTicket.id == ticket_id, owner)
        ticket = self.db.scalar(query.with_for_update() if lock else query)
        if ticket is None:
            raise SupportError(404, "ticket_not_found")
        return ticket

    def list_tickets(self, principal: SupportPrincipal, offset: int = 0) -> list[dict[str, Any]]:
        owner = (
            SupportTicket.user_id == principal.user.id
            if principal.user is not None
            else SupportTicket.guest_token_hash == principal.guest_hash
        )
        tickets = self.db.scalars(
            select(SupportTicket)
            .where(owner)
            .order_by(SupportTicket.updated_at.desc())
            .offset(offset)
            .limit(100)
        )
        return [self.ticket_json(t) for t in tickets]

    @staticmethod
    def ticket_json(ticket: SupportTicket) -> dict[str, Any]:
        return {
            "id": ticket.id,
            "subject": ticket.subject,
            "status": ticket.status,
            "created_at": naive_utc(ticket.created_at).isoformat() + "Z",
            "updated_at": naive_utc(ticket.updated_at).isoformat() + "Z",
        }

    def detail(self, ticket: SupportTicket, after: int = 0) -> dict[str, Any]:
        messages = list(
            self.db.scalars(
                select(SupportMessage)
                .where(SupportMessage.ticket_id == ticket.id, SupportMessage.id > after)
                .order_by(SupportMessage.id)
                .limit(20)
            )
        )
        return {
            "ticket": self.ticket_json(ticket),
            "messages": [
                {
                    "id": m.id,
                    "request_id": m.request_id,
                    "author": m.author,
                    "body": m.body,
                    "created_at": naive_utc(m.created_at).isoformat() + "Z",
                }
                for m in messages
            ],
            "has_more": len(messages) == 20,
        }

    def _message(
        self, ticket: SupportTicket, request_id: str, author: str, body: str
    ) -> SupportMessage:
        message = SupportMessage(
            ticket_id=ticket.id, request_id=request_id, author=author, body=safe_text(body)[:2000]
        )
        self.db.add(message)
        ticket.updated_at = utc_now()
        self.db.flush()
        return message

    def _queue(self, ticket: SupportTicket, body: str) -> None:
        self.db.add(
            SupportOutbox(
                ticket_id=ticket.id,
                payload={"text": body, "parse_mode": "HTML", "reply_markup": self.buttons(ticket)},
            )
        )

    @staticmethod
    def buttons(ticket: SupportTicket) -> dict[str, Any]:
        buttons = []
        if ticket.status == "waiting":
            buttons.append({"text": "Взять в работу", "callback_data": f"take:{ticket.id}"})
        if ticket.status == "in_progress":
            buttons.append({"text": "Выбрать чат", "callback_data": f"select:{ticket.id}"})
        if ticket.status != "closed":
            buttons.append({"text": "Закрыть обращение", "callback_data": f"close:{ticket.id}"})
        return {"inline_keyboard": [buttons] if buttons else []}

    @staticmethod
    def heading(ticket: SupportTicket) -> str:
        identity = (
            f"<code>{html.escape(ticket.key_mask)}</code>"
            if ticket.user_id is not None
            else "гость без ключа"
        )
        name = html.escape(ticket.guest_name or "Не указали имя")
        return (
            f"🆘 <b>Обращение №{ticket.id[:8]}</b>\n"
            f"👤 Пользователь: {identity}\n"
            f"Имя: {name}\n"
            f"📌 <b>{html.escape(ticket.subject)}</b>\n"
            f"Статус: {STATUS_LABELS[ticket.status]}"
        )

    def create(
        self,
        user: UserModel,
        mask: str,
        request_id: str,
        subject: str,
        body: str,
        client_version: str,
        platform: str,
        guest_name: str = "",
    ) -> SupportTicket:
        return self._create(
            SupportPrincipal(user=user, key_mask=mask),
            request_id,
            subject,
            body,
            client_version,
            platform,
            guest_name,
        )

    def create_guest(
        self,
        guest_hash: str,
        remote_hash: str,
        request_id: str,
        subject: str,
        body: str,
        client_version: str,
        platform: str,
        guest_name: str = "",
    ) -> SupportTicket:
        return self._create(
            SupportPrincipal(guest_hash=guest_hash),
            request_id,
            subject,
            body,
            client_version,
            platform,
            guest_name,
            remote_hash=remote_hash,
        )

    def _create(
        self,
        principal: SupportPrincipal,
        request_id: str,
        subject: str,
        body: str,
        client_version: str,
        platform: str,
        guest_name: str,
        *,
        remote_hash: str | None = None,
    ) -> SupportTicket:
        # Serializes concurrent creation; the partial unique index is a second guard.
        if principal.user is not None:
            self.db.scalar(
                select(UserModel.id).where(UserModel.id == principal.user.id).with_for_update()
            )
        owner = (
            SupportTicket.user_id == principal.user.id
            if principal.user is not None
            else SupportTicket.guest_token_hash == principal.guest_hash
        )
        prior = self.db.scalar(
            select(SupportTicket).where(owner, SupportTicket.request_id == request_id)
        )
        if prior is not None:
            return prior
        if self.db.scalar(select(SupportTicket.id).where(owner, SupportTicket.status != "closed")):
            raise SupportError(409, "active_ticket_exists")
        recent = (
            self.db.scalar(
                select(func.count())
                .select_from(SupportTicket)
                .where(
                    owner,
                    SupportTicket.created_at > utc_now() - timedelta(days=1),
                )
            )
            or 0
        )
        if recent >= (10 if principal.user is not None else 3):
            raise SupportError(429, "rate_limited")
        if remote_hash is not None:
            remote_recent = (
                self.db.scalar(
                    select(func.count())
                    .select_from(SupportTicket)
                    .where(
                        SupportTicket.guest_ip_hash == remote_hash,
                        SupportTicket.created_at > utc_now() - timedelta(hours=1),
                    )
                )
                or 0
            )
            if remote_recent >= 20:
                raise SupportError(429, "rate_limited")
            global_recent = (
                self.db.scalar(
                    select(func.count())
                    .select_from(SupportTicket)
                    .where(
                        SupportTicket.guest_token_hash.is_not(None),
                        SupportTicket.created_at > utc_now() - timedelta(days=1),
                    )
                )
                or 0
            )
            if global_recent >= 200:
                raise SupportError(429, "rate_limited")
        name = " ".join(safe_text(guest_name).split())[:80] or None
        ticket = SupportTicket(
            user_id=principal.user.id if principal.user is not None else None,
            guest_token_hash=principal.guest_hash,
            guest_ip_hash=remote_hash,
            guest_name=name,
            request_id=request_id,
            key_mask=principal.key_mask,
            subject=safe_text(subject)[:120],
            client_version=safe_text(client_version)[:40],
            platform=safe_text(platform)[:40],
            status="waiting",
        )
        self.db.add(ticket)
        self.db.flush()
        message = self._message(ticket, request_id, "user", body)
        self._message(
            ticket,
            "waiting",
            "system",
            "Обращение принято. Ожидаем технического эксперта. "
            "Вы можете дополнить описание проблемы.",
        )
        self._queue(
            ticket,
            self.heading(ticket)
            + "\n\n"
            + html.escape(message.body)
            + f"\n\nПриложение: {html.escape(ticket.client_version)}"
            + f" · {html.escape(ticket.platform)}",
        )
        return ticket

    def send(self, ticket: SupportTicket, request_id: str, body: str) -> None:
        if self.db.scalar(
            select(SupportMessage.id).where(
                SupportMessage.ticket_id == ticket.id, SupportMessage.request_id == request_id
            )
        ):
            return
        if ticket.status == "closed":
            raise SupportError(409, "ticket_closed")
        recent = (
            self.db.scalar(
                select(func.count())
                .select_from(SupportMessage)
                .where(
                    SupportMessage.ticket_id == ticket.id,
                    SupportMessage.author == "user",
                    SupportMessage.created_at > utc_now() - timedelta(minutes=1),
                )
            )
            or 0
        )
        if recent >= 20:
            raise SupportError(429, "rate_limited")
        message = self._message(ticket, request_id, "user", body)
        self._queue(ticket, self.heading(ticket) + "\n\n💬 " + html.escape(message.body))

    def transition(self, ticket: SupportTicket, status: str, event: str) -> bool:
        if ticket.status == "closed" or ticket.status == status:
            return False
        ticket.status = status
        text = (
            "Технический эксперт взял обращение в работу."
            if status == "in_progress"
            else "Обращение закрыто. При необходимости создайте новое обращение."
        )
        self._message(ticket, event, "system", text)
        self._queue(ticket, self.heading(ticket) + "\n\n" + text)
        return True

    def reply(self, ticket: SupportTicket, body: str, update_id: int) -> None:
        if ticket.status == "closed":
            raise SupportError(409, "ticket_closed")
        self.transition(ticket, "in_progress", f"take:{update_id}")
        self._message(ticket, f"telegram:{update_id}", "support", body)
