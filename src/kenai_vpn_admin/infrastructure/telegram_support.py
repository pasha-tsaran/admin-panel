"""Telegram transport and durable bridge. Never logs tokens, payloads or HTTP URLs."""
# ruff: noqa: RUF001

from __future__ import annotations

import json
import time
import urllib.request
from datetime import timedelta
from typing import Any, cast

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from kenai_vpn_admin.application.support import SupportError, SupportService, TelegramTransport
from kenai_vpn_admin.config import Settings, get_settings
from kenai_vpn_admin.infrastructure.database import build_engine, build_session_factory
from kenai_vpn_admin.infrastructure.models import utc_now
from kenai_vpn_admin.infrastructure.support_models import (
    SupportOperatorSession,
    SupportOutbox,
    SupportTelegramState,
    SupportTicket,
)


class TelegramUnavailable(Exception):
    pass


class TelegramHttpTransport:
    def __init__(self, token: str):
        self._token = token

    def call(self, method: str, payload: dict[str, Any]) -> Any:
        if method not in {
            "sendMessage",
            "getUpdates",
            "answerCallbackQuery",
            "getWebhookInfo",
            "getMe",
        }:
            raise ValueError("Unsupported Telegram operation")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self._token}/{method}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=35) as reply:
                data = json.loads(reply.read(2 * 1024 * 1024))
            if not data.get("ok"):
                raise TelegramUnavailable
            return data["result"]
        except Exception:
            raise TelegramUnavailable("Telegram temporarily unavailable") from None


class SupportBridge:
    def __init__(
        self, settings: Settings, factory: sessionmaker[Session], transport: TelegramTransport
    ):
        self.settings = settings
        self.factory = factory
        self.transport = transport

    def deliver(self) -> None:
        # One dedicated worker holds a PostgreSQL advisory lock for its lifetime.
        with self.factory() as db:
            pending = list(
                db.scalars(
                    select(SupportOutbox)
                    .where(
                        SupportOutbox.sent_at.is_(None), SupportOutbox.next_attempt_at <= utc_now()
                    )
                    .order_by(SupportOutbox.id)
                    .limit(25)
                )
            )
            for item in pending:
                payload = {**item.payload, "chat_id": self.settings.support_telegram_chat_id}
                try:
                    result = self.transport.call("sendMessage", payload)
                    message_id = int(result["message_id"])
                except Exception:
                    item.attempts += 1
                    item.next_attempt_at = utc_now() + timedelta(
                        seconds=min(300, 2 ** min(item.attempts, 8))
                    )
                else:
                    item.telegram_message_id = message_id
                    item.sent_at = utc_now()
                db.commit()

    def offset(self) -> int:
        with self.factory() as db:
            state = db.get(SupportTelegramState, 1)
            return state.next_update_id if state else 0

    def select_ticket(self, db: Session, operator_id: int, ticket: SupportTicket) -> None:
        key = (self.settings.support_telegram_chat_id, operator_id)
        selection = db.get(SupportOperatorSession, key)
        if selection is None:
            selection = SupportOperatorSession(chat_id=key[0], operator_id=key[1])
            db.add(selection)
        selection.ticket_id = ticket.id

    def receive_text(
        self, db: Session, service: SupportService, message: dict[str, Any], update_id: int
    ) -> str:
        body = message.get("text")
        if not isinstance(body, str) or not body.strip() or len(body) > 2000:
            return "Поддерживаются текстовые ответы от 1 до 2000 символов."
        if body.strip().split()[0].split("@")[0] in {"/start", "/help"}:
            return (
                "Нажмите «Взять в работу» или «Выбрать чат» в карточке обращения, "
                "затем пишите сюда обычные сообщения — они появятся у пользователя."
            )
        operator_id = message["from"]["id"]
        ticket_id: str | None
        if "reply_to_message" in message:
            replied = message.get("reply_to_message", {}).get("message_id")
            original = (
                db.scalar(select(SupportOutbox).where(SupportOutbox.telegram_message_id == replied))
                if isinstance(replied, int)
                else None
            )
            if original is None:
                return (
                    "Обращение для этого сообщения не найдено. Выберите чат в карточке обращения."
                )
            ticket_id = original.ticket_id
        else:
            selection = db.get(
                SupportOperatorSession, (self.settings.support_telegram_chat_id, operator_id)
            )
            if selection is not None:
                ticket_id = selection.ticket_id
            else:
                active = list(
                    db.scalars(
                        select(SupportTicket.id).where(SupportTicket.status != "closed").limit(2)
                    )
                )
                if len(active) != 1:
                    return (
                        "Выберите обращение: нажмите «Взять в работу» или «Выбрать чат» "
                        "в его карточке. Сообщение не отправлено."
                    )
                ticket_id = active[0]
        ticket = (
            db.scalar(select(SupportTicket).where(SupportTicket.id == ticket_id).with_for_update())
            if ticket_id
            else None
        )
        if ticket is None or ticket.status == "closed":
            return "Обращение закрыто. Выберите другое обращение. Ответ пользователю не отправлен."
        try:
            service.reply(ticket, body, update_id)
        except SupportError:
            return "Ответ пользователю не отправлен. Проверьте статус обращения."
        self.select_ticket(db, operator_id, ticket)
        return f"Ответ отправлен в обращение №{ticket.id[:8]}."

    def receive(self, update: dict[str, Any]) -> None:
        update_id = update.get("update_id")
        if not isinstance(update_id, int):
            return
        callback = update.get("callback_query")
        acknowledgment = "Готово"
        notify: str | None = None
        with self.factory() as db:
            state = db.get(SupportTelegramState, 1)
            if state is None:
                state = SupportTelegramState(id=1, next_update_id=0)
                db.add(state)
            if update_id < state.next_update_id:
                return
            service = SupportService(db)
            event = callback if isinstance(callback, dict) else update.get("message", {})
            sender = event.get("from", {})
            message = event.get("message", {}) if callback else event
            allowed = (
                sender.get("id") in self.settings.support_admin_ids
                and not sender.get("is_bot", False)
                and message.get("chat", {}).get("id") == self.settings.support_telegram_chat_id
            )
            if not allowed:
                acknowledgment = "Нет доступа"
            elif callback:
                parts = str(event.get("data", "")).split(":", 1)
                original = db.scalar(
                    select(SupportOutbox).where(
                        SupportOutbox.telegram_message_id == message.get("message_id")
                    )
                )
                ticket = (
                    db.scalar(
                        select(SupportTicket).where(SupportTicket.id == parts[1]).with_for_update()
                    )
                    if len(parts) == 2
                    else None
                )
                if (
                    ticket is None
                    or original is None
                    or original.ticket_id != ticket.id
                    or parts[0] not in {"take", "close", "select"}
                ):
                    acknowledgment = "Обращение не найдено"
                elif parts[0] == "close":
                    service.transition(
                        ticket,
                        "closed",
                        f"status:{update_id}",
                    )
                    acknowledgment = "Закрыто"
                elif ticket.status == "closed":
                    acknowledgment = "Обращение закрыто"
                else:
                    service.transition(ticket, "in_progress", f"status:{update_id}")
                    self.select_ticket(db, sender["id"], ticket)
                    acknowledgment = f"Выбран чат №{ticket.id[:8]}. Пишите обычным сообщением."
            else:
                notify = self.receive_text(db, service, message, update_id)
            state.next_update_id = update_id + 1
            db.commit()
        # Telegram callback acknowledgment is not a prerequisite for persisting status.
        try:
            if callback:
                self.transport.call(
                    "answerCallbackQuery",
                    {"callback_query_id": callback["id"], "text": acknowledgment},
                )
            elif notify:
                self.transport.call(
                    "sendMessage",
                    {"chat_id": self.settings.support_telegram_chat_id, "text": notify},
                )
        except Exception:
            pass

    def run_once(self) -> None:
        self.deliver()
        updates = self.transport.call(
            "getUpdates",
            {
                "offset": self.offset(),
                "timeout": 10,
                "allowed_updates": ["message", "callback_query"],
            },
        )
        for update in cast(list[dict[str, Any]], updates):
            self.receive(update)


def main() -> None:
    settings = get_settings()
    if not settings.support_available:
        raise SystemExit("Support is not configured. See docs/support.md.")
    engine = build_engine(settings)
    transport = TelegramHttpTransport(settings.support_telegram_bot_token.get_secret_value())
    try:
        # Session-level advisory lock prevents two processes from consuming the same bot.
        with engine.connect() as lock:
            if engine.dialect.name == "postgresql":
                if not lock.scalar(text("SELECT pg_try_advisory_lock(726514209)")):
                    raise SystemExit("A support worker is already running.")
            elif settings.env != "test":
                raise SystemExit("The support worker requires PostgreSQL.")
            if transport.call("getWebhookInfo", {}).get("url"):
                raise SystemExit("Bot has an existing webhook. Use a dedicated support bot.")
            bridge = SupportBridge(settings, build_session_factory(engine), transport)
            while True:
                # A broken lock connection must stop the worker, not silently
                # continue after PostgreSQL has released its advisory lock.
                lock.execute(text("SELECT 1"))
                try:
                    bridge.run_once()
                except Exception:
                    # Secrets and message text must never enter process logs.
                    print("support_worker_retry", flush=True)
                    time.sleep(5)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
