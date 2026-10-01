# Russian copy is tested verbatim.
# ruff: noqa: RUF001
import base64
import uuid
from datetime import timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select

from kenai_vpn_admin.application.support import safe_text
from kenai_vpn_admin.infrastructure.models import UserModel, utc_now
from kenai_vpn_admin.infrastructure.support_models import (
    SupportMessage,
    SupportOutbox,
    SupportTicket,
)
from kenai_vpn_admin.infrastructure.telegram_support import SupportBridge
from kenai_vpn_admin.security import hash_token

KEY = "123456789012"
OTHER_KEY = "987654321098"
BASE = "/api/v1/support"


class FakeTelegram:
    def __init__(self):
        self.calls = []
        self.failed = False
        self.next_id = 100

    def call(self, method, payload):
        self.calls.append((method, payload))
        if self.failed:
            raise RuntimeError("offline")
        if method == "sendMessage":
            self.next_id += 1
            return {"message_id": self.next_id}
        return [] if method == "getUpdates" else True


@pytest.fixture
def support(app, client):
    config = app.state.settings
    config.support_enabled = True
    config.support_telegram_bot_token = SecretStr("test-token-not-real")
    config.support_telegram_chat_id = 1001
    config.support_telegram_admin_ids = "1001"
    with app.state.session_factory() as db:
        for number, key in enumerate([KEY, OTHER_KEY]):
            db.add(
                UserModel(
                    slug=f"support-{number}",
                    display_name="Support tester",
                    activation_key_hash=hash_token(key),
                    subscription_expires_at=utc_now() - timedelta(days=2),
                )
            )
        db.commit()
    tg = FakeTelegram()
    bridge = SupportBridge(config, app.state.session_factory, tg)
    return app, client, tg, bridge


def auth(client, key=KEY):
    result = client.post(BASE + "/session", json={"activation_key": key})
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json()["access_token"]}


def create(client, headers, request_id=None):
    return client.post(
        BASE + "/tickets",
        headers=headers,
        json={
            "request_id": request_id or str(uuid.uuid4()),
            "subject": "VPN не работает",
            "body": "Не подключается. Ключ " + KEY,
            "client_version": "2.2.2",
            "platform": "Windows",
        },
    )


def callback(update_id, message_id, ticket, action="take", sender=1001):
    return {
        "update_id": update_id,
        "callback_query": {
            "id": f"callback-{update_id}",
            "from": {"id": sender},
            "data": f"{action}:{ticket}",
            "message": {"message_id": message_id, "chat": {"id": 1001}},
        },
    }


def reply(update_id, message_id, body="Попробуйте подключиться ещё раз.", sender=1001):
    return {
        "update_id": update_id,
        "message": {
            "from": {"id": sender},
            "chat": {"id": 1001},
            "text": body,
            "reply_to_message": {"message_id": message_id},
        },
    }


def test_full_conversation_and_statuses(support):
    app, client, tg, bridge = support
    headers = auth(client)
    created = create(client, headers)
    assert created.status_code == 201
    ticket = created.json()["ticket"]["id"]
    assert created.json()["ticket"]["status"] == "waiting"
    assert created.json()["messages"][-1]["author"] == "system"
    bridge.deliver()
    card = tg.calls[-1][1]
    assert "12******9012" in card["text"]
    assert KEY not in card["text"]
    assert [b["text"] for b in card["reply_markup"]["inline_keyboard"][0]] == [
        "Взять в работу",
        "Закрыть обращение",
    ]
    with app.state.session_factory() as db:
        delivered = db.scalar(select(SupportOutbox).where(SupportOutbox.ticket_id == ticket))
        message_id = delivered.telegram_message_id
    bridge.receive(callback(1, message_id, ticket))
    bridge.receive(callback(1, message_id, ticket))  # Redelivery must be harmless.
    detail = client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()
    assert detail["ticket"]["status"] == "in_progress"
    assert len(detail["messages"]) == 3
    bridge.receive(reply(2, message_id))
    detail = client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()
    assert detail["messages"][-1]["author"] == "support"
    assert "Попробуйте" in detail["messages"][-1]["body"]
    bridge.receive(callback(3, message_id, ticket, "close"))
    assert (
        client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["ticket"]["status"]
        == "closed"
    )
    result = client.post(
        f"{BASE}/tickets/{ticket}/messages",
        headers=headers,
        json={"request_id": str(uuid.uuid4()), "body": "Ещё вопрос"},
    )
    assert result.status_code == 409
    bridge.receive(reply(4, message_id))
    assert "закрыто" in tg.calls[-1][1]["text"]
    assert create(client, headers).status_code == 201


def test_guest_chat_is_isolated_and_telegram_receives_optional_name(support):
    app, client, tg, bridge = support
    guest = {"Authorization": "Guest " + "a" * 64}
    payload = {
        "request_id": str(uuid.uuid4()),
        "subject": "Не получается активировать приложение",
        "body": "Нужна помощь до ввода ключа",
        "guest_name": "Иван <тест>",
        "client_version": "2.2.2",
        "platform": "windows",
    }
    created = client.post(BASE + "/tickets", headers=guest, json=payload)
    assert created.status_code == 201
    ticket = created.json()["ticket"]["id"]
    assert (
        client.post(BASE + "/tickets", headers=guest, json=payload).json()["ticket"]["id"] == ticket
    )
    bridge.deliver()
    card = tg.calls[-1][1]["text"]
    assert "гость без ключа" in card
    assert "Имя: Иван &lt;тест&gt;" in card
    assert "a" * 64 not in card

    other = {"Authorization": "Guest " + "b" * 64}
    assert client.get(f"{BASE}/tickets/{ticket}", headers=other).status_code == 404
    assert client.get(f"{BASE}/tickets/{ticket}", headers=auth(client)).status_code == 404
    assert client.get(f"{BASE}/tickets/{ticket}").status_code == 401
    assert client.get(BASE + "/tickets", headers=guest).json()["tickets"][0]["id"] == ticket
    with app.state.session_factory() as db:
        delivered = db.scalar(select(SupportOutbox).where(SupportOutbox.ticket_id == ticket))
        message_id = delivered.telegram_message_id
    bridge.receive(reply(201, message_id, "Ответ для гостя"))
    detail = client.get(f"{BASE}/tickets/{ticket}", headers=guest).json()
    assert detail["messages"][-1]["body"] == "Ответ для гостя"
    assert (
        client.post(
            f"{BASE}/tickets/{ticket}/messages",
            headers=guest,
            json={"request_id": str(uuid.uuid4()), "body": "Спасибо"},
        ).status_code
        == 200
    )

    unnamed = {"Authorization": "Guest " + "c" * 64}
    payload["request_id"] = str(uuid.uuid4())
    payload["guest_name"] = ""
    assert client.post(BASE + "/tickets", headers=unnamed, json=payload).status_code == 201
    bridge.deliver()
    assert "Имя: Не указали имя" in tg.calls[-1][1]["text"]


def test_guest_tickets_have_a_per_identity_limit(support):
    app, client, _tg, _bridge = support
    guest = {"Authorization": "Guest " + "d" * 64}
    for _ in range(3):
        created = client.post(
            BASE + "/tickets",
            headers=guest,
            json={"request_id": str(uuid.uuid4()), "subject": "Вопрос", "body": "Сообщение"},
        )
        assert created.status_code == 201
        with app.state.session_factory() as db:
            ticket = db.get(SupportTicket, created.json()["ticket"]["id"])
            ticket.status = "closed"
            db.commit()
    denied = client.post(
        BASE + "/tickets",
        headers=guest,
        json={"request_id": str(uuid.uuid4()), "subject": "Ещё вопрос", "body": "Сообщение"},
    )
    assert denied.status_code == 429


def test_ownership_admin_allowlist_and_unmatched_replies(support):
    _app, client, tg, bridge = support
    headers = auth(client)
    ticket = create(client, headers).json()["ticket"]["id"]
    other = auth(client, OTHER_KEY)
    assert client.get(f"{BASE}/tickets/{ticket}", headers=other).status_code == 404
    assert (
        client.post(
            f"{BASE}/tickets/{ticket}/messages",
            headers=other,
            json={"request_id": str(uuid.uuid4()), "body": "wrong user"},
        ).status_code
        == 404
    )
    bridge.deliver()
    bridge.receive(callback(10, 101, ticket, sender=999))
    bridge.receive(reply(11, 101, sender=999))
    bridge.receive(callback(12, 9999, ticket))
    assert (
        client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["ticket"]["status"]
        == "waiting"
    )
    bridge.receive(reply(13, 9999))
    assert "не найдено" in tg.calls[-1][1]["text"]
    assert len(client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["messages"]) == 2


def test_idempotent_posts_and_pagination(support):
    _app, client, _tg, _bridge = support
    headers = auth(client)
    request_id = str(uuid.uuid4())
    ticket = create(client, headers, request_id).json()["ticket"]["id"]
    assert create(client, headers, request_id).json()["ticket"]["id"] == ticket
    assert create(client, headers).status_code == 409
    message = {"request_id": str(uuid.uuid4()), "body": "Дополнение"}
    for _ in range(2):
        assert (
            client.post(
                f"{BASE}/tickets/{ticket}/messages", headers=headers, json=message
            ).status_code
            == 200
        )
    detail = client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()
    assert len(detail["messages"]) == 3
    cursor = detail["messages"][1]["id"]
    assert (
        len(
            client.get(f"{BASE}/tickets/{ticket}?after={cursor}", headers=headers).json()[
                "messages"
            ]
        )
        == 1
    )


def test_disabled_bot_and_delivery_retry_preserve_history(support):
    app, client, tg, bridge = support
    headers = auth(client)
    app.state.settings.support_enabled = False
    assert client.get(BASE + "/config").json() == {"available": False}
    assert create(client, headers).status_code == 503
    app.state.settings.support_enabled = True
    ticket = create(client, headers).json()["ticket"]["id"]
    tg.failed = True
    bridge.deliver()
    with app.state.session_factory() as db:
        outbox = db.scalar(select(SupportOutbox))
        assert outbox.sent_at is None and outbox.attempts == 1
        outbox.next_attempt_at = utc_now() - timedelta(seconds=1)
        db.commit()
    tg.failed = False
    bridge.deliver()
    assert client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["messages"]
    with app.state.session_factory() as db:
        assert db.scalar(select(SupportOutbox)).sent_at is not None


def test_authentication_revocation_validation_and_rate_limit(support):
    app, client, _tg, _bridge = support
    assert client.get(BASE + "/tickets").status_code == 401
    headers = auth(client)
    bad = {"Authorization": headers["Authorization"] + "x"}
    encoded = headers["Authorization"].split()[1].split(".")[0]
    claims = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
    assert hash_token(KEY) not in claims
    assert KEY not in claims
    assert client.get(BASE + "/tickets", headers=bad).status_code == 401
    ticket = create(client, headers).json()["ticket"]["id"]
    assert (
        client.post(
            f"{BASE}/tickets/{ticket}/messages",
            headers=headers,
            json={"request_id": str(uuid.uuid4()), "body": " "},
        ).status_code
        == 422
    )
    for _ in range(19):
        assert (
            client.post(
                f"{BASE}/tickets/{ticket}/messages",
                headers=headers,
                json={"request_id": str(uuid.uuid4()), "body": "test"},
            ).status_code
            == 200
        )
    assert (
        client.post(
            f"{BASE}/tickets/{ticket}/messages",
            headers=headers,
            json={"request_id": str(uuid.uuid4()), "body": "limit"},
        ).status_code
        == 429
    )
    with app.state.session_factory() as db:
        user = db.scalar(select(UserModel).where(UserModel.activation_key_hash == hash_token(KEY)))
        user.status = "revoked"
        db.commit()
    assert client.get(BASE + "/tickets", headers=headers).status_code == 401
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SupportMessage)) == 21


def test_redaction():
    redacted = safe_text("12 3456 7890 12 vless://secret@host PrivateKey=secret")
    assert "secret" not in redacted
    assert KEY not in redacted


def plain(update_id, body="Обновитесь", sender=1001):
    update = reply(update_id, 0, body, sender)
    del update["message"]["reply_to_message"]
    return update


def test_plain_reply_single_ticket_persists_and_commands_are_not_forwarded(support):
    app, client, tg, bridge = support
    headers = auth(client)
    ticket = create(client, headers).json()["ticket"]["id"]
    bridge.receive(plain(1, "/start"))
    bridge.receive(plain(2, sender=999))
    assert len(client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["messages"]) == 2
    bridge.receive(plain(3))
    bridge.receive(plain(3))
    detail = client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()
    assert detail["ticket"]["status"] == "in_progress"
    assert detail["messages"][-1]["body"] == "Обновитесь"
    assert len(detail["messages"]) == 4
    create(client, auth(client, OTHER_KEY))
    restarted = SupportBridge(app.state.settings, app.state.session_factory, tg)
    restarted.receive(plain(4, "Второе сообщение"))
    assert (
        client.get(f"{BASE}/tickets/{ticket}", headers=headers).json()["messages"][-1]["body"]
        == "Второе сообщение"
    )


def test_multiple_tickets_require_selection_and_operator_choices_are_independent(support):
    app, client, tg, bridge = support
    app.state.settings.support_telegram_admin_ids = "1001,1002"
    headers = auth(client)
    other = auth(client, OTHER_KEY)
    first = create(client, headers).json()["ticket"]["id"]
    second = create(client, other).json()["ticket"]["id"]
    bridge.deliver()
    bridge.receive(plain(1))
    assert "Выберите обращение" in tg.calls[-1][1]["text"]
    bridge.receive(callback(2, 101, first))
    bridge.receive(callback(3, 102, second, sender=1002))
    bridge.receive(plain(4, "Первому"))
    bridge.receive(plain(5, "Второму", sender=1002))
    assert (
        client.get(f"{BASE}/tickets/{first}", headers=headers).json()["messages"][-1]["body"]
        == "Первому"
    )
    assert (
        client.get(f"{BASE}/tickets/{second}", headers=other).json()["messages"][-1]["body"]
        == "Второму"
    )
    bridge.receive(callback(6, 101, second, "select"))  # Mismatched card cannot switch.
    bridge.receive(reply(7, 9999))  # Invalid reply cannot fall back to selection.
    bridge.receive(callback(8, 101, first, "close"))
    bridge.receive(plain(9, "Не отправлять другому"))
    assert "закрыто" in tg.calls[-1][1]["text"]
    bridge.receive(callback(10, 101, first))  # Closed tickets cannot be reopened.
    bridge.receive(callback(11, 102, second, "select"))
    bridge.receive(plain(12, "Выбран второй"))
    detail = client.get(f"{BASE}/tickets/{second}", headers=other).json()
    assert [m["body"] for m in detail["messages"] if m["author"] == "support"] == [
        "Второму",
        "Выбран второй",
    ]
    bridge.deliver()
    cards = [p for m, p in tg.calls if m == "sendMessage" and "reply_markup" in p]
    assert any(
        b["text"] == "Выбрать чат"
        for card in cards
        for row in card["reply_markup"]["inline_keyboard"]
        for b in row
    )


def test_redaction_expansion_keeps_database_and_telegram_limits(support):
    _app, client, tg, bridge = support
    created = client.post(
        BASE + "/tickets",
        headers=auth(client),
        json={
            "request_id": str(uuid.uuid4()),
            "subject": "ss://a " * 17,
            "body": "ss://a " * 285,
            "client_version": "ss://a " * 5,
        },
    )
    assert created.status_code == 201
    assert len(created.json()["ticket"]["subject"]) <= 120
    assert len(created.json()["messages"][0]["body"]) <= 2000
    bridge.deliver()
    assert len(tg.calls[-1][1]["text"]) < 4096
