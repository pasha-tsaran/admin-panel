"""Interactive server-only setup. Credentials stay in memory and root-owned web.env."""

# ruff: noqa: RUF001
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

RELEASE = Path("/opt/kenai-vpn/releases/support-20260920T131025Z-r4")
ENV = Path("/etc/kenai-vpn/web.env")
STATUS = Path("/var/lib/kenai-vpn-support-deploy.status")


def command(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def replace_env(content: str) -> None:
    metadata = ENV.stat()
    descriptor, temporary = tempfile.mkstemp(prefix=".support-env-", dir=ENV.parent)
    path = Path(temporary)
    try:
        os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(path, ENV)
    finally:
        path.unlink(missing_ok=True)


def main() -> None:
    if os.geteuid() != 0 or not RELEASE.is_dir() or ENV.is_symlink():
        raise RuntimeError("Setup requires the installed release and root")
    sys.path.insert(0, str(RELEASE / "src"))
    from kenai_vpn_admin.config import Settings
    from kenai_vpn_admin.infrastructure.telegram_support import TelegramHttpTransport

    settings_from_file = Settings(_env_file=ENV)
    token = settings_from_file.support_telegram_bot_token.get_secret_value().strip()
    if not token:
        print("Укажите KENAI_SUPPORT_TELEGRAM_BOT_TOKEN в /etc/kenai-vpn/web.env.")
        return
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token):
        raise RuntimeError("Invalid token format")
    telegram = TelegramHttpTransport(token)
    bot = telegram.call("getMe", {})
    if telegram.call("getWebhookInfo", {}).get("url"):
        raise RuntimeError("Use a dedicated bot without a webhook")
    print(f"Бот: @{bot['username']}")
    input("Откройте этого бота в Telegram, отправьте /start и затем нажмите Enter здесь. ")
    updates = telegram.call(
        "getUpdates",
        {"timeout": 10, "limit": 100, "allowed_updates": ["message", "callback_query"]},
    )
    candidates = {}
    for update in updates:
        message = update.get("message", {})
        chat, sender = message.get("chat", {}), message.get("from", {})
        if chat.get("type") == "private" and sender.get("id") == chat.get("id"):
            candidates[chat["id"]] = sender
    ids = list(candidates)
    chat_id = 0
    if ids:
        print("Найдены личные чаты. Выберите свой; 0 — ввести ID вручную.")
        for index, candidate in enumerate(ids, 1):
            print(f"{index}. Telegram ID {candidate}")
        choice = input("Номер: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ids):
            chat_id = ids[int(choice) - 1]
    if not chat_id:
        chat_id = int(input("ID чата или закрытой группы: ").strip())
    if not chat_id:
        raise RuntimeError("Chat ID cannot be zero")
    default_admin = str(chat_id) if chat_id > 0 else ""
    admins = input(f"ID разрешённых операторов через запятую [{default_admin}]: ").strip()
    admins = admins or default_admin
    parts = [part.strip() for part in admins.split(",")]
    if not parts or any(not part.isdigit() or int(part) <= 0 for part in parts):
        raise RuntimeError("Invalid operator IDs")
    admins = ",".join(parts)
    # Confirm that this bot can actually deliver to the explicitly selected chat.
    telegram.call(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": "✅ Kenai VPN: проверка доставки успешна. Завершаем настройку поддержки. "
            "Выберите обращение кнопкой «Взять в работу», затем пишите обычные сообщения.",
        },
    )
    original = ENV.read_text(encoding="utf-8")
    settings = {
        "KENAI_SUPPORT_ENABLED": "true",
        "KENAI_SUPPORT_TELEGRAM_BOT_TOKEN": token,
        "KENAI_SUPPORT_TELEGRAM_CHAT_ID": str(chat_id),
        "KENAI_SUPPORT_TELEGRAM_ADMIN_IDS": admins,
    }
    lines = [
        line for line in original.splitlines() if line.split("=", 1)[0].strip() not in settings
    ]
    updated = "\n".join(lines) + "\n" + "\n".join(f"{k}={v}" for k, v in settings.items()) + "\n"
    backup = Path("/var/backups/kenai-vpn-admin") / (
        "support-config-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    backup.mkdir(mode=0o700)
    shutil.copy2(ENV, backup / "web.env")
    (backup / "web.env").chmod(0o600)
    try:
        replace_env(updated)
        command("systemctl", "enable", "--now", "kenai-vpn-support.service")
        command("systemctl", "restart", "kenai-vpn-web.service")
        time.sleep(3)
        command("systemctl", "is-active", "--quiet", "kenai-vpn-support.service")
        command("systemctl", "is-active", "--quiet", "kenai-vpn-web.service")
        with urllib.request.urlopen(
            "https://88.218.94.3:9443/api/v1/support/config", timeout=15
        ) as r:
            import json

            if json.load(r) != {"available": True}:
                raise RuntimeError("Public support endpoint is unavailable")
    except (Exception, KeyboardInterrupt):
        replace_env(original)
        subprocess.run(
            ["systemctl", "disable", "--now", "kenai-vpn-support.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["systemctl", "restart", "kenai-vpn-web.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        raise RuntimeError("Configuration rolled back") from None
    if STATUS.is_symlink():
        raise RuntimeError("Unexpected status path")
    STATUS.write_text("support_deploy=active; bot=configured; telegram_delivery=verified\n")
    STATUS.chmod(0o644)
    print("Готово. Поддержка включена, доставка в Telegram проверена. Токен не выводился.")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print(
            "Настройка не завершена. Проверьте токен, выбранные ID и доступ к Telegram. "
            "Не отправляйте секреты в чат.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
