# Kenai VPN Admin

Локальный переносимый control plane (`PostgreSQL + админ-панель + официальный Xray`) запускается
по инструкции [`docs/local-control-plane.md`](docs/local-control-plane.md). Режим предназначен для
разработки на ПК до покупки российского входного VPS и не изменяет действующий зарубежный сервер.

Модульная административная веб-панель для управления пользователями и устройствами собственного VPN-сервера на AmneziaWG 2.0 и Xray/VLESS + REALITY. Новая выдача WireGuard отключена; код чтения и отзыва старых доступов сохранён, чтобы не прерывать работу существующих пользователей.

Проект создаётся как безопасная основа будущей экосистемы: веб-панели, Telegram-интерфейса и клиентских приложений. Сейчас реализуется локально проверяемый MVP. Он **не изменяет рабочий VPS**, пока production-адаптер и деплой не будут отдельно проверены и разрешены.

## Основные возможности MVP

Чат поддержки в клиенте с ответами через Telegram: [настройка и обновление](docs/support.md).
Новая административная консоль, RBAC, метрики, уведомления и безопасный onboarding описаны в
[`docs/admin-console.md`](docs/admin-console.md).

- локальная административная авторизация;
- пароль Argon2id и TOTP;
- пользователи и несколько устройств на пользователя;
- подписчики клиентского приложения с автоматически созданным ключом активации;
- автоматическая выдача настроенных через `KENAI_SUBSCRIPTION_PROTOCOLS` AmneziaWG и VLESS; сохранённый WireGuard в настройке не выдаётся новым пользователям;
- отдельная вкладка ручной выдачи с автоматическими идентификаторами, выбором AmneziaWG/VLESS, QR и конфигами;
- независимые состояния AmneziaWG и VLESS для каждого устройства;
- выдача одного или сразу двух протоколов;
- одноразовые пакеты конфигураций;
- временное отключение, повторное включение и отзыв;
- аудит административных действий;
- удаление отдельного устройства с автоматическим отзывом только его протоколов;
- безопасное удаление пользователя с отзывом всех принадлежащих ему протоколов;
- управление администраторами, смена пароля и безопасная перепривязка TOTP;
- роли и явные разрешения, отзыв сессий и одноразово показываемые API-токены;
- тарифы и подписки с ручным подтверждением без вымышленного платёжного провайдера;
- серверные метрики каждые пять минут, 30-дневное хранение и честные состояния «нет данных»;
- Telegram-очередь с категориями, ограниченными повторами и журналом доставки;
- поэтапное подключение VPN-узла через HTTPS agent с certificate pinning и rollback;
- фильтры и CSV-экспорт журнала аудита без секретных метаданных;
- живые счётчики AmneziaWG и опциональные счётчики VLESS через локальный Xray Stats API;
- состояние VPN-служб через заменяемый адаптер;
- mock-режим для безопасной локальной разработки.

## Главные правила проекта

- Веб-приложение не запускается от root.
- HTTP API не принимает произвольные shell-команды.
- Production-операции выполняет отдельный ограниченный helper через Unix-сокет.
- У каждого устройства отдельные AmneziaWG-ключи, IP и VLESS UUID.
- Секреты шифруются при хранении и выдаются только через специальный provisioning-процесс.
- Схема БД нормализована и изменяется только миграциями Alembic.
- Тесты никогда не подключаются к рабочему VPS.

Подробные обязательные инструкции для разработчиков и AI находятся в [`AGENTS.md`](AGENTS.md).

Практическая последовательность подготовки российского входа и зарубежного выхода описана в
[`docs/vless-cascade-runbook.md`](docs/vless-cascade-runbook.md).
Текущий зарубежный Debian 13 MVP без собственного домена и его точные ограничения описаны в
[`docs/domainless-foreign-mvp.md`](docs/domainless-foreign-mvp.md).

## Архитектура

```text
Browser
   |
FastAPI web layer
   |
Application use cases
   |-------------------|
Repository ports       VPN manager port
   |                    |
SQLAlchemy/PostgreSQL   Mock adapter (local)
                        Unix-socket helper (production)
                          |-- WireGuard adapter
                          `-- Xray/VLESS adapter
```

Слои и направления зависимостей описаны в [`docs/architecture.md`](docs/architecture.md). Реляционная модель — в [`docs/data-model.md`](docs/data-model.md).

## Быстрый старт для разработки

Требуется Python 3.12+.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
Copy-Item .env.example .env
alembic upgrade head
kenai-admin create-admin
uvicorn kenai_vpn_admin.main:app --reload
```

После запуска откройте `http://127.0.0.1:8000`. Значения для первого администратора вводятся интерактивно; минимальная длина пароля — 10 символов, а секрет TOTP показывается только при создании. Для реальной установки рекомендуется уникальная парольная фраза большей длины.

## Проверки качества

```powershell
ruff format --check .
ruff check .
mypy src
pytest
```

## Конфигурация

Настройки читаются из переменных окружения и `.env`. Полный шаблон находится в [`.env.example`](.env.example). `.env` запрещён к коммиту.

Ключевые режимы:

- `KENAI_ENV=development` — локальная разработка;
- `KENAI_VPN_BACKEND=mock` — никаких обращений к системному WireGuard/Xray;
- `KENAI_COOKIE_SECURE=false` — допустимо только для локального HTTP;
- production требует HTTPS, защищённых cookie и отдельного helper.

Production-helper реализован, но не устанавливается автоматически. Он использует строгий
Unix-socket протокол, root-owned state, проверяемые candidate-файлы, атомарную замену и откат.
Перед деплоем обязательны read-only инвентаризация VPS и проверка адаптеров на копиях именно
действующих `wg0.conf` и Xray JSON. Подробности: [`docs/helper-protocol.md`](docs/helper-protocol.md)
и [`docs/deployment.md`](docs/deployment.md).

## Работа с базой

```powershell
alembic upgrade head
alembic current
alembic history
```

Любое изменение SQLAlchemy-моделей должно сопровождаться миграцией и тестом связей/ограничений.

## GitHub

Репозиторий подготовлен так, чтобы не коммитить секреты, базы, профили и runtime-файлы. Перед первым коммитом:

```powershell
git init
git add .
git status
git commit -m "Initial Kenai VPN Admin MVP"
```

Перед публикацией обязательно убедитесь, что `git status` не содержит `.env`, `*.db`, WireGuard-конфигураций, VLESS URI, архивов выдачи или ключей.

## Документация

- [`docs/architecture.md`](docs/architecture.md) — модули и границы;
- [`docs/security.md`](docs/security.md) — модель безопасности;
- [`docs/data-model.md`](docs/data-model.md) — таблицы, ключи и связи;
- [`docs/development.md`](docs/development.md) — правила изменения проекта;
- [`docs/deployment.md`](docs/deployment.md) — будущий безопасный деплой;
- [`docs/threat-model.md`](docs/threat-model.md) — угрозы и меры защиты.
- [`docs/helper-protocol.md`](docs/helper-protocol.md) — контракт и граница root-helper.
- [`docs/vps-preflight.md`](docs/vps-preflight.md) — безопасная инвентаризация действующего VPS.
- [`docs/vless-cascade-runbook.md`](docs/vless-cascade-runbook.md) — генерация, проверка, применение
  и откат конфигураций каскада VLESS + REALITY.
