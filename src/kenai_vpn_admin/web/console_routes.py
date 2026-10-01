from __future__ import annotations

import contextlib
import csv
import io
import math
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import desc, select
from sqlalchemy.orm import selectinload

from kenai_vpn_admin.application.console import NOTIFICATION_CATEGORIES
from kenai_vpn_admin.application.rbac import PERMISSIONS, effective_permissions
from kenai_vpn_admin.application.services import DomainConflictError
from kenai_vpn_admin.domain.enums import NodeRole, Protocol
from kenai_vpn_admin.infrastructure.models import (
    ApiTokenModel,
    AuditEventModel,
    NodeOnboardingModel,
    NotificationDeliveryModel,
    SessionModel,
    SubscriptionEventModel,
    SubscriptionModel,
    SubscriptionPlanModel,
    TelegramRecipientModel,
    UserModel,
    VpnNodeModel,
    naive_utc,
    utc_now,
)
from kenai_vpn_admin.infrastructure.node_agent import NodeAgentClient
from kenai_vpn_admin.security import verify_password
from kenai_vpn_admin.web.dependencies import CsrfAdmin, CurrentAdmin, DbSession
from kenai_vpn_admin.web.routes import correlation_id, render

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    service = request.app.state.console_service
    summary = service.summary(db)
    users = request.app.state.admin_service.list_users(db)
    subscription_users = [user for user in users if user.activation_key_hash is not None]
    latest_users = sorted(users, key=lambda item: item.created_at, reverse=True)[:5]
    events = list(
        db.scalars(
            select(AuditEventModel)
            .options(selectinload(AuditEventModel.administrator))
            .order_by(desc(AuditEventModel.occurred_at))
            .limit(6)
        )
    )
    try:
        health = request.app.state.vpn_manager.health()
    except RuntimeError:
        health = None
    try:
        runtime_summary = request.app.state.admin_service.dashboard_runtime_summary(
            subscription_users
        )
    except RuntimeError:
        runtime_summary = None
    return render(
        request,
        "home.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "summary": summary,
            "latest_users": latest_users,
            "events": events,
            "health": health,
            "runtime_summary": runtime_summary,
            "metrics": service.metrics(db, hours=24),
            "nodes": list(db.scalars(select(VpnNodeModel).order_by(VpnNodeModel.display_name))),
            "permissions": effective_permissions(current.administrator),
        },
    )


def _filtered_users(
    request: Request,
    db: DbSession,
    *,
    query: str,
    status: str,
    protocol: str,
    subscription: str,
) -> list[UserModel]:
    users = request.app.state.admin_service.list_users(db)
    needle = query.strip().casefold()
    now = utc_now()
    result: list[UserModel] = []
    for user in users:
        search_text = " ".join(
            filter(
                None,
                (
                    user.display_name,
                    user.slug,
                    user.email,
                    user.telegram_username,
                    user.phone_number,
                    request.app.state.admin_service.activation_key_for_admin(user),
                ),
            )
        ).casefold()
        if needle and needle not in search_text:
            continue
        if status and user.status != status:
            continue
        if subscription == "active" and (
            user.subscription_expires_at is None or naive_utc(user.subscription_expires_at) <= now
        ):
            continue
        if subscription == "expired" and (
            user.subscription_expires_at is None or naive_utc(user.subscription_expires_at) > now
        ):
            continue
        if protocol:
            has_protocol = any(
                (
                    protocol == "amneziawg"
                    and device.amneziawg is not None
                    and device.amneziawg.status != "revoked"
                )
                or (
                    protocol == "vless"
                    and device.vless is not None
                    and device.vless.status != "revoked"
                )
                for device in user.devices
            )
            if not has_protocol:
                continue
        result.append(user)
    return result


@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    db: DbSession,
    current: CurrentAdmin,
    q: str = "",
    status: str = "",
    protocol: str = "",
    subscription: str = "",
    page: int = 1,
    per_page: int = 20,
) -> HTMLResponse:
    per_page = max(10, min(per_page, 100))
    users = _filtered_users(
        request,
        db,
        query=q[:120],
        status=status,
        protocol=protocol,
        subscription=subscription,
    )
    page_count = max(1, math.ceil(len(users) / per_page))
    page = max(1, min(page, page_count))
    start = (page - 1) * per_page
    return render(
        request,
        "users.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "users": users[start : start + per_page],
            "total": len(users),
            "page": page,
            "page_count": page_count,
            "per_page": per_page,
            "filters": {
                "q": q,
                "status": status,
                "protocol": protocol,
                "subscription": subscription,
            },
        },
    )


@router.get("/users/export.csv")
def export_users(
    request: Request,
    db: DbSession,
    current: CurrentAdmin,
    q: str = "",
    status: str = "",
    protocol: str = "",
    subscription: str = "",
) -> Response:
    del current
    users = _filtered_users(
        request,
        db,
        query=q[:120],
        status=status,
        protocol=protocol,
        subscription=subscription,
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(("name", "id", "email", "telegram", "phone", "status", "expires_at", "devices"))
    for user in users:
        writer.writerow(
            (
                user.display_name,
                user.slug,
                user.email or "",
                user.telegram_username or "",
                user.phone_number or "",
                user.status,
                user.subscription_expires_at.isoformat() if user.subscription_expires_at else "",
                len(user.devices),
            )
        )
    return Response(
        "\ufeff" + stream.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=kenai-users.csv"},
    )


@router.get("/issuance", response_class=HTMLResponse)
def issuance_page(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    recent = list(
        db.scalars(
            select(UserModel)
            .where(UserModel.activation_key_hash.is_(None))
            .options(selectinload(UserModel.devices))
            .order_by(desc(UserModel.created_at))
            .limit(5)
        )
    )
    return render(
        request,
        "issuance.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "recent": recent,
            "primary_server": request.app.state.settings.primary_address or None,
        },
    )


@router.post("/issuance", response_class=HTMLResponse)
def issue_access(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    display_name: Annotated[str, Form(min_length=1, max_length=120)],
    duration_days: Annotated[int, Form(ge=1, le=3650)] = 30,
    device_limit: Annotated[int, Form(ge=1, le=1000)] = 1,
    server: Annotated[str, Form(max_length=64)] = "primary",
    amneziawg: Annotated[bool, Form()] = False,
    vless: Annotated[bool, Form()] = False,
    comment: Annotated[str, Form(max_length=1000)] = "",
) -> HTMLResponse:
    if server != "primary":
        raise HTTPException(
            status_code=422, detail="Выбранный сервер не поддерживает ручную выдачу"
        )
    protocols = {
        protocol
        for protocol, selected in (
            (Protocol.AMNEZIAWG, amneziawg),
            (Protocol.VLESS, vless),
        )
        if selected
    }
    if not protocols or not protocols <= request.app.state.settings.issuable_protocol_set:
        raise HTTPException(status_code=422, detail="Выберите доступный протокол")
    created_ref = ""
    try:
        user = request.app.state.admin_service.create_user(
            db,
            slug=None,
            display_name=display_name,
            comment=comment,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        user.subscription_expires_at = request.app.state.admin_service.subscription_expiry(
            days=duration_days, until=None
        )
        user.device_limit = device_limit
        device = request.app.state.admin_service.create_device(
            db,
            user_id=user.id,
            slug="primary",
            display_name="Основное устройство",
            protocols=protocols,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        created_ref = f"{user.slug}-{device.slug}"
        package = request.app.state.admin_service.create_package(
            db,
            device_id=device.id,
            protocols=protocols,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except Exception:
        db.rollback()
        if created_ref:
            request.app.state.admin_service.compensate_device_creation(created_ref, protocols)
        raise
    return render(
        request,
        "issuance_result.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "user": user,
            "device": device,
            "protocols": protocols,
            "expires_at": package.expires_at,
            "download_url": f"/provision/{package.token}",
        },
        status_code=201,
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    return _render_settings(request, db, current)


def _render_settings(
    request: Request,
    db: DbSession,
    current: CurrentAdmin,
    *,
    one_time_token: str | None = None,
) -> HTMLResponse:
    return render(
        request,
        "settings.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "settings": request.app.state.console_service.settings_map(db),
            "recipients": list(
                db.scalars(select(TelegramRecipientModel).order_by(TelegramRecipientModel.label))
            ),
            "deliveries": list(
                db.scalars(
                    select(NotificationDeliveryModel)
                    .order_by(desc(NotificationDeliveryModel.created_at))
                    .limit(20)
                )
            ),
            "api_tokens": list(
                db.scalars(select(ApiTokenModel).order_by(desc(ApiTokenModel.created_at)))
            ),
            "plans": request.app.state.console_service.plans(db),
            "subscriptions": request.app.state.console_service.subscriptions(db, limit=50),
            "categories": sorted(NOTIFICATION_CATEGORIES),
            "all_permissions": sorted(PERMISSIONS),
            "one_time_token": one_time_token,
            "telegram_configured": bool(
                request.app.state.settings.notification_telegram_bot_token.get_secret_value()
            ),
        },
    )


@router.post("/settings/general")
def save_general_settings(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    system_name: Annotated[str, Form(min_length=1, max_length=120)],
    timezone: Annotated[str, Form(max_length=64)] = "Europe/Moscow",
    inactivity_minutes: Annotated[int, Form(ge=5, le=1440)] = 30,
) -> Response:
    request.app.state.console_service.set_setting(
        db,
        key="general",
        value={
            "system_name": system_name.strip(),
            "timezone": timezone,
            "inactivity_minutes": inactivity_minutes,
        },
        administrator_id=current.administrator.id,
    )
    db.commit()
    return RedirectResponse("/settings?section=general&notice=saved", status_code=303)


@router.post("/settings/telegram/recipients")
def save_telegram_recipient(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    label: Annotated[str, Form(min_length=1, max_length=120)],
    chat_id: Annotated[int, Form()],
    categories: Annotated[list[str] | None, Form()] = None,
) -> Response:
    request.app.state.console_service.save_recipient(
        db, label=label, chat_id=chat_id, categories=categories or []
    )
    db.commit()
    return RedirectResponse("/settings?section=telegram&notice=saved", status_code=303)


@router.post("/settings/telegram/test")
def test_telegram(request: Request, db: DbSession, current: CsrfAdmin) -> Response:
    queued = request.app.state.console_service.queue_notification(
        db,
        category="critical_admin_action",
        message=f"Kenai VPN: тестовое уведомление от {current.administrator.username}",
    )
    sent = request.app.state.console_service.send_pending_notifications(db)
    db.commit()
    if not request.app.state.settings.notification_telegram_bot_token.get_secret_value():
        notice = "test-queued-no-token" if queued else "test-no-recipients"
    elif queued and sent == queued:
        notice = "test-sent"
    else:
        notice = "test-queued"
    return RedirectResponse(f"/settings?section=telegram&notice={notice}", status_code=303)


@router.post("/settings/api-tokens", response_class=HTMLResponse)
def create_api_token(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    name: Annotated[str, Form(min_length=1, max_length=120)],
    permissions: Annotated[list[str] | None, Form()] = None,
    expires_in_days: Annotated[int | None, Form(ge=1, le=3650)] = None,
) -> HTMLResponse:
    _, plaintext = request.app.state.console_service.create_api_token(
        db,
        name=name,
        permissions=permissions or [],
        created_by_id=current.administrator.id,
        expires_in_days=expires_in_days,
    )
    db.commit()
    response = _render_settings(request, db, current, one_time_token=plaintext)
    response.headers["Cache-Control"] = "no-store"
    return response


def _verify_critical(request: Request, current: CsrfAdmin, password: str, totp: str) -> None:
    if not verify_password(current.administrator.password_hash, password):
        raise HTTPException(status_code=403, detail="Подтверждение отклонено")
    if not request.app.state.auth_service.verify_totp(current.administrator, totp):
        raise HTTPException(status_code=403, detail="Подтверждение отклонено")


@router.post("/settings/api-tokens/{token_id}/revoke")
def revoke_api_token(
    request: Request,
    token_id: str,
    db: DbSession,
    current: CsrfAdmin,
    acting_password: Annotated[str, Form(min_length=1, max_length=512)],
    acting_totp: Annotated[str, Form(min_length=6, max_length=8)],
) -> Response:
    _verify_critical(request, current, acting_password, acting_totp)
    request.app.state.console_service.revoke_api_token(db, token_id)
    request.app.state.console_service.queue_notification(
        db,
        category="critical_admin_action",
        message=f"Kenai VPN: {current.administrator.username} отозвал API-токен {token_id}.",
    )
    db.commit()
    return RedirectResponse("/settings?section=api&notice=revoked", status_code=303)


@router.post("/settings/billing/plans")
def create_subscription_plan(
    db: DbSession,
    current: CsrfAdmin,
    slug: Annotated[str, Form(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=64)],
    display_name: Annotated[str, Form(min_length=1, max_length=120)],
    duration_days: Annotated[int, Form(ge=1, le=3650)],
    price_minor: Annotated[int, Form(ge=0, le=100_000_000)],
    currency: Annotated[str, Form(min_length=3, max_length=3)] = "RUB",
    device_limit: Annotated[int, Form(ge=1, le=1000)] = 1,
) -> Response:
    del current
    if db.scalar(select(SubscriptionPlanModel.id).where(SubscriptionPlanModel.slug == slug)):
        raise HTTPException(status_code=409, detail="Идентификатор тарифа уже занят")
    db.add(
        SubscriptionPlanModel(
            slug=slug,
            display_name=display_name.strip(),
            duration_days=duration_days,
            price_minor=price_minor,
            currency=currency.upper(),
            device_limit=device_limit,
        )
    )
    db.commit()
    return RedirectResponse("/settings?section=billing&notice=plan-created", status_code=303)


@router.post("/settings/billing/subscriptions/{subscription_id}/confirm")
def confirm_subscription(
    request: Request,
    subscription_id: str,
    db: DbSession,
    current: CsrfAdmin,
    acting_password: Annotated[str, Form(min_length=1, max_length=512)],
    acting_totp: Annotated[str, Form(min_length=6, max_length=8)],
) -> Response:
    _verify_critical(request, current, acting_password, acting_totp)
    subscription = db.get(SubscriptionModel, subscription_id)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Подписка не найдена")
    old_status = subscription.status
    subscription.status = "active"
    subscription.confirmed_at = utc_now()
    subscription.confirmed_by_id = current.administrator.id
    db.add(
        SubscriptionEventModel(
            subscription_id=subscription.id,
            administrator_id=current.administrator.id,
            event_type="manual_confirm",
            old_status=old_status,
            new_status="active",
            details_json={"provider": None, "automatic_payment": False},
        )
    )
    db.commit()
    return RedirectResponse("/settings?section=billing&notice=confirmed", status_code=303)


@router.post("/administrators/{administrator_id}/access")
def change_administrator_access(
    request: Request,
    administrator_id: str,
    db: DbSession,
    current: CsrfAdmin,
    role: Annotated[str, Form(max_length=32)],
    permissions: Annotated[list[str] | None, Form()] = None,
    acting_password: Annotated[str, Form(min_length=1, max_length=512)] = "",
    acting_totp: Annotated[str, Form(min_length=6, max_length=8)] = "",
) -> Response:
    try:
        request.app.state.admin_service.set_administrator_access(
            db,
            target_id=administrator_id,
            role=role,
            permissions=permissions or [],
            acting_administrator=current.administrator,
            acting_password=acting_password,
            acting_totp=acting_totp,
            current_session_id=current.session.id,
            correlation_id=correlation_id(request),
        )
        request.app.state.console_service.queue_notification(
            db,
            category="critical_admin_action",
            message=(
                f"Kenai VPN: {current.administrator.username} изменил права "
                f"администратора {administrator_id}."
            ),
        )
        db.commit()
    except (ValueError, DomainConflictError):
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return RedirectResponse("/administrators?notice=access", status_code=303)


@router.post("/administrators/sessions/{session_id}/revoke")
def revoke_administrator_session(
    request: Request,
    session_id: str,
    db: DbSession,
    current: CsrfAdmin,
    acting_password: Annotated[str, Form(min_length=1, max_length=512)],
    acting_totp: Annotated[str, Form(min_length=6, max_length=8)],
) -> Response:
    _verify_critical(request, current, acting_password, acting_totp)
    session = db.get(SessionModel, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    session.revoked_at = utc_now()
    request.app.state.console_service.queue_notification(
        db,
        category="critical_admin_action",
        message=f"Kenai VPN: {current.administrator.username} отозвал сессию {session_id}.",
    )
    db.commit()
    return RedirectResponse("/administrators?notice=session", status_code=303)


@router.post("/topology/onboarding/preflight")
def node_onboarding_preflight(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    node_slug: Annotated[str, Form(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=64)],
    display_name: Annotated[str, Form(min_length=1, max_length=120)],
    role: Annotated[str, Form(max_length=16)],
    country_code: Annotated[str, Form(min_length=2, max_length=2)],
    city: Annotated[str, Form(min_length=1, max_length=120)],
    public_endpoint: Annotated[str, Form(min_length=1, max_length=253)],
    agent_endpoint: Annotated[str, Form(min_length=1, max_length=512)],
    certificate_sha256: Annotated[str, Form(min_length=64, max_length=95)],
    enrollment_token: Annotated[str, Form(min_length=1, max_length=512)],
) -> Response:
    try:
        selected_role = NodeRole(role)
        client = NodeAgentClient(agent_endpoint, certificate_sha256)
        report = client.preflight(enrollment_token)
        agent_version = report.get("agent_version")
        identity = report.get("identity_key_sha256")
        capabilities = report.get("capabilities")
        if (
            not isinstance(agent_version, str)
            or not isinstance(identity, str)
            or len(identity) != 64
            or not isinstance(capabilities, list)
            or any(not isinstance(item, str) for item in capabilities)
        ):
            raise RuntimeError("agent_preflight_invalid")
        attempt = NodeOnboardingModel(
            administrator_id=current.administrator.id,
            node_slug=node_slug,
            agent_endpoint=agent_endpoint,
            expected_certificate_sha256=certificate_sha256.lower().replace(":", ""),
            stage="preview",
            status="passed",
            preview_json={
                "display_name": display_name,
                "role": selected_role.value,
                "country_code": country_code.upper(),
                "city": city,
                "public_endpoint": public_endpoint,
                "agent_version": agent_version,
                "identity_key_sha256": identity,
                "capabilities": capabilities,
            },
        )
        db.add(attempt)
        db.commit()
    except (ValueError, RuntimeError, OSError):
        db.rollback()
        return RedirectResponse("/topology?notice=onboarding-failed", status_code=303)
    return RedirectResponse(
        f"/topology?notice=onboarding-preview&attempt={attempt.id}", status_code=303
    )


@router.post("/topology/onboarding/{attempt_id}/register")
def node_onboarding_register(
    request: Request,
    attempt_id: str,
    db: DbSession,
    current: CsrfAdmin,
    enrollment_token: Annotated[str, Form(min_length=1, max_length=512)],
    acting_password: Annotated[str, Form(min_length=1, max_length=512)],
    acting_totp: Annotated[str, Form(min_length=6, max_length=8)],
) -> Response:
    _verify_critical(request, current, acting_password, acting_totp)
    attempt = db.get(NodeOnboardingModel, attempt_id)
    if attempt is None or attempt.status != "passed" or attempt.stage != "preview":
        raise HTTPException(status_code=409, detail="Onboarding preview is unavailable")
    preview = attempt.preview_json
    client = NodeAgentClient(attempt.agent_endpoint, attempt.expected_certificate_sha256)
    registered = False
    try:
        attempt.stage = "registration"
        attempt.status = "running"
        result = client.register(
            enrollment_token, node_slug=attempt.node_slug, role=str(preview["role"])
        )
        registered = result.get("registered") is True
        if not registered or result.get("health") != "online":
            raise RuntimeError("agent_health_failed")
        request.app.state.cascade_service.create_node(
            db,
            slug=attempt.node_slug,
            display_name=str(preview["display_name"]),
            role=NodeRole(str(preview["role"])),
            country_code=str(preview["country_code"]),
            city=str(preview["city"]),
            public_endpoint=str(preview["public_endpoint"]),
            agent_endpoint=attempt.agent_endpoint,
            certificate_sha256=attempt.expected_certificate_sha256,
        )
        attempt.stage = "complete"
        attempt.status = "passed"
        request.app.state.console_service.queue_notification(
            db,
            category="critical_admin_action",
            message=(
                f"Kenai VPN: {current.administrator.username} зарегистрировал "
                f"VPN-узел {attempt.node_slug}."
            ),
        )
        db.commit()
    except Exception:
        db.rollback()
        if registered:
            with contextlib.suppress(Exception):
                client.rollback(enrollment_token, node_slug=attempt.node_slug)
        with request.app.state.session_factory() as repair_db:
            repair = repair_db.get(NodeOnboardingModel, attempt_id)
            if repair is not None:
                repair.stage = "rollback"
                repair.status = "rolled_back" if registered else "failed"
                repair.error_code = "registration_failed"
                repair_db.commit()
        return RedirectResponse("/topology?notice=onboarding-failed", status_code=303)
    return RedirectResponse("/topology?notice=node-created", status_code=303)
