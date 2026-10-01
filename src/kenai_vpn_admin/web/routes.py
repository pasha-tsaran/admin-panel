from __future__ import annotations

import base64
import csv
import io
import uuid
from datetime import UTC, date, datetime, time
from typing import Annotated, Any, cast
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import selectinload

from kenai_vpn_admin.application.cascade import subscription_timestamp
from kenai_vpn_admin.application.rbac import PERMISSIONS, ROLE_DEFAULTS, effective_permissions
from kenai_vpn_admin.application.services import DomainConflictError, NotFoundError
from kenai_vpn_admin.domain.enums import NodeRole, Protocol
from kenai_vpn_admin.domain.validation import normalize_username
from kenai_vpn_admin.infrastructure.models import (
    AdministratorModel,
    AuditEventModel,
    NodeOnboardingModel,
    ServerMetricModel,
    SessionModel,
    utc_now,
)
from kenai_vpn_admin.security import verify_password
from kenai_vpn_admin.web.dependencies import (
    CsrfAdmin,
    CurrentAdmin,
    CurrentDevice,
    DbSession,
)

router = APIRouter()


class ActivationRequest(BaseModel):
    activation_key: str = Field(pattern=r"^\d{12}$")
    device_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


def render(
    request: Request, template: str, context: dict[str, Any], status_code: int = 200
) -> HTMLResponse:
    labels = {
        Protocol.AMNEZIAWG: "AmneziaWG 2.0",
        Protocol.VLESS: "VLESS",
    }
    configured = request.app.state.settings.issuable_protocol_set
    base: dict[str, Any] = {
        "request": request,
        "app_name": "Kenai VPN Admin",
        "subscription_protocol_names": ", ".join(
            labels[protocol] for protocol in Protocol if protocol in configured
        ),
        "amneziawg_configured": Protocol.AMNEZIAWG in configured,
        "vless_configured": Protocol.VLESS in configured,
    }
    base.update(context)
    current = context.get("current")
    if current is not None:
        base["permissions"] = effective_permissions(current.administrator)
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request, template, base, status_code=status_code
        ),
    )


def correlation_id(request: Request) -> str:
    return getattr(request.state, "correlation_id", str(uuid.uuid4()))


def safe_referer(request: Request, default: str = "/") -> str:
    referer = request.headers.get("referer")
    if not referer:
        return default
    parsed = urlsplit(referer)
    if parsed.scheme and parsed.scheme != request.url.scheme:
        return default
    if parsed.netloc and parsed.netloc != request.url.netloc:
        return default
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return default
    target = parsed.path
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return target


def verify_critical_action(
    request: Request, current: CsrfAdmin, password: str, totp_code: str
) -> None:
    if not verify_password(current.administrator.password_hash, password):
        raise HTTPException(status_code=403, detail="Administrator verification failed")
    if not request.app.state.auth_service.verify_totp(current.administrator, totp_code):
        raise HTTPException(status_code=403, detail="Administrator verification failed")


def subscription_period(
    period_type: str, custom_days: str, expires_on: str
) -> tuple[int | None, date | None]:
    if period_type in {"3", "30"}:
        return int(period_type), None
    if period_type == "custom_days":
        try:
            return int(custom_days), None
        except ValueError as exc:
            raise ValueError("Subscription duration is invalid") from exc
    if period_type == "date":
        try:
            return None, date.fromisoformat(expires_on)
        except ValueError as exc:
            raise ValueError("Subscription date is invalid") from exc
    raise ValueError("Subscription period is required")


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/api/v1/activate")
def activate(request: Request, payload: ActivationRequest, db: DbSession) -> JSONResponse:
    remote_address = request.client.host if request.client else "unknown"
    admin_service = request.app.state.admin_service
    if admin_service.activation_is_rate_limited(db, remote_address):
        raise HTTPException(status_code=429, detail="Too many activation attempts")
    created_ref: str | None = None
    issued_protocols: set[Protocol] = set()
    try:
        if payload.device_id is None:
            account = admin_service.activate_account(db, payload.activation_key)
        else:
            result = admin_service.activate_subscription_device(
                db, payload.activation_key, payload.device_id
            )
            account, created_ref, issued_protocols = (
                result if result is not None else (None, None, set())
            )
        admin_service.record_activation_attempt(db, remote_address, succeeded=account is not None)
        db.commit()
    except DomainConflictError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Device limit reached") from exc
    except Exception:
        db.rollback()
        if created_ref is not None:
            admin_service.compensate_device_creation(created_ref, issued_protocols)
        raise
    if account is None:
        raise HTTPException(status_code=401, detail="Invalid activation key")
    netherlands = request.app.state.settings.netherlands_exit
    netherlands_awg = request.app.state.settings.netherlands_awg_exit
    netherlands_profiles: dict[str, str] = {}
    if netherlands is not None and account.vless_uri is not None:
        netherlands_profiles["vless"] = netherlands.profile_from(account.vless_uri)
    if netherlands_awg is not None and account.amneziawg_config is not None:
        netherlands_profiles["amneziawg"] = netherlands_awg.profile_from(account.amneziawg_config)
    return JSONResponse(
        {
            "account": {
                "id": account.user_id,
                "email": account.email,
                "telegram_username": account.telegram_username,
                "phone_number": account.phone_number,
            },
            "protocols": {
                "wireguard": account.wireguard_config,
                "amneziawg": account.amneziawg_config,
                "vless": account.vless_uri,
            },
            "locations": ({"netherlands-1": netherlands_profiles} if netherlands_profiles else {}),
            "subscription": {
                "status": "active",
                "expires_at": subscription_timestamp(account.subscription_expires_at),
                "device_limit": request.app.state.settings.max_subscription_devices,
            },
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.post("/api/v2/activate")
def activate_v2(request: Request, payload: ActivationRequest, db: DbSession) -> JSONResponse:
    remote_address = request.client.host if request.client else "unknown"
    admin_service = request.app.state.admin_service
    if admin_service.activation_is_rate_limited(db, remote_address):
        raise HTTPException(status_code=429, detail="Too many activation attempts")
    activation = request.app.state.cascade_service.activate_device(db, payload.activation_key)
    admin_service.record_activation_attempt(db, remote_address, succeeded=activation is not None)
    db.commit()
    if activation is None:
        raise HTTPException(status_code=401, detail="Invalid activation key")
    return JSONResponse(
        {
            "account": {
                "id": activation.user.id,
                "email": activation.user.email,
                "telegram_username": activation.user.telegram_username,
                "phone_number": activation.user.phone_number,
            },
            "device": {
                "id": activation.device.id,
                "display_name": activation.device.display_name,
            },
            "subscription": {
                "status": "active",
                "expires_at": subscription_timestamp(activation.user.subscription_expires_at),
            },
            "access_token": activation.access_token,
            "token_type": "Bearer",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.get("/api/v2/subscription")
def subscription_v2(current: CurrentDevice) -> JSONResponse:
    user = current.token.device.user
    return JSONResponse(
        {
            "status": "active",
            "expires_at": subscription_timestamp(user.subscription_expires_at),
            "device_id": current.token.device_id,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/api/v2/locations")
def locations_v2(request: Request, db: DbSession, current: CurrentDevice) -> JSONResponse:
    del current
    locations = request.app.state.cascade_service.list_locations(db)
    return JSONResponse(
        {
            "locations": [
                {
                    "id": location.id,
                    "country_code": location.country_code,
                    "country_name": location.country_name,
                    "city": location.city,
                    "name": location.display_name,
                    "status": location.status,
                    "available": request.app.state.cascade_service.location_available(location),
                    "latency_ms": location.latency_ms,
                    "load_percent": location.exit_node.load_percent,
                    "last_checked_at": subscription_timestamp(location.last_probe_at),
                    "recommended": location.is_recommended,
                    "protocols": ["vless-reality"],
                }
                for location in locations
            ]
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/api/v2/locations/{location_id}/profile")
def location_profile_v2(
    request: Request,
    location_id: str,
    db: DbSession,
    current: CurrentDevice,
) -> JSONResponse:
    try:
        profile = request.app.state.cascade_service.profile_for_location(
            db, current.token.device, location_id
        )
        db.commit()
    except NotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainConflictError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return JSONResponse(
        {
            "profile": {
                "id": profile.id,
                "location_id": profile.location_id,
                "protocol": profile.protocol,
                "client_uri": profile.client_uri,
            }
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return render(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    db: DbSession,
    username: str = Form(min_length=1, max_length=80),
    password: str = Form(min_length=1, max_length=512),
    totp_code: str = Form(default="", max_length=8),
) -> Response:
    normalized_username = normalize_username(username)
    remote_address = request.client.host if request.client else "unknown"
    auth = request.app.state.auth_service
    if auth.is_rate_limited(db, normalized_username, remote_address):
        return render(
            request,
            "login.html",
            {"error": "Слишком много попыток. Повторите позднее."},
            status_code=429,
        )
    administrator = db.scalar(
        select(AdministratorModel).where(AdministratorModel.username == normalized_username)
    )
    password_valid = bool(
        administrator
        and administrator.is_active
        and verify_password(administrator.password_hash, password)
    )
    totp_valid = bool(
        not request.app.state.settings.login_totp_required
        or (
            administrator
            and administrator.totp_confirmed
            and auth.verify_totp(administrator, totp_code)
        )
    )
    valid = password_valid and totp_valid
    auth.record_attempt(db, normalized_username, remote_address, succeeded=valid)
    if not valid or administrator is None:
        db.commit()
        return render(
            request,
            "login.html",
            {"error": "Неверные данные входа."},
            status_code=401,
        )
    new_session = auth.create_session(
        db, administrator, remote_address, request.headers.get("user-agent")
    )
    db.commit()
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "kenai_session",
        new_session.cookie_token,
        httponly=True,
        secure=request.app.state.settings.cookie_secure,
        samesite="strict",
        max_age=request.app.state.settings.session_ttl_minutes * 60,
        path="/",
    )
    response.set_cookie(
        "kenai_csrf",
        new_session.csrf_token,
        httponly=False,
        secure=request.app.state.settings.cookie_secure,
        samesite="strict",
        max_age=request.app.state.settings.session_ttl_minutes * 60,
        path="/",
    )
    return response


@router.post("/logout")
def logout(request: Request, db: DbSession, current: CsrfAdmin) -> Response:
    request.app.state.auth_service.revoke_session(current.session)
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("kenai_session", path="/")
    response.delete_cookie("kenai_csrf", path="/")
    return response


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    return _dashboard(request, db, current, legacy_mode=False)


@router.get("/legacy", response_class=HTMLResponse)
def legacy_dashboard(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    return _dashboard(request, db, current, legacy_mode=True)


def _dashboard(
    request: Request, db: DbSession, current: CurrentAdmin, *, legacy_mode: bool
) -> HTMLResponse:
    all_users = request.app.state.admin_service.list_users(db)
    users = [user for user in all_users if (user.activation_key_hash is None) == legacy_mode]
    try:
        health = request.app.state.vpn_manager.health()
    except RuntimeError:
        health = None
    device_count = sum(len(user.devices) for user in users)
    runtime_summary = None
    runtime_available = True
    notice = request.query_params.get("notice")
    notice_messages = {
        "user-conflict": "Идентификатор уже занят.",
        "user-invalid": "Проверьте имя и выбранные протоколы.",
    }
    try:
        runtime_summary = request.app.state.admin_service.dashboard_runtime_summary(users)
    except RuntimeError:
        runtime_available = False
    return render(
        request,
        "dashboard.html",
        {
            "current": current,
            "users": users,
            "health": health,
            "device_count": device_count,
            "runtime_summary": runtime_summary,
            "runtime_available": runtime_available,
            "notice_message": notice_messages.get(notice) if notice else None,
            "csrf_token": current.csrf_token,
            "legacy_mode": legacy_mode,
        },
    )


@router.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    service = request.app.state.cascade_service
    settings = request.app.state.settings
    configured_servers: list[dict[str, str]] = []
    if settings.primary_address:
        configured_servers.append(
            {
                "name": settings.primary_country_name,
                "location": f"{settings.primary_country_name} · {settings.primary_city}",
                "address": settings.primary_address,
                "kind": "Основной VPN-сервер",
            }
        )
    netherlands = settings.netherlands_exit
    if netherlands is not None:
        configured_servers.append(
            {
                "name": "Нидерланды",
                "location": "Нидерланды · Амстердам",
                "address": netherlands.address,
                "kind": "Прямой VLESS-выход",
            }
        )
    try:
        health = request.app.state.vpn_manager.health()
    except RuntimeError:
        health = None
    attempt_id = request.query_params.get("attempt", "")[:36]
    onboarding_preview = db.get(NodeOnboardingModel, attempt_id) if attempt_id else None
    return render(
        request,
        "topology.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "nodes": service.list_nodes(db),
            "locations": service.list_locations(db, include_disabled=True),
            "configured_servers": configured_servers,
            "health": health,
            "latest_metrics": list(
                db.scalars(
                    select(ServerMetricModel)
                    .order_by(desc(ServerMetricModel.captured_at))
                    .limit(20)
                )
            ),
            "onboarding_preview": onboarding_preview,
            "notice": request.query_params.get("notice"),
        },
    )


@router.post("/topology/nodes")
def create_topology_node(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    slug: str = Form(min_length=1, max_length=64),
    display_name: str = Form(min_length=1, max_length=120),
    role: str = Form(max_length=16),
    country_code: str = Form(min_length=2, max_length=2),
    city: str = Form(min_length=1, max_length=120),
    public_endpoint: str = Form(min_length=1, max_length=253),
    agent_endpoint: str = Form(default="", max_length=512),
    certificate_sha256: str = Form(default="", max_length=95),
) -> Response:
    del current
    try:
        request.app.state.cascade_service.create_node(
            db,
            slug=slug,
            display_name=display_name,
            role=NodeRole(role),
            country_code=country_code,
            city=city,
            public_endpoint=public_endpoint,
            agent_endpoint=agent_endpoint,
            certificate_sha256=certificate_sha256,
        )
        db.commit()
    except (ValueError, DomainConflictError):
        db.rollback()
        return RedirectResponse("/topology?notice=node-invalid", status_code=303)
    return RedirectResponse("/topology?notice=node-created", status_code=303)


@router.post("/topology/locations")
def create_topology_location(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    slug: str = Form(min_length=1, max_length=64),
    country_code: str = Form(min_length=2, max_length=2),
    country_name: str = Form(min_length=1, max_length=120),
    city: str = Form(min_length=1, max_length=120),
    display_name: str = Form(min_length=1, max_length=120),
    ingress_node_id: str = Form(min_length=36, max_length=36),
    exit_node_id: str = Form(min_length=36, max_length=36),
    exit_port: int = Form(default=443, ge=1, le=65535),
    link_uuid: str = Form(min_length=36, max_length=36),
    server_name: str = Form(min_length=1, max_length=253),
    reality_public_key: str = Form(min_length=20, max_length=128),
    short_id: str = Form(min_length=2, max_length=16),
    sort_order: int = Form(default=100, ge=0, le=10_000),
    is_recommended: bool = Form(default=False),
) -> Response:
    del current
    try:
        request.app.state.cascade_service.create_location(
            db,
            slug=slug,
            country_code=country_code,
            country_name=country_name,
            city=city,
            display_name=display_name,
            ingress_node_id=ingress_node_id,
            exit_node_id=exit_node_id,
            exit_port=exit_port,
            link_uuid=link_uuid,
            server_name=server_name,
            reality_public_key=reality_public_key,
            short_id=short_id,
            sort_order=sort_order,
            is_recommended=is_recommended,
        )
        db.commit()
    except (ValueError, DomainConflictError, NotFoundError):
        db.rollback()
        return RedirectResponse("/topology?notice=location-invalid", status_code=303)
    return RedirectResponse("/topology?notice=location-created", status_code=303)


@router.post("/topology/locations/{location_id}/refresh")
def refresh_topology_location(
    request: Request,
    location_id: str,
    db: DbSession,
    current: CsrfAdmin,
) -> Response:
    del current
    try:
        request.app.state.cascade_service.refresh_location_health(db, location_id)
        db.commit()
    except (NotFoundError, RuntimeError):
        db.rollback()
        return RedirectResponse("/topology?notice=health-failed", status_code=303)
    return RedirectResponse("/topology?notice=health-refreshed", status_code=303)


@router.post("/subscriptions")
def create_subscription(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    display_name: str = Form(default="", max_length=120),
    email: str = Form(default="", max_length=254),
    telegram_username: str = Form(default="", max_length=64),
    phone_number: str = Form(default="", max_length=32),
    comment: str = Form(default="", max_length=1000),
    period_type: str = Form(default="30", max_length=20),
    custom_days: str = Form(default="", max_length=4),
    expires_on: str = Form(default="", max_length=10),
    device_limit: int | None = Form(default=None, ge=1, le=1000),
) -> Response:
    device_ref = ""
    protocols = request.app.state.settings.issuable_protocol_set
    try:
        subscription_days, subscription_until = subscription_period(
            period_type, custom_days, expires_on
        )
        result = request.app.state.admin_service.create_subscription(
            db,
            display_name=display_name,
            email=email,
            telegram_username=telegram_username,
            phone_number=phone_number,
            comment=comment,
            subscription_days=subscription_days,
            subscription_until=subscription_until,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
            device_limit=device_limit,
        )
        device_ref = result.device_ref
        db.commit()
    except (ValueError, DomainConflictError):
        db.rollback()
        return RedirectResponse("/?notice=user-invalid", status_code=303)
    except Exception:
        db.rollback()
        if device_ref:
            request.app.state.admin_service.compensate_device_creation(device_ref, protocols)
        raise
    return render(
        request,
        "activation_created.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "user": result.user,
            "activation_key": result.activation_key,
        },
        status_code=201,
    )


@router.post("/users/{user_id}/subscription/renew")
def renew_subscription(
    request: Request,
    user_id: str,
    db: DbSession,
    current: CsrfAdmin,
    period_type: str = Form(default="30", max_length=20),
    custom_days: str = Form(default="", max_length=4),
    expires_on: str = Form(default="", max_length=10),
) -> Response:
    try:
        subscription_days, subscription_until = subscription_period(
            period_type, custom_days, expires_on
        )
        request.app.state.admin_service.renew_subscription(
            db,
            user_id=user_id,
            subscription_days=subscription_days,
            subscription_until=subscription_until,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        request.app.state.cascade_service.enable_route_credentials_for_user(db, user_id)
        db.commit()
    except (ValueError, DomainConflictError, NotFoundError, RuntimeError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse(f"/users/{user_id}", status_code=303)


@router.get("/connections/wireguard", response_class=HTMLResponse)
def wireguard_connections(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    users = request.app.state.admin_service.list_users(db)
    connections = []
    runtime_available = True
    try:
        connections = request.app.state.admin_service.connected_wireguard_devices(users)
    except RuntimeError:
        runtime_available = False
    return render(
        request,
        "wireguard_connections.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "connections": connections,
            "runtime_available": runtime_available,
            "connected_window_seconds": (
                request.app.state.settings.wireguard_connected_window_seconds
            ),
        },
    )


@router.get("/connections/vless", response_class=HTMLResponse)
def vless_connections(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    source = request.query_params.get("source", "app")
    legacy_mode = source == "manual"
    users = [
        user
        for user in request.app.state.admin_service.list_users(db)
        if (user.activation_key_hash is None) == legacy_mode
    ]
    devices = []
    activation_keys: dict[str, str] = {}
    runtime_available = True
    try:
        devices = request.app.state.admin_service.connected_vless_devices(users)
        activation_keys = {
            user.id: key
            for user in users
            if (key := request.app.state.admin_service.activation_key_for_admin(user))
        }
    except RuntimeError:
        runtime_available = False
    return render(
        request,
        "vless_connections.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "devices": devices,
            "activation_keys": activation_keys,
            "legacy_mode": legacy_mode,
            "runtime_available": runtime_available,
        },
    )


@router.get("/connections/amneziawg", response_class=HTMLResponse)
def amneziawg_connections(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    source = request.query_params.get("source", "app")
    legacy_mode = source == "manual"
    users = [
        user
        for user in request.app.state.admin_service.list_users(db)
        if (user.activation_key_hash is None) == legacy_mode
    ]
    connections = []
    activation_keys: dict[str, str] = {}
    runtime_available = True
    try:
        connections = request.app.state.admin_service.connected_amneziawg_devices(users)
        activation_keys = {
            user.id: key
            for user in users
            if (key := request.app.state.admin_service.activation_key_for_admin(user))
        }
    except RuntimeError:
        runtime_available = False
    return render(
        request,
        "amneziawg_connections.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "connections": connections,
            "activation_keys": activation_keys,
            "legacy_mode": legacy_mode,
            "runtime_available": runtime_available,
            "connected_window_seconds": (
                request.app.state.settings.wireguard_connected_window_seconds
            ),
        },
    )


@router.post("/users")
def create_user(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    slug: str = Form(default="", max_length=64),
    display_name: str = Form(min_length=1, max_length=120),
    comment: str = Form(default="", max_length=1000),
    amneziawg: bool = Form(default=False),
    vless: bool = Form(default=False),
) -> Response:
    protocols = set()
    if amneziawg:
        protocols.add(Protocol.AMNEZIAWG)
    if vless:
        protocols.add(Protocol.VLESS)
    protocols &= request.app.state.settings.issuable_protocol_set
    device_ref = ""
    try:
        user = request.app.state.admin_service.create_user(
            db,
            slug=slug or None,
            display_name=display_name,
            comment=comment,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        if not slug:
            if not protocols:
                raise ValueError("Select at least one configured protocol")
            device_ref = f"{user.slug}-device-1"
            device = request.app.state.admin_service.create_device(
                db,
                user_id=user.id,
                slug="device-1",
                display_name="Устройство 1",
                protocols=protocols,
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
            device_ref = f"{user.slug}-{device.slug}"
        db.commit()
    except DomainConflictError:
        db.rollback()
        return RedirectResponse("/legacy?notice=user-conflict", status_code=303)
    except ValueError:
        db.rollback()
        return RedirectResponse("/legacy?notice=user-invalid", status_code=303)
    except Exception:
        db.rollback()
        if device_ref:
            request.app.state.admin_service.compensate_device_creation(device_ref, protocols)
        raise
    return RedirectResponse(f"/users/{user.id}", status_code=303)


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(
    request: Request, user_id: str, db: DbSession, current: CurrentAdmin
) -> HTMLResponse:
    try:
        user = request.app.state.admin_service.get_user(db, user_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    runtime_by_device = {}
    runtime_available = True
    try:
        runtime_by_device = {
            device.id: request.app.state.admin_service.device_runtime_status(device)
            for device in user.devices
        }
    except RuntimeError:
        runtime_available = False
    return render(
        request,
        "user_detail.html",
        {
            "current": current,
            "user": user,
            "csrf_token": current.csrf_token,
            "runtime_by_device": runtime_by_device,
            "runtime_available": runtime_available,
            "activation_key": request.app.state.admin_service.activation_key_for_admin(user),
        },
    )


@router.post("/users/{user_id}/devices")
def create_device(
    request: Request,
    user_id: str,
    db: DbSession,
    current: CsrfAdmin,
    slug: str = Form(default="", max_length=64),
    display_name: str = Form(min_length=1, max_length=120),
    amneziawg: bool = Form(default=False),
    vless: bool = Form(default=False),
) -> Response:
    protocols = set()
    if amneziawg is True:
        protocols.add(Protocol.AMNEZIAWG)
    if vless:
        protocols.add(Protocol.VLESS)
    protocols &= request.app.state.settings.issuable_protocol_set
    device_ref = ""
    try:
        device = request.app.state.admin_service.create_device(
            db,
            user_id=user_id,
            slug=slug or None,
            display_name=display_name,
            protocols=protocols,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        device_ref = f"{device.user.slug}-{device.slug}"
    except (ValueError, DomainConflictError, NotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        db.commit()
    except Exception:
        db.rollback()
        request.app.state.admin_service.compensate_device_creation(device_ref, protocols)
        raise
    return RedirectResponse(f"/users/{user_id}", status_code=303)


@router.post("/devices/{device_id}/protocol/{protocol_name}/{action}")
def protocol_action(
    request: Request,
    device_id: str,
    protocol_name: str,
    action: str,
    db: DbSession,
    current: CsrfAdmin,
    confirmation: str = Form(default=""),
    acting_password: str = Form(default="", max_length=512),
    acting_totp: str = Form(default="", max_length=8),
) -> Response:
    try:
        protocol = Protocol(protocol_name)
        if protocol is Protocol.WIREGUARD and action in {"issue", "enable"}:
            raise ValueError("WireGuard issuance is discontinued")
        if action in {"issue", "enable"} and (
            protocol not in request.app.state.settings.issuable_protocol_set
        ):
            raise ValueError("Protocol is not configured")
        if action in {"enable", "disable"}:
            request.app.state.admin_service.set_protocol_enabled(
                db,
                device_id=device_id,
                protocol=protocol,
                enabled=action == "enable",
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
        elif action == "issue":
            if confirmation != "ISSUE":
                raise ValueError("Issuance confirmation is required")
            request.app.state.admin_service.issue_protocol(
                db,
                device_id=device_id,
                protocol=protocol,
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
        elif action == "revoke":
            if confirmation != "REVOKE":
                raise ValueError("Revocation confirmation is required")
            verify_critical_action(request, current, acting_password, acting_totp)
            request.app.state.admin_service.revoke_protocol(
                db,
                device_id=device_id,
                protocol=protocol,
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
        else:
            raise ValueError("Unknown protocol action")
        db.commit()
    except (ValueError, DomainConflictError, NotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse(safe_referer(request), status_code=303)


@router.post("/devices/{device_id}/packages")
def create_package(
    request: Request,
    device_id: str,
    db: DbSession,
    current: CsrfAdmin,
    amneziawg: bool = Form(default=False),
    vless: bool = Form(default=False),
) -> HTMLResponse:
    protocols = set()
    if amneziawg is True:
        protocols.add(Protocol.AMNEZIAWG)
    if vless:
        protocols.add(Protocol.VLESS)
    try:
        result = request.app.state.admin_service.create_package(
            db,
            device_id=device_id,
            protocols=protocols,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (ValueError, DomainConflictError, NotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return render(
        request,
        "package_ready.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "download_url": f"/provision/{result.token}",
            "expires_at": result.expires_at,
        },
    )


@router.post("/devices/{device_id}/delete")
def delete_device(
    request: Request,
    device_id: str,
    db: DbSession,
    current: CsrfAdmin,
    confirmation: str = Form(default=""),
    acting_password: str = Form(default="", max_length=512),
    acting_totp: str = Form(default="", max_length=8),
) -> Response:
    if confirmation != "DELETE":
        raise HTTPException(status_code=409, detail="Deletion confirmation is required")
    verify_critical_action(request, current, acting_password, acting_totp)
    try:
        user_id, targets = request.app.state.admin_service.device_revocation_targets(db, device_id)
        for protocol in targets:
            request.app.state.admin_service.revoke_protocol(
                db,
                device_id=device_id,
                protocol=protocol,
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
            db.commit()
        user_id = request.app.state.admin_service.delete_device(
            db,
            device_id=device_id,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (DomainConflictError, NotFoundError, RuntimeError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse(f"/users/{user_id}", status_code=303)


@router.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    user_id: str,
    db: DbSession,
    current: CsrfAdmin,
    confirmation: str = Form(default=""),
    acting_password: str = Form(default="", max_length=512),
    acting_totp: str = Form(default="", max_length=8),
) -> Response:
    if confirmation != "DELETE":
        raise HTTPException(status_code=409, detail="Deletion confirmation is required")
    verify_critical_action(request, current, acting_password, acting_totp)
    try:
        targets = request.app.state.admin_service.user_revocation_targets(db, user_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    for device_id, protocol in targets:
        try:
            request.app.state.admin_service.revoke_protocol(
                db,
                device_id=device_id,
                protocol=protocol,
                administrator_id=current.administrator.id,
                correlation_id=correlation_id(request),
            )
            db.commit()
        except (DomainConflictError, NotFoundError, RuntimeError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="Not every VPN access could be revoked; the user was not deleted",
            ) from exc
    try:
        request.app.state.admin_service.delete_user(
            db,
            user_id=user_id,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (DomainConflictError, NotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse("/", status_code=303)


@router.get("/devices/{device_id}/qr/{protocol_name}")
def protocol_qr(
    request: Request,
    device_id: str,
    protocol_name: str,
    db: DbSession,
    current: CurrentAdmin,
) -> Response:
    try:
        protocol = Protocol(protocol_name)
        payload = request.app.state.admin_service.qr_code(
            db,
            device_id=device_id,
            protocol=protocol,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (ValueError, NotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=payload,
        media_type="image/png",
        headers={"Cache-Control": "no-store", "Content-Disposition": "inline"},
    )


@router.get("/provision/{token}")
def download_package(
    request: Request, token: str, db: DbSession, current: CurrentAdmin
) -> Response:
    try:
        payload, filename = request.app.state.admin_service.consume_package(
            db,
            token,
            administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (DomainConflictError, NotFoundError) as exc:
        db.commit()
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    return Response(
        content=payload,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def filtered_audit_events(
    db: DbSession,
    *,
    action: str,
    outcome: str,
    administrator_id: str,
    limit: int,
    offset: int = 0,
    date_from: str = "",
    date_to: str = "",
) -> list[AuditEventModel]:
    query = select(AuditEventModel).options(
        selectinload(AuditEventModel.administrator),
        selectinload(AuditEventModel.user),
        selectinload(AuditEventModel.device),
    )
    if action:
        query = query.where(AuditEventModel.action == action)
    if outcome in {"success", "denied", "failure"}:
        query = query.where(AuditEventModel.outcome == outcome)
    if administrator_id:
        query = query.where(AuditEventModel.administrator_id == administrator_id)
    if date_from:
        try:
            parsed_from = datetime.combine(date.fromisoformat(date_from), time.min, tzinfo=UTC)
        except ValueError:
            parsed_from = None
        if parsed_from is not None:
            query = query.where(AuditEventModel.occurred_at >= parsed_from)
    if date_to:
        try:
            parsed_to = datetime.combine(date.fromisoformat(date_to), time.max, tzinfo=UTC)
        except ValueError:
            parsed_to = None
        if parsed_to is not None:
            query = query.where(AuditEventModel.occurred_at <= parsed_to)
    return list(
        db.scalars(query.order_by(desc(AuditEventModel.occurred_at)).offset(offset).limit(limit))
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_log(
    request: Request,
    db: DbSession,
    current: CurrentAdmin,
    action: str = "",
    outcome: str = "",
    administrator_id: str = "",
    date_from: str = "",
    date_to: str = "",
    page: int = 1,
    per_page: int = 50,
) -> HTMLResponse:
    per_page = max(10, min(per_page, 100))
    page = max(1, page)
    events = filtered_audit_events(
        db,
        action=action[:100],
        outcome=outcome,
        administrator_id=administrator_id[:36],
        limit=per_page + 1,
        offset=(page - 1) * per_page,
        date_from=date_from,
        date_to=date_to,
    )
    actions = list(
        db.scalars(select(AuditEventModel.action).distinct().order_by(AuditEventModel.action))
    )
    return render(
        request,
        "audit.html",
        {
            "current": current,
            "events": events[:per_page],
            "has_next": len(events) > per_page,
            "page": page,
            "per_page": per_page,
            "actions": actions,
            "administrators": request.app.state.admin_service.list_administrators(db),
            "filters": {
                "action": action,
                "outcome": outcome,
                "administrator_id": administrator_id,
                "date_from": date_from,
                "date_to": date_to,
            },
            "csrf_token": current.csrf_token,
        },
    )


@router.get("/audit/export.csv")
def export_audit_log(
    db: DbSession,
    current: CurrentAdmin,
    action: str = "",
    outcome: str = "",
    administrator_id: str = "",
    date_from: str = "",
    date_to: str = "",
) -> Response:
    events = filtered_audit_events(
        db,
        action=action[:100],
        outcome=outcome,
        administrator_id=administrator_id[:36],
        limit=5000,
        date_from=date_from,
        date_to=date_to,
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        ("occurred_at", "action", "outcome", "administrator", "user", "device", "correlation_id")
    )
    for event in events:
        writer.writerow(
            (
                event.occurred_at.isoformat(),
                event.action,
                event.outcome,
                event.administrator.username if event.administrator else "",
                event.user.slug if event.user else "",
                event.device.slug if event.device else "",
                event.correlation_id,
            )
        )
    return Response(
        content="\ufeff" + stream.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=kenai-audit.csv",
            "Cache-Control": "no-store",
        },
    )


@router.get("/administrators", response_class=HTMLResponse)
def administrators_page(request: Request, db: DbSession, current: CurrentAdmin) -> HTMLResponse:
    notices = {
        "created": "Администратор создан и TOTP подтверждён.",
        "password": "Пароль изменён. Другие сессии завершены.",
        "status": "Статус администратора изменён.",
        "access": "Роль и права изменены. Другие сессии администратора отозваны.",
        "session": "Сессия отозвана.",
        "invalid": "Операция отклонена. Проверьте пароль, TOTP и введённые данные.",
    }
    notice = request.query_params.get("notice")
    return render(
        request,
        "administrators.html",
        {
            "current": current,
            "administrators": request.app.state.admin_service.list_administrators(db),
            "active_sessions": list(
                db.scalars(
                    select(SessionModel)
                    .where(SessionModel.revoked_at.is_(None), SessionModel.expires_at > utc_now())
                    .order_by(desc(SessionModel.last_seen_at))
                )
            ),
            "all_permissions": sorted(PERMISSIONS),
            "role_defaults": ROLE_DEFAULTS,
            "csrf_token": current.csrf_token,
            "notice_message": notices.get(notice) if notice else None,
            "notice_error": notice == "invalid",
        },
    )


def enrollment_response(request: Request, current: CurrentAdmin, enrollment: Any) -> HTMLResponse:
    encoded_qr = base64.b64encode(enrollment.qr_png).decode("ascii")
    response = render(
        request,
        "totp_enrollment.html",
        {
            "current": current,
            "csrf_token": current.csrf_token,
            "administrator_id": enrollment.administrator_id,
            "provisioning_uri": enrollment.provisioning_uri,
            "qr_data_uri": f"data:image/png;base64,{encoded_qr}",
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/administrators")
def create_administrator(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    username: str = Form(min_length=1, max_length=80),
    password: str = Form(min_length=10, max_length=512),
    password_repeat: str = Form(min_length=10, max_length=512),
    acting_password: str = Form(min_length=1, max_length=512),
    acting_totp: str = Form(min_length=6, max_length=8),
    role: str = Form(default="admin", max_length=32),
    permissions: Annotated[list[str] | None, Form()] = None,
) -> Response:
    if password != password_repeat:
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    try:
        enrollment = request.app.state.admin_service.create_administrator(
            db,
            username=username,
            password=password,
            acting_administrator=current.administrator,
            acting_password=acting_password,
            acting_totp=acting_totp,
            correlation_id=correlation_id(request),
            role=role,
            permissions=permissions,
        )
        db.commit()
    except (ValueError, DomainConflictError):
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return enrollment_response(request, current, enrollment)


@router.post("/administrators/{administrator_id}/confirm-totp")
def confirm_administrator_totp(
    request: Request,
    administrator_id: str,
    db: DbSession,
    current: CsrfAdmin,
    totp_code: str = Form(min_length=6, max_length=8),
) -> Response:
    try:
        request.app.state.admin_service.confirm_administrator_totp(
            db,
            administrator_id=administrator_id,
            code=totp_code,
            acting_administrator_id=current.administrator.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (ValueError, NotFoundError):
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return RedirectResponse("/administrators?notice=created", status_code=303)


@router.post("/administrators/change-password")
def change_administrator_password(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    current_password: str = Form(min_length=1, max_length=512),
    current_totp: str = Form(min_length=6, max_length=8),
    new_password: str = Form(min_length=10, max_length=512),
    new_password_repeat: str = Form(min_length=10, max_length=512),
) -> Response:
    if new_password != new_password_repeat:
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    try:
        request.app.state.admin_service.change_password(
            db,
            administrator=current.administrator,
            current_password=current_password,
            current_totp=current_totp,
            new_password=new_password,
            current_session_id=current.session.id,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except ValueError:
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return RedirectResponse("/administrators?notice=password", status_code=303)


@router.post("/administrators/reset-totp")
def reset_administrator_totp(
    request: Request,
    db: DbSession,
    current: CsrfAdmin,
    current_password: str = Form(min_length=1, max_length=512),
    current_totp: str = Form(min_length=6, max_length=8),
) -> Response:
    try:
        enrollment = request.app.state.admin_service.reset_totp(
            db,
            administrator=current.administrator,
            current_password=current_password,
            current_totp=current_totp,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except ValueError:
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return enrollment_response(request, current, enrollment)


@router.post("/administrators/{administrator_id}/status")
def administrator_status(
    request: Request,
    administrator_id: str,
    db: DbSession,
    current: CsrfAdmin,
    active: bool = Form(),
    acting_password: str = Form(min_length=1, max_length=512),
    acting_totp: str = Form(min_length=6, max_length=8),
) -> Response:
    try:
        request.app.state.admin_service.set_administrator_active(
            db,
            target_id=administrator_id,
            active=active,
            acting_administrator=current.administrator,
            acting_password=acting_password,
            acting_totp=acting_totp,
            correlation_id=correlation_id(request),
        )
        db.commit()
    except (ValueError, DomainConflictError, NotFoundError):
        db.rollback()
        return RedirectResponse("/administrators?notice=invalid", status_code=303)
    return RedirectResponse("/administrators?notice=status", status_code=303)
