from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from kenai_vpn_admin.application.cascade import bearer_token
from kenai_vpn_admin.application.rbac import has_permission, permission_for_request
from kenai_vpn_admin.infrastructure.models import (
    AdministratorModel,
    DeviceAccessTokenModel,
    SessionModel,
)


@dataclass(frozen=True)
class AuthenticatedAdmin:
    administrator: AdministratorModel
    session: SessionModel
    csrf_token: str


def get_db(request: Request) -> Generator[Session, None, None]:
    with request.app.state.session_factory() as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]


def require_admin(request: Request, db: DbSession) -> AuthenticatedAdmin:
    auth_service = request.app.state.auth_service
    model = auth_service.resolve_session(db, request.cookies.get("kenai_session"))
    if not model:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    required_permission = permission_for_request(request.url.path, request.method)
    if not has_permission(model.administrator, required_permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    csrf_token = request.cookies.get("kenai_csrf", "")
    db.commit()
    return AuthenticatedAdmin(model.administrator, model, csrf_token)


CurrentAdmin = Annotated[AuthenticatedAdmin, Depends(require_admin)]


async def verify_csrf(request: Request, db: DbSession, current: CurrentAdmin) -> AuthenticatedAdmin:
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied:
        form = await request.form()
        value = form.get("csrf_token")
        supplied = value if isinstance(value, str) else None
    if not supplied:
        raise HTTPException(status_code=403, detail="Missing CSRF token")
    if not request.app.state.auth_service.validate_csrf(current.session, supplied):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return current


CsrfAdmin = Annotated[AuthenticatedAdmin, Depends(verify_csrf)]


@dataclass(frozen=True)
class AuthenticatedDevice:
    token: DeviceAccessTokenModel


def require_device(request: Request, db: DbSession) -> AuthenticatedDevice:
    supplied = bearer_token(request.headers.get("Authorization"))
    model = (
        request.app.state.cascade_service.resolve_access_token(db, supplied)
        if supplied is not None
        else None
    )
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired device token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    db.commit()
    return AuthenticatedDevice(model)


CurrentDevice = Annotated[AuthenticatedDevice, Depends(require_device)]
