from __future__ import annotations

import re
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from kenai_vpn_admin.application.support import (
    SupportError,
    SupportPrincipal,
    SupportService,
    guest_remote_hash,
    guest_token_hash,
    issue_session,
    resolve_session,
)
from kenai_vpn_admin.infrastructure.support_models import SupportMessage, SupportTicket
from kenai_vpn_admin.web.dependencies import DbSession

router = APIRouter(prefix="/api/v1/support")


class SessionInput(BaseModel):
    activation_key: SecretStr


class MessageInput(BaseModel):
    request_id: UUID
    body: str = Field(min_length=1, max_length=2000)

    @field_validator("body")
    @classmethod
    def nonblank_body(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message is empty")
        return value.strip()


class TicketInput(MessageInput):
    subject: str = Field(min_length=1, max_length=120)
    guest_name: str = Field(default="", max_length=80)
    client_version: str = Field(default="", max_length=40)
    platform: str = Field(default="", max_length=40)

    @field_validator("subject")
    @classmethod
    def nonblank_subject(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Subject is empty")
        return value.strip()


def response(body: dict[str, object], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def require_support_account(request: Request, db: DbSession) -> SupportPrincipal:
    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 2048:
        raise HTTPException(401, detail="invalid_session")
    try:
        if authorization.startswith("Bearer "):
            user, mask = resolve_session(db, request.app.state.settings, authorization[7:])
            return SupportPrincipal(user=user, key_mask=mask)
        if authorization.startswith("Guest "):
            return SupportPrincipal(
                guest_hash=guest_token_hash(request.app.state.settings, authorization[6:])
            )
        raise SupportError(401, "invalid_session")
    except SupportError as error:
        raise HTTPException(error.status, detail=error.code) from None


SupportAccount = Annotated[SupportPrincipal, Depends(require_support_account)]


def require_delivery(request: Request) -> None:
    if not request.app.state.settings.support_available:
        raise HTTPException(503, detail="support_unavailable")


@router.get("/config")
def configuration(request: Request) -> JSONResponse:
    return response({"available": request.app.state.settings.support_available})


@router.post("/session")
def session(request: Request, payload: SessionInput, db: DbSession) -> JSONResponse:
    key = payload.activation_key.get_secret_value()
    remote = request.client.host if request.client else "unknown"
    admin = request.app.state.admin_service
    if admin.activation_is_rate_limited(db, remote):
        raise HTTPException(429, detail="rate_limited")
    try:
        if not re.fullmatch(r"\d{12}", key):
            raise SupportError(401, "invalid_account")
        token = issue_session(db, request.app.state.settings, key)
    except SupportError as error:
        admin.record_activation_attempt(db, remote, succeeded=False)
        db.commit()
        raise HTTPException(error.status, detail=error.code) from None
    admin.record_activation_attempt(db, remote, succeeded=True)
    db.commit()
    return response({"access_token": token, "expires_in": 3600})


@router.get("/tickets")
def tickets(
    db: DbSession, current: SupportAccount, offset: int = Query(default=0, ge=0)
) -> JSONResponse:
    page = SupportService(db).list_tickets(current, offset)
    return response({"tickets": page, "has_more": len(page) == 100})


@router.post("/tickets")
def create_ticket(
    request: Request, payload: TicketInput, db: DbSession, current: SupportAccount
) -> JSONResponse:
    require_delivery(request)
    service = SupportService(db)
    try:
        if current.user is not None:
            ticket = service.create(
                current.user,
                current.key_mask,
                str(payload.request_id),
                payload.subject,
                payload.body,
                payload.client_version,
                payload.platform,
                payload.guest_name,
            )
        else:
            remote = request.client.host if request.client else "unknown"
            ticket = service.create_guest(
                current.guest_hash or "",
                guest_remote_hash(request.app.state.settings, remote),
                str(payload.request_id),
                payload.subject,
                payload.body,
                payload.client_version,
                payload.platform,
                payload.guest_name,
            )
        db.commit()
        return response(service.detail(ticket), 201)
    except SupportError as error:
        db.rollback()
        raise HTTPException(error.status, detail=error.code) from None
    except IntegrityError:
        db.rollback()
        owner = (
            SupportTicket.user_id == current.user.id
            if current.user is not None
            else SupportTicket.guest_token_hash == current.guest_hash
        )
        prior = db.scalar(
            select(SupportTicket).where(owner, SupportTicket.request_id == str(payload.request_id))
        )
        if prior is not None:
            return response(service.detail(prior), 201)
        raise HTTPException(409, detail="active_ticket_exists") from None


@router.get("/tickets/{ticket_id}")
def detail(
    ticket_id: UUID, db: DbSession, current: SupportAccount, after: int = Query(default=0, ge=0)
) -> JSONResponse:
    service = SupportService(db)
    try:
        return response(service.detail(service.owned(current, str(ticket_id)), after))
    except SupportError as error:
        raise HTTPException(error.status, detail=error.code) from None


@router.post("/tickets/{ticket_id}/messages")
def send(
    request: Request, ticket_id: UUID, payload: MessageInput, db: DbSession, current: SupportAccount
) -> JSONResponse:
    require_delivery(request)
    service = SupportService(db)
    try:
        ticket = service.owned(current, str(ticket_id), lock=True)
        service.send(ticket, str(payload.request_id), payload.body)
        db.commit()
        return response({"ok": True})
    except SupportError as error:
        db.rollback()
        raise HTTPException(error.status, detail=error.code) from None
    except IntegrityError:
        db.rollback()
        # Only a committed duplicate may be acknowledged as delivered.
        duplicate = db.scalar(
            select(SupportMessage.id).where(
                SupportMessage.ticket_id == str(ticket_id),
                SupportMessage.request_id == str(payload.request_id),
            )
        )
        if duplicate is not None:
            return response({"ok": True})
        raise HTTPException(500, detail="message_not_saved") from None
