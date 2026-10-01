from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kenai_vpn_admin.application.cascade import CascadeService
from kenai_vpn_admin.application.console import ConsoleService
from kenai_vpn_admin.application.services import AdminService
from kenai_vpn_admin.config import Settings, get_settings
from kenai_vpn_admin.infrastructure.crypto import FernetCipher
from kenai_vpn_admin.infrastructure.database import build_engine, build_session_factory
from kenai_vpn_admin.infrastructure.helper_client import HelperVpnManagerClient
from kenai_vpn_admin.infrastructure.mock_vpn import MockVpnManager
from kenai_vpn_admin.security import AuthenticationService
from kenai_vpn_admin.web.console_routes import router as console_router
from kenai_vpn_admin.web.routes import router
from kenai_vpn_admin.web.support_routes import router as support_router

PACKAGE_DIR = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_safe_production()
    _ = settings.netherlands_exit  # Reject a partial or invalid location at startup.
    _ = settings.netherlands_awg_exit
    engine = build_engine(settings)
    session_factory = build_session_factory(engine)
    cipher = FernetCipher(
        settings.encryption_key,
        settings.secret_key,
        allow_derived=settings.env in {"development", "test"},
    )
    vpn_manager = (
        MockVpnManager()
        if settings.vpn_backend == "mock"
        else HelperVpnManagerClient(settings.helper_socket)
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="Kenai VPN Admin",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.cipher = cipher
    app.state.vpn_manager = vpn_manager
    app.state.auth_service = AuthenticationService(settings, cipher)
    app.state.admin_service = AdminService(settings, cipher, vpn_manager)
    app.state.cascade_service = CascadeService(cipher, vpn_manager)
    app.state.console_service = ConsoleService(settings, vpn_manager)
    app.state.templates = Jinja2Templates(directory=PACKAGE_DIR / "web" / "templates")
    app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "web" / "static"), name="static")

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.correlation_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        return response

    app.include_router(console_router)
    app.include_router(router)
    app.include_router(support_router)
    return app


app = create_app()
