from __future__ import annotations

from collections.abc import Iterable

from kenai_vpn_admin.infrastructure.models import AdministratorModel

PERMISSIONS = frozenset(
    {
        "users",
        "issuance",
        "servers",
        "audit",
        "administrators",
        "settings",
        "backups",
        "api_tokens",
        "billing",
    }
)

ROLE_DEFAULTS: dict[str, frozenset[str]] = {
    "super_admin": PERMISSIONS,
    "admin": frozenset({"users", "issuance", "servers", "audit", "billing"}),
    "moderator": frozenset({"users", "audit"}),
    "custom": frozenset(),
}


def normalize_permissions(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value in PERMISSIONS})


def effective_permissions(administrator: AdministratorModel) -> frozenset[str]:
    if administrator.role == "super_admin":
        return PERMISSIONS
    configured = normalize_permissions(administrator.permissions_json or [])
    if configured:
        return frozenset(configured)
    return ROLE_DEFAULTS.get(administrator.role, frozenset())


def has_permission(administrator: AdministratorModel, permission: str) -> bool:
    if not permission:
        return True
    if permission == "settings_any":
        return bool(
            effective_permissions(administrator) & {"settings", "backups", "api_tokens", "billing"}
        )
    return permission in effective_permissions(administrator)


def permission_for_request(path: str, method: str) -> str:
    if path == "/logout":
        return ""
    if path.startswith("/administrators"):
        return "administrators"
    if path.startswith("/audit"):
        return "audit"
    if path.startswith("/topology") or path.startswith("/servers"):
        return "servers"
    if path.startswith("/settings/backups"):
        return "backups"
    if path.startswith("/settings/api-tokens"):
        return "api_tokens"
    if path.startswith("/settings/billing"):
        return "billing"
    if path == "/settings":
        return "settings_any"
    if path.startswith("/settings"):
        return "settings"
    if path.startswith("/subscriptions") or "/subscription/" in path:
        return "billing"
    if (
        path.startswith("/issuance")
        or path.startswith("/legacy")
        or path.startswith("/devices")
        or path.startswith("/connections")
    ):
        return "issuance"
    if path.startswith("/users") and method.upper() != "GET":
        return "issuance"
    return "users"
