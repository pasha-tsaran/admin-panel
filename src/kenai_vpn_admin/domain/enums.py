from enum import StrEnum


class LifecycleStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class Protocol(StrEnum):
    WIREGUARD = "wireguard"
    AMNEZIAWG = "amneziawg"
    VLESS = "vless"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class PackageStatus(StrEnum):
    READY = "ready"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    PURGED = "purged"


class NodeRole(StrEnum):
    INGRESS = "ingress"
    EXIT = "exit"


class OperationalStatus(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DISABLED = "disabled"
