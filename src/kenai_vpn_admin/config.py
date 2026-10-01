from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from kenai_vpn_admin.application.direct_locations import DirectAmneziaWgExit, DirectVlessExit
from kenai_vpn_admin.domain.enums import Protocol


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KENAI_",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+psycopg://kenai:kenai@127.0.0.1:5432/kenai"
    secret_key: str = "development-only-change-me-32-characters"
    encryption_key: str | None = None
    vpn_backend: Literal["mock", "helper"] = "mock"
    helper_socket: Path = Path("/run/kenai-vpn/helper.sock")
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    cookie_secure: bool = False
    session_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    provisioning_ttl_minutes: int = Field(default=15, ge=1, le=1440)
    login_max_attempts: int = Field(default=5, ge=1, le=100)
    login_window_minutes: int = Field(default=15, ge=1, le=1440)
    login_totp_required: bool = True
    activation_max_attempts: int = Field(default=10, ge=1, le=1000)
    activation_window_minutes: int = Field(default=15, ge=1, le=1440)
    max_subscription_devices: int = Field(default=32, ge=1, le=1000)
    wireguard_connected_window_seconds: int = Field(default=180, ge=60, le=600)
    subscription_protocols: str = "amneziawg,vless"
    backup_protocols: str = "wireguard,amneziawg,vless"
    support_enabled: bool = False
    support_telegram_bot_token: SecretStr = SecretStr("")
    support_telegram_chat_id: int = 0
    support_telegram_admin_ids: str = ""
    notification_telegram_bot_token: SecretStr = SecretStr("")
    notification_retry_limit: int = Field(default=3, ge=1, le=5)
    metrics_retention_days: int = Field(default=30, ge=1, le=365)
    primary_address: str = ""
    primary_country_name: str = "Армения"
    primary_city: str = "Ереван"
    netherlands_address: str = ""
    netherlands_server_name: str = ""
    netherlands_public_key: str = ""
    netherlands_short_id: str = ""
    netherlands_awg_public_key: str = ""
    netherlands_awg_header_protection_key: SecretStr = SecretStr("")

    @property
    def netherlands_exit(self) -> DirectVlessExit | None:
        values = (
            self.netherlands_address,
            self.netherlands_server_name,
            self.netherlands_public_key,
            self.netherlands_short_id,
        )
        if not any(values):
            return None
        if not all(values):
            raise ValueError("Incomplete Netherlands direct-exit configuration")
        return DirectVlessExit(*values)

    @property
    def netherlands_awg_exit(self) -> DirectAmneziaWgExit | None:
        values = (
            self.netherlands_address,
            self.netherlands_awg_public_key,
            self.netherlands_awg_header_protection_key.get_secret_value(),
        )
        if not any(values[1:]):
            return None
        if not all(values):
            raise ValueError("Incomplete Netherlands AmneziaWG configuration")
        return DirectAmneziaWgExit(*values)

    @property
    def support_admin_ids(self) -> set[int]:
        return {
            int(value.strip())
            for value in self.support_telegram_admin_ids.split(",")
            if value.strip()
        }

    @field_validator("support_telegram_admin_ids")
    @classmethod
    def validate_support_admin_ids(cls, value: str) -> str:
        if any(
            not item.strip().isdigit() or int(item.strip()) <= 0
            for item in value.split(",")
            if item.strip()
        ):
            raise ValueError("Support admin IDs must be positive Telegram user IDs")
        return value

    @property
    def support_available(self) -> bool:
        return bool(
            self.support_enabled
            and self.support_telegram_bot_token.get_secret_value()
            and self.support_telegram_chat_id
            and self.support_admin_ids
        )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("KENAI_SECRET_KEY must contain at least 32 characters")
        return value

    @field_validator("subscription_protocols", "backup_protocols")
    @classmethod
    def validate_subscription_protocols(cls, value: str, info: ValidationInfo) -> str:
        names = [item.strip().lower() for item in value.split(",") if item.strip()]
        allowed = {protocol.value for protocol in Protocol}
        if not names or len(names) != len(set(names)) or any(name not in allowed for name in names):
            name = (info.field_name or "PROTOCOLS").upper()
            raise ValueError(f"KENAI_{name} contains invalid protocol names")
        return ",".join(names)

    @property
    def subscription_protocol_set(self) -> set[Protocol]:
        return {Protocol(name) for name in self.subscription_protocols.split(",")}

    @property
    def issuable_protocol_set(self) -> set[Protocol]:
        """Protocols offered for new accounts; legacy WireGuard stays readable."""
        return self.subscription_protocol_set & {Protocol.AMNEZIAWG, Protocol.VLESS}

    @property
    def backup_protocol_set(self) -> set[Protocol]:
        return {Protocol(name) for name in self.backup_protocols.split(",")}

    def ensure_safe_production(self) -> None:
        if not self.login_totp_required and self.env != "test":
            raise RuntimeError("KENAI_LOGIN_TOTP_REQUIRED=false is allowed only in test mode")
        if self.env != "production":
            return
        if not self.cookie_secure:
            raise RuntimeError("Production requires KENAI_COOKIE_SECURE=true")
        if self.vpn_backend != "helper":
            raise RuntimeError("Production requires KENAI_VPN_BACKEND=helper")
        if self.encryption_key is None:
            raise RuntimeError("Production requires KENAI_ENCRYPTION_KEY")
        if make_url(self.database_url).get_backend_name() != "postgresql":
            raise RuntimeError("Production requires PostgreSQL")
        if self.host in {"0.0.0.0", "::"}:
            raise RuntimeError("Production must not bind the admin panel to every interface")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_safe_production()
    return settings
