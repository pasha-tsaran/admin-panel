from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.command_runner import SafeCommandRunner
from kenai_vpn_admin.helper.production import HealthCommandSettings, ProductionHelperOperations
from kenai_vpn_admin.helper.server import HelperServer
from kenai_vpn_admin.helper.wireguard_adapter import WireGuardAdapter, WireGuardSettings
from kenai_vpn_admin.helper.xray_adapter import XrayAdapter, XraySettings


class HelperSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KENAI_HELPER_",
        case_sensitive=False,
        extra="ignore",
    )

    allowed_uid: int = Field(ge=1)
    socket_gid: int = Field(ge=1)
    socket_path: Path = Path("/run/kenai-vpn/helper.sock")
    state_directory: Path = Path("/var/lib/kenai-vpn-helper")
    wireguard_enabled: bool = True
    wireguard_config: Path = Path("/etc/wireguard/wg0.conf")
    wireguard_interface: str = "wg0"
    wireguard_network: ipaddress.IPv4Network = ipaddress.IPv4Network("10.66.66.0/24")
    wireguard_server_address: ipaddress.IPv4Address = ipaddress.IPv4Address("10.66.66.1")
    wireguard_listen_port: int = Field(default=51820, ge=1, le=65535)
    public_endpoint: str = Field(min_length=1, max_length=253)
    wireguard_server_public_key: str | None = Field(default=None, min_length=40, max_length=64)
    wireguard_dns: tuple[str, ...] = ("1.1.1.1", "1.0.0.1")
    amneziawg_enabled: bool = True
    amneziawg_config: Path = Path("/etc/amneziawg/awg0.conf")
    amneziawg_interface: str = "awg0"
    amneziawg_network: ipaddress.IPv4Network = ipaddress.IPv4Network("10.67.67.0/24")
    amneziawg_server_address: ipaddress.IPv4Address = ipaddress.IPv4Address("10.67.67.1")
    amneziawg_listen_port: int = Field(default=585, ge=1, le=65535)
    amneziawg_server_public_key: str | None = Field(default=None, min_length=40, max_length=64)
    amneziawg_dns: tuple[str, ...] = ("1.1.1.1", "1.0.0.1")
    amneziawg_jc: int = Field(default=7, ge=0, le=10)
    amneziawg_jmin: int = Field(default=64, ge=64, le=1024)
    amneziawg_jmax: int = Field(default=256, ge=64, le=1024)
    amneziawg_s1: int = Field(default=32, ge=0, le=64)
    amneziawg_s2: int = Field(default=32, ge=0, le=64)
    amneziawg_s3: int = Field(default=32, ge=0, le=64)
    amneziawg_s4: int = Field(default=16, ge=0, le=32)
    amneziawg_h1: str = Field(default="100000000-199999999", pattern=r"^[0-9]+(?:-[0-9]+)?$")
    amneziawg_h2: str = Field(default="200000000-299999999", pattern=r"^[0-9]+(?:-[0-9]+)?$")
    amneziawg_h3: str = Field(default="300000000-399999999", pattern=r"^[0-9]+(?:-[0-9]+)?$")
    amneziawg_h4: str = Field(default="400000000-499999999", pattern=r"^[0-9]+(?:-[0-9]+)?$")
    amneziawg_i1: str = Field(default="", max_length=4096)
    amneziawg_i2: str = Field(default="", max_length=4096)
    amneziawg_i3: str = Field(default="", max_length=4096)
    amneziawg_i4: str = Field(default="", max_length=4096)
    amneziawg_i5: str = Field(default="", max_length=4096)
    xray_config: Path = Path("/usr/local/etc/xray/config.json")
    xray_inbound_tag: str | None = Field(default=None, min_length=1, max_length=128)
    xray_port: int = Field(default=443, ge=1, le=65535)
    xray_server_name: str = Field(min_length=1, max_length=253)
    xray_reality_public_key: str = Field(min_length=20, max_length=128)
    xray_short_id: str = Field(pattern=r"^[0-9a-f]{2,16}$")
    xray_stats_server: str | None = Field(
        default=None, pattern=r"^(127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$"
    )
    wg_binary: Path = Path("/usr/bin/wg")
    wg_quick_binary: Path = Path("/usr/bin/wg-quick")
    awg_binary: Path = Path("/usr/local/bin/awg")
    awg_quick_binary: Path = Path("/usr/local/bin/awg-quick")
    xray_binary: Path = Path("/usr/local/bin/xray")
    systemctl_binary: Path = Path("/usr/bin/systemctl")
    nft_binary: Path = Path("/usr/sbin/nft")

    @model_validator(mode="after")
    def validate_enabled_protocols(self) -> HelperSettings:
        if self.wireguard_enabled and self.wireguard_server_public_key is None:
            raise ValueError("WireGuard public key is required when WireGuard is enabled")
        if self.amneziawg_enabled and self.amneziawg_server_public_key is None:
            raise ValueError("AmneziaWG public key is required when AmneziaWG is enabled")
        return self


def build_server(settings: HelperSettings) -> HelperServer:
    executables = {settings.xray_binary, settings.systemctl_binary, settings.nft_binary}
    if settings.wireguard_enabled:
        executables.update((settings.wg_binary, settings.wg_quick_binary))
    if settings.amneziawg_enabled:
        executables.update((settings.awg_binary, settings.awg_quick_binary))
    executor = SafeCommandRunner(executables)
    wireguard = None
    if settings.wireguard_enabled:
        assert settings.wireguard_server_public_key is not None
        wireguard = WireGuardAdapter(
            WireGuardSettings(
                config_path=settings.wireguard_config,
                state_path=settings.state_directory / "wireguard.json",
                interface=settings.wireguard_interface,
                network=settings.wireguard_network,
                server_address=settings.wireguard_server_address,
                listen_port=settings.wireguard_listen_port,
                endpoint=settings.public_endpoint,
                server_public_key=settings.wireguard_server_public_key,
                dns_servers=settings.wireguard_dns,
                wg_binary=settings.wg_binary,
                wg_quick_binary=settings.wg_quick_binary,
            ),
            executor,
        )
    xray = XrayAdapter(
        XraySettings(
            config_path=settings.xray_config,
            state_path=settings.state_directory / "xray.json",
            inbound_tag=settings.xray_inbound_tag,
            endpoint=settings.public_endpoint,
            port=settings.xray_port,
            server_name=settings.xray_server_name,
            reality_public_key=settings.xray_reality_public_key,
            short_id=settings.xray_short_id,
            stats_server=settings.xray_stats_server,
            xray_binary=settings.xray_binary,
            systemctl_binary=settings.systemctl_binary,
        ),
        executor,
    )
    amneziawg = None
    if settings.amneziawg_enabled:
        assert settings.amneziawg_server_public_key is not None
        amneziawg = WireGuardAdapter(
            WireGuardSettings(
                config_path=settings.amneziawg_config,
                state_path=settings.state_directory / "amneziawg.json",
                interface=settings.amneziawg_interface,
                network=settings.amneziawg_network,
                server_address=settings.amneziawg_server_address,
                listen_port=settings.amneziawg_listen_port,
                endpoint=settings.public_endpoint,
                server_public_key=settings.amneziawg_server_public_key,
                dns_servers=settings.amneziawg_dns,
                credential_protocol=Protocol.AMNEZIAWG,
                interface_settings=tuple(
                    item
                    for item in (
                        ("Jc", str(settings.amneziawg_jc)),
                        ("Jmin", str(settings.amneziawg_jmin)),
                        ("Jmax", str(settings.amneziawg_jmax)),
                        ("S1", str(settings.amneziawg_s1)),
                        ("S2", str(settings.amneziawg_s2)),
                        ("S3", str(settings.amneziawg_s3)),
                        ("S4", str(settings.amneziawg_s4)),
                        ("H1", settings.amneziawg_h1),
                        ("H2", settings.amneziawg_h2),
                        ("H3", settings.amneziawg_h3),
                        ("H4", settings.amneziawg_h4),
                        ("I1", settings.amneziawg_i1),
                        ("I2", settings.amneziawg_i2),
                        ("I3", settings.amneziawg_i3),
                        ("I4", settings.amneziawg_i4),
                        ("I5", settings.amneziawg_i5),
                    )
                    if item[1]
                ),
                wg_binary=settings.awg_binary,
                wg_quick_binary=settings.awg_quick_binary,
            ),
            executor,
        )
    operations = ProductionHelperOperations(
        wireguard,
        xray,
        executor,
        HealthCommandSettings(
            systemctl_binary=settings.systemctl_binary,
            nft_binary=settings.nft_binary,
        ),
        amneziawg=amneziawg,
    )
    return HelperServer(
        settings.socket_path,
        operations,
        allowed_uid=settings.allowed_uid,
        socket_gid=settings.socket_gid,
    )


def main() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("kenai-vpn-helper must run as root on Linux")
    settings = HelperSettings()  # type: ignore[call-arg]
    build_server(settings).serve_forever()


if __name__ == "__main__":
    main()
