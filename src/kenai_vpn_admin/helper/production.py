from __future__ import annotations

import os
import shutil
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from kenai_vpn_admin.application.ports import (
    DeviceRuntimeStatus,
    IssuedCredential,
    IssuedRouteProfile,
    ProtocolRuntimeStatus,
    RouteRuntimeStatus,
    ServerHealth,
)
from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.wireguard_adapter import CommandExecutor, WireGuardAdapter
from kenai_vpn_admin.helper.xray_adapter import XrayAdapter


@dataclass(frozen=True)
class HealthCommandSettings:
    systemctl_binary: Path = Path("/usr/bin/systemctl")
    nft_binary: Path = Path("/usr/sbin/nft")


@dataclass(frozen=True)
class SystemMetrics:
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_percent: float | None = None
    load_percent: float | None = None


class LinuxSystemMetricsReader:
    """Read bounded, non-secret host metrics without invoking a shell."""

    def __init__(self, proc_root: Path = Path("/proc"), disk_root: Path = Path("/")) -> None:
        self.proc_root = proc_root
        self.disk_root = disk_root

    def read(self) -> SystemMetrics:
        return SystemMetrics(
            cpu_percent=self._cpu_percent(),
            memory_percent=self._memory_percent(),
            disk_percent=self._disk_percent(),
            load_percent=self._load_percent(),
        )

    @staticmethod
    def _bounded(value: float) -> float:
        return round(max(0.0, min(value, 100.0)), 2)

    def _cpu_percent(self) -> float | None:
        try:
            first = self._cpu_sample()
            time.sleep(0.05)
            second = self._cpu_sample()
            total_delta = second[0] - first[0]
            idle_delta = second[1] - first[1]
            if total_delta <= 0:
                return None
            return self._bounded(100.0 * (total_delta - idle_delta) / total_delta)
        except (OSError, ValueError, IndexError):
            return None

    def _cpu_sample(self) -> tuple[int, int]:
        fields = (self.proc_root / "stat").read_text(encoding="utf-8").splitlines()[0].split()
        if not fields or fields[0] != "cpu":
            raise ValueError("Invalid /proc/stat")
        counters = [int(value) for value in fields[1:]]
        return sum(counters), counters[3] + (counters[4] if len(counters) > 4 else 0)

    def _memory_percent(self) -> float | None:
        try:
            values: dict[str, int] = {}
            for line in (self.proc_root / "meminfo").read_text(encoding="utf-8").splitlines():
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0])
            total = values["MemTotal"]
            available = values["MemAvailable"]
            if total <= 0:
                return None
            return self._bounded(100.0 * (total - available) / total)
        except (OSError, ValueError, KeyError, IndexError):
            return None

    def _disk_percent(self) -> float | None:
        try:
            usage = shutil.disk_usage(self.disk_root)
            if usage.total <= 0:
                return None
            return self._bounded(100.0 * usage.used / usage.total)
        except OSError:
            return None

    def _load_percent(self) -> float | None:
        try:
            cpu_count = os.cpu_count()
            if not cpu_count:
                return None
            load_average = float(
                (self.proc_root / "loadavg").read_text(encoding="utf-8").split()[0]
            )
            return self._bounded(100.0 * load_average / cpu_count)
        except (OSError, ValueError, IndexError):
            return None


class ProductionHelperOperations:
    def __init__(
        self,
        wireguard: WireGuardAdapter | None,
        xray: XrayAdapter,
        executor: CommandExecutor,
        health_commands: HealthCommandSettings | None = None,
        amneziawg: WireGuardAdapter | None = None,
        metrics_reader: LinuxSystemMetricsReader | None = None,
    ) -> None:
        self.wireguard = wireguard
        self.amneziawg = amneziawg
        self.xray = xray
        self.executor = executor
        self.health_commands = health_commands or HealthCommandSettings()
        self.metrics_reader = metrics_reader or LinuxSystemMetricsReader()

    def issue(self, device_ref: str, protocols: set[Protocol]) -> list[IssuedCredential]:
        issued: list[IssuedCredential] = []
        try:
            if Protocol.WIREGUARD in protocols and self.wireguard is not None:
                issued.append(self.wireguard.issue(device_ref))
            elif Protocol.WIREGUARD in protocols:
                raise RuntimeError("WireGuard backend is unavailable")
            if Protocol.AMNEZIAWG in protocols and self.amneziawg is not None:
                issued.append(self.amneziawg.issue(device_ref))
            elif Protocol.AMNEZIAWG in protocols:
                raise RuntimeError("AmneziaWG backend is unavailable")
            if Protocol.VLESS in protocols:
                issued.append(self.xray.issue(device_ref))
        except Exception:
            for credential in reversed(issued):
                with suppress(Exception):
                    self.revoke(device_ref, credential.protocol)
            raise
        return issued

    def set_enabled(self, device_ref: str, protocol: Protocol, enabled: bool) -> None:
        self._adapter(protocol).set_enabled(device_ref, enabled)

    def revoke(self, device_ref: str, protocol: Protocol) -> None:
        self._adapter(protocol).revoke(device_ref)

    def health(self) -> ServerHealth:
        systemctl = str(self.health_commands.systemctl_binary)
        nft = str(self.health_commands.nft_binary)
        wireguard = (
            ProtocolRuntimeStatus(
                active=self._status((systemctl, "is-active", "wg-quick@wg0.service"), "active"),
                enabled=self._status((systemctl, "is-enabled", "wg-quick@wg0.service"), "enabled"),
            )
            if self.wireguard is not None
            else ProtocolRuntimeStatus(active=False, enabled=False)
        )
        xray = ProtocolRuntimeStatus(
            active=self._status((systemctl, "is-active", "xray.service"), "active"),
            enabled=self._status((systemctl, "is-enabled", "xray.service"), "enabled"),
        )
        amneziawg = (
            ProtocolRuntimeStatus(
                active=self._status((systemctl, "is-active", "awg-quick@awg0.service"), "active"),
                enabled=self._status(
                    (systemctl, "is-enabled", "awg-quick@awg0.service"), "enabled"
                ),
            )
            if self.amneziawg is not None
            else ProtocolRuntimeStatus(active=False, enabled=False)
        )
        failed_output = self.executor.run(
            (systemctl, "list-units", "--state=failed", "--no-legend", "--plain")
        ).stdout
        firewall_active = bool(self.executor.run((nft, "list", "ruleset")).stdout.strip())
        metrics = self.metrics_reader.read()
        return ServerHealth(
            wireguard=wireguard,
            amneziawg=amneziawg,
            xray=xray,
            firewall_active=firewall_active,
            failed_units=len([line for line in failed_output.splitlines() if line.strip()]),
            mode="helper",
            cpu_percent=metrics.cpu_percent,
            memory_percent=metrics.memory_percent,
            disk_percent=metrics.disk_percent,
            load_percent=metrics.load_percent,
        )

    def device_status(self, device_ref: str) -> DeviceRuntimeStatus:
        return DeviceRuntimeStatus(
            wireguard=(
                self.wireguard.runtime_status(device_ref) if self.wireguard is not None else None
            ),
            amneziawg=(
                self.amneziawg.runtime_status(device_ref) if self.amneziawg is not None else None
            ),
            vless=self.xray.runtime_status(device_ref),
        )

    def issue_route_profile(
        self,
        profile_ref: str,
        device_ref: str,
        location_slug: str,
        outbound_tag: str,
    ) -> IssuedRouteProfile:
        return self.xray.issue_route_profile(profile_ref, device_ref, location_slug, outbound_tag)

    def set_route_profile_enabled(self, profile_ref: str, enabled: bool) -> None:
        self.xray.set_route_profile_enabled(profile_ref, enabled)

    def revoke_route_profile(self, profile_ref: str) -> None:
        self.xray.revoke_route_profile(profile_ref)

    def route_health(self, outbound_tag: str) -> RouteRuntimeStatus:
        return self.xray.route_health(outbound_tag)

    def _adapter(self, protocol: Protocol) -> WireGuardAdapter | XrayAdapter:
        if protocol is Protocol.WIREGUARD:
            if self.wireguard is None:
                raise RuntimeError("WireGuard backend is unavailable")
            return self.wireguard
        if protocol is Protocol.AMNEZIAWG:
            if self.amneziawg is None:
                raise RuntimeError("AmneziaWG backend is unavailable")
            return self.amneziawg
        return self.xray

    def _status(self, command: tuple[str, ...], expected: str) -> bool:
        try:
            return self.executor.run(command).stdout.strip() == expected
        except Exception:
            return False
