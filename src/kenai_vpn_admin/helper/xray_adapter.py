from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from kenai_vpn_admin.application.ports import (
    IssuedCredential,
    IssuedRouteProfile,
    ProtocolRuntimeStatus,
    RouteRuntimeStatus,
)
from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.atomic_config import AtomicConfigEditor
from kenai_vpn_admin.helper.command_runner import CommandExecutionError
from kenai_vpn_admin.helper.state_store import JsonStateStore, StateConflictError
from kenai_vpn_admin.helper.wireguard_adapter import CommandExecutor


@dataclass(frozen=True)
class XraySettings:
    config_path: Path
    state_path: Path
    inbound_tag: str | None
    endpoint: str
    port: int
    server_name: str
    reality_public_key: str
    short_id: str
    stats_server: str | None = None
    xray_binary: Path = Path("/usr/local/bin/xray")
    systemctl_binary: Path = Path("/usr/bin/systemctl")


class XrayAdapter:
    def __init__(self, settings: XraySettings, executor: CommandExecutor) -> None:
        self.settings = settings
        self.executor = executor
        self.state = JsonStateStore(settings.state_path)
        self.editor = AtomicConfigEditor(settings.config_path)

    def issue(self, device_ref: str) -> IssuedCredential:
        state = self.state.load()
        if device_ref in state and not bool(state[device_ref].get("revoked")):
            raise StateConflictError("VLESS credential already exists")
        client_uuid = str(uuid.uuid4())
        config = self._load_config()
        clients = self._clients(config)
        if any(client.get("email") == device_ref for client in clients):
            raise StateConflictError("VLESS client identifier already exists")
        clients.append(self._client(device_ref, client_uuid))
        self._apply(config)
        state[device_ref] = {
            "client_uuid": client_uuid,
            "enabled": True,
            "revoked": False,
        }
        self.state.save(state)
        return IssuedCredential(
            Protocol.VLESS,
            client_uuid,
            self._client_uri(device_ref, client_uuid),
        )

    def set_enabled(self, device_ref: str, enabled: bool) -> None:
        state = self.state.load()
        record = self._record(state, device_ref)
        if bool(record.get("revoked")):
            raise StateConflictError("VLESS credential is revoked")
        config = self._load_config()
        clients = self._clients(config)
        self._remove_client(clients, device_ref)
        if enabled:
            clients.append(self._client(device_ref, str(record["client_uuid"])))
        self._apply(config)
        record["enabled"] = enabled
        self.state.save(state)

    def revoke(self, device_ref: str) -> None:
        state = self.state.load()
        record = self._record(state, device_ref)
        config = self._load_config()
        self._remove_client(self._clients(config), device_ref)
        self._apply(config)
        record["enabled"] = False
        record["revoked"] = True
        self.state.save(state)

    def runtime_status(self, device_ref: str) -> ProtocolRuntimeStatus | None:
        record = self.state.load().get(device_ref)
        if record is None:
            return None
        enabled = bool(record.get("enabled")) and not bool(record.get("revoked"))
        if not enabled or self.settings.stats_server is None:
            return ProtocolRuntimeStatus(active=enabled, enabled=enabled)
        prefix = f"user>>>{device_ref}>>>traffic>>>"
        output = self.executor.run(
            (
                str(self.settings.xray_binary),
                "api",
                "statsquery",
                f"--server={self.settings.stats_server}",
                f"--pattern={prefix}",
                "--reset=false",
            )
        ).stdout
        received, transmitted = self._parse_stats(output, prefix)
        current_connections = self._online_connections(device_ref)
        return ProtocolRuntimeStatus(
            active=current_connections > 0,
            enabled=True,
            received_bytes=received,
            transmitted_bytes=transmitted,
            current_connections=current_connections,
        )

    def issue_route_profile(
        self,
        profile_ref: str,
        device_ref: str,
        location_slug: str,
        outbound_tag: str,
    ) -> IssuedRouteProfile:
        state = self.state.load()
        state_key = self._route_state_key(profile_ref)
        if state_key in state and not bool(state[state_key].get("revoked")):
            raise StateConflictError("VLESS route profile already exists")
        config = self._load_config()
        if not self._outbound_exists(config, outbound_tag):
            raise StateConflictError("Configured route outbound does not exist")
        client_uuid = str(uuid.uuid4())
        client_email = f"route:{location_slug}:{device_ref}"
        clients = self._clients(config)
        if any(client.get("email") == client_email for client in clients):
            raise StateConflictError("VLESS route client identifier already exists")
        clients.append(self._client(client_email, client_uuid))
        self._routing_rules(config).insert(
            0,
            self._route_rule(profile_ref, client_email, location_slug),
        )
        self._apply(config)
        state[state_key] = {
            "client_uuid": client_uuid,
            "client_email": client_email,
            "location_slug": location_slug,
            "outbound_tag": outbound_tag,
            "enabled": True,
            "revoked": False,
        }
        self.state.save(state)
        return IssuedRouteProfile(
            public_identifier=client_uuid,
            client_email=client_email,
            client_uri=self._client_uri(location_slug, client_uuid),
        )

    def set_route_profile_enabled(self, profile_ref: str, enabled: bool) -> None:
        state = self.state.load()
        record = self._route_record(state, profile_ref)
        if bool(record.get("revoked")):
            raise StateConflictError("VLESS route profile is revoked")
        config = self._load_config()
        client_email = str(record["client_email"])
        clients = self._clients(config)
        self._remove_client(clients, client_email)
        rules = self._routing_rules(config)
        self._remove_route_rule(rules, profile_ref)
        if enabled:
            clients.append(self._client(client_email, str(record["client_uuid"])))
            rules.insert(
                0,
                self._route_rule(profile_ref, client_email, str(record["location_slug"])),
            )
        self._apply(config)
        record["enabled"] = enabled
        self.state.save(state)

    def revoke_route_profile(self, profile_ref: str) -> None:
        state = self.state.load()
        record = self._route_record(state, profile_ref)
        config = self._load_config()
        self._remove_client(self._clients(config), str(record["client_email"]))
        self._remove_route_rule(self._routing_rules(config), profile_ref)
        self._apply(config)
        record["enabled"] = False
        record["revoked"] = True
        self.state.save(state)

    def route_health(self, outbound_tag: str) -> RouteRuntimeStatus:
        if self.settings.stats_server is None:
            return RouteRuntimeStatus(outbound_tag, False, error_code="OBSERVATORY_UNAVAILABLE")
        balancer_tag = self._balancer_tag(outbound_tag.removeprefix("kenai-exit-"))
        try:
            output = self.executor.run(
                (
                    str(self.settings.xray_binary),
                    "api",
                    "bi",
                    f"--server={self.settings.stats_server}",
                    balancer_tag,
                )
            ).stdout
            payload = json.loads(output)
        except (CommandExecutionError, json.JSONDecodeError):
            return RouteRuntimeStatus(outbound_tag, False, error_code="PROBE_FAILED")
        alive, latency_ms = self._parse_balancer_health(payload, outbound_tag)
        return RouteRuntimeStatus(
            outbound_tag,
            alive,
            latency_ms=latency_ms,
            error_code=None if alive else "OUTBOUND_UNAVAILABLE",
        )

    def _online_connections(self, device_ref: str) -> int:
        assert self.settings.stats_server is not None
        try:
            output = self.executor.run(
                (
                    str(self.settings.xray_binary),
                    "api",
                    "statsonline",
                    f"--server={self.settings.stats_server}",
                    f"--email={device_ref}",
                )
            ).stdout
        except CommandExecutionError:
            # Xray returns a non-zero status when the per-user online counter
            # does not exist, which is the normal representation of offline.
            return 0
        return self._parse_online_connections(output, device_ref)

    @staticmethod
    def _parse_online_connections(output: str, device_ref: str) -> int:
        try:
            payload = json.loads(output)
            stat = payload["stat"]
            name = stat["name"]
            # Xray omits ``value`` for a valid online counter whose current
            # value is zero.  Treat that wire representation as offline
            # instead of making one idle device hide the whole dashboard.
            value = int(stat.get("value", 0))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise StateConflictError("Xray online statistics response is invalid") from exc
        if name != f"user>>>{device_ref}>>>online" or value < 0:
            raise StateConflictError("Xray online statistics response is invalid")
        return value

    @staticmethod
    def _parse_stats(output: str, prefix: str) -> tuple[int, int]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise StateConflictError("Xray statistics response is invalid") from exc
        stats = payload.get("stat") if isinstance(payload, dict) else None
        if stats is None:
            return (0, 0)
        if not isinstance(stats, list):
            raise StateConflictError("Xray statistics response is invalid")
        values: dict[str, int] = {}
        for item in stats:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise StateConflictError("Xray statistics response is invalid")
            name = item["name"]
            if name not in {prefix + "uplink", prefix + "downlink"}:
                continue
            try:
                value = int(item.get("value", 0))
            except (TypeError, ValueError) as exc:
                raise StateConflictError("Xray statistics response is invalid") from exc
            if value < 0:
                raise StateConflictError("Xray statistics response is invalid")
            values[name] = value
        return (values.get(prefix + "downlink", 0), values.get(prefix + "uplink", 0))

    def _load_config(self) -> dict[str, Any]:
        value = json.loads(self.settings.config_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise StateConflictError("Xray configuration root must be an object")
        return value

    def _clients(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        inbounds = config.get("inbounds")
        if not isinstance(inbounds, list):
            raise StateConflictError("Xray inbounds are missing")
        candidates = [
            inbound
            for inbound in inbounds
            if isinstance(inbound, dict) and self._matches_inbound(inbound)
        ]
        if len(candidates) != 1:
            raise StateConflictError("Exactly one managed Xray inbound must match")
        settings = candidates[0].get("settings")
        if not isinstance(settings, dict):
            raise StateConflictError("Managed Xray inbound settings are invalid")
        if "clients" in settings and "users" in settings:
            raise StateConflictError(
                "Managed Xray inbound must not define clients and users together"
            )
        clients = settings.get("users") if "users" in settings else settings.get("clients")
        if not isinstance(clients, list) or not all(isinstance(client, dict) for client in clients):
            raise StateConflictError("Managed Xray client list is invalid")
        return clients

    @staticmethod
    def _outbound_exists(config: dict[str, Any], outbound_tag: str) -> bool:
        outbounds = config.get("outbounds")
        return isinstance(outbounds, list) and any(
            isinstance(item, dict) and item.get("tag") == outbound_tag for item in outbounds
        )

    @staticmethod
    def _routing_rules(config: dict[str, Any]) -> list[dict[str, Any]]:
        routing = config.get("routing")
        if not isinstance(routing, dict):
            raise StateConflictError("Xray routing configuration is missing")
        rules = routing.get("rules")
        if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
            raise StateConflictError("Xray routing rules are invalid")
        return rules

    def _matches_inbound(self, inbound: dict[str, Any]) -> bool:
        if self.settings.inbound_tag is not None:
            return inbound.get("tag") == self.settings.inbound_tag
        return inbound.get("protocol") == "vless" and inbound.get("port") == self.settings.port

    def _apply(self, config: dict[str, Any]) -> None:
        content = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        self.editor.apply(content, validate=self._validate, activate=self._activate)

    def _validate(self, candidate: Path) -> None:
        # Xray detects the configuration format from the filename suffix.  The
        # atomic editor deliberately gives candidates a random suffix, so
        # validate a private copy whose name still ends in ``.json``.
        with tempfile.TemporaryDirectory(prefix="kenai-xray-validate-") as directory:
            validation_config = Path(directory) / "config.json"
            shutil.copy2(candidate, validation_config)
            self.executor.run(
                (
                    str(self.settings.xray_binary),
                    "run",
                    "-test",
                    "-config",
                    str(validation_config),
                )
            )

    def _activate(self) -> None:
        self.executor.run(
            (str(self.settings.systemctl_binary), "reload-or-restart", "xray.service")
        )

    @staticmethod
    def _client(device_ref: str, client_uuid: str) -> dict[str, str]:
        return {"id": client_uuid, "email": device_ref, "flow": "xtls-rprx-vision"}

    @staticmethod
    def _remove_client(clients: list[dict[str, Any]], device_ref: str) -> None:
        clients[:] = [client for client in clients if client.get("email") != device_ref]

    @staticmethod
    def _record(state: dict[str, dict[str, Any]], device_ref: str) -> dict[str, Any]:
        try:
            return state[device_ref]
        except KeyError as exc:
            raise StateConflictError("VLESS credential does not exist") from exc

    @staticmethod
    def _route_state_key(profile_ref: str) -> str:
        return f"route-profile:{profile_ref}"

    @classmethod
    def _route_record(cls, state: dict[str, dict[str, Any]], profile_ref: str) -> dict[str, Any]:
        try:
            return state[cls._route_state_key(profile_ref)]
        except KeyError as exc:
            raise StateConflictError("VLESS route profile does not exist") from exc

    @staticmethod
    def _balancer_tag(location_slug: str) -> str:
        return f"kenai-balancer-{location_slug}"

    @classmethod
    def _route_rule(
        cls, profile_ref: str, client_email: str, location_slug: str
    ) -> dict[str, object]:
        return {
            "type": "field",
            "user": [client_email],
            "balancerTag": cls._balancer_tag(location_slug),
            "ruleTag": f"kenai-profile-{profile_ref}",
        }

    @staticmethod
    def _remove_route_rule(rules: list[dict[str, Any]], profile_ref: str) -> None:
        rule_tag = f"kenai-profile-{profile_ref}"
        rules[:] = [rule for rule in rules if rule.get("ruleTag") != rule_tag]

    @staticmethod
    def _parse_balancer_health(payload: object, outbound_tag: str) -> tuple[bool, int | None]:
        matches: list[dict[str, Any]] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                tag = value.get("outboundTag", value.get("outbound_tag"))
                if tag == outbound_tag:
                    matches.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(payload)
        if not matches:
            return (False, None)
        for match in matches:
            alive_value = match.get("alive", match.get("available", match.get("isAlive")))
            delay_value = match.get("delay", match.get("latencyMs", match.get("latency_ms")))
            alive = bool(alive_value)
            try:
                latency_ms = int(delay_value) if delay_value is not None else None
            except (TypeError, ValueError):
                latency_ms = None
            if alive:
                return (True, latency_ms)
        return (False, None)

    def _client_uri(self, device_ref: str, client_uuid: str) -> str:
        query = urlencode(
            {
                "type": "raw",
                "security": "reality",
                "flow": "xtls-rprx-vision",
                "sni": self.settings.server_name,
                "fp": "chrome",
                "pbk": self.settings.reality_public_key,
                "sid": self.settings.short_id,
            }
        )
        label = quote(device_ref, safe="")
        return (
            f"vless://{client_uuid}@{self.settings.endpoint}:{self.settings.port}?{query}#{label}"
        )
