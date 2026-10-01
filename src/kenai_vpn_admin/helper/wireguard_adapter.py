from __future__ import annotations

import base64
import ipaddress
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kenai_vpn_admin.application.ports import IssuedCredential, ProtocolRuntimeStatus
from kenai_vpn_admin.domain.enums import Protocol as VpnProtocol
from kenai_vpn_admin.helper.atomic_config import AtomicConfigEditor
from kenai_vpn_admin.helper.command_runner import CommandResult
from kenai_vpn_admin.helper.state_store import JsonStateStore, StateConflictError


class CommandExecutor(Protocol):
    def run(
        self, arguments: tuple[str, ...], *, input_text: str | None = None
    ) -> CommandResult: ...


@dataclass(frozen=True)
class WireGuardSettings:
    config_path: Path
    state_path: Path
    interface: str
    network: ipaddress.IPv4Network
    server_address: ipaddress.IPv4Address
    listen_port: int
    endpoint: str
    server_public_key: str
    dns_servers: tuple[str, ...]
    credential_protocol: VpnProtocol = VpnProtocol.WIREGUARD
    interface_settings: tuple[tuple[str, str], ...] = ()
    wg_binary: Path = Path("/usr/bin/wg")
    wg_quick_binary: Path = Path("/usr/bin/wg-quick")


class WireGuardAdapter:
    def __init__(self, settings: WireGuardSettings, executor: CommandExecutor) -> None:
        for name, value in settings.interface_settings:
            if not name or any(character in name for character in "=\r\n\x00"):
                raise ValueError("VPN interface setting name is invalid")
            if any(character in value for character in "\r\n\x00"):
                raise ValueError("VPN interface setting value is invalid")
        self.settings = settings
        self.executor = executor
        self.state = JsonStateStore(settings.state_path)
        self.editor = AtomicConfigEditor(settings.config_path)

    def issue(self, device_ref: str) -> IssuedCredential:
        state = self.state.load()
        if device_ref in state and not bool(state[device_ref].get("revoked")):
            raise StateConflictError("WireGuard credential already exists")
        original = self.settings.config_path.read_text(encoding="utf-8")
        if f"# BEGIN KENAI {device_ref}\n" in original:
            raise StateConflictError("WireGuard managed block already exists")
        address = self._next_address(state, original)
        private_key = X25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        private_text = base64.b64encode(private_raw).decode("ascii")
        public_text = base64.b64encode(public_raw).decode("ascii")
        updated = self._without_block(original, device_ref) + self._peer_block(
            device_ref, public_text, address
        )
        self._apply(updated)
        state[device_ref] = {
            "public_key": public_text,
            "address": str(address),
            "enabled": True,
            "revoked": False,
        }
        self.state.save(state)
        client = self._client_config(private_text, address)
        return IssuedCredential(
            self.settings.credential_protocol, public_text, client, f"{address}/32"
        )

    def set_enabled(self, device_ref: str, enabled: bool) -> None:
        state = self.state.load()
        record = self._record(state, device_ref)
        if bool(record.get("revoked")):
            raise StateConflictError("WireGuard credential is revoked")
        original = self.settings.config_path.read_text(encoding="utf-8")
        updated = self._without_block(original, device_ref)
        if enabled:
            updated += self._peer_block(
                device_ref,
                str(record["public_key"]),
                ipaddress.IPv4Address(str(record["address"])),
            )
        self._apply(updated)
        record["enabled"] = enabled
        self.state.save(state)

    def revoke(self, device_ref: str) -> None:
        state = self.state.load()
        record = self._record(state, device_ref)
        original = self.settings.config_path.read_text(encoding="utf-8")
        self._apply(self._without_block(original, device_ref))
        record["enabled"] = False
        record["revoked"] = True
        self.state.save(state)

    def runtime_status(self, device_ref: str) -> ProtocolRuntimeStatus | None:
        record = self.state.load().get(device_ref)
        if record is None:
            return None
        enabled = bool(record.get("enabled")) and not bool(record.get("revoked"))
        if not enabled:
            return ProtocolRuntimeStatus(active=False, enabled=False)
        public_key = str(record.get("public_key", ""))
        output = self.executor.run(
            (str(self.settings.wg_binary), "show", self.settings.interface, "dump")
        ).stdout
        for line in output.splitlines()[1:]:
            columns = line.split("\t")
            if len(columns) < 8 or columns[0] != public_key:
                continue
            handshake_seconds = int(columns[4])
            return ProtocolRuntimeStatus(
                active=True,
                enabled=True,
                last_seen_at=(
                    datetime.fromtimestamp(handshake_seconds, UTC)
                    if handshake_seconds > 0
                    else None
                ),
                received_bytes=int(columns[5]),
                transmitted_bytes=int(columns[6]),
            )
        return ProtocolRuntimeStatus(active=False, enabled=True)

    def _apply(self, content: str) -> None:
        self.editor.apply(content, validate=self._validate, activate=self._activate)

    def _validate(self, candidate: Path) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".wg-validate-", dir=self.settings.config_path.parent
        ) as directory:
            validation_directory = Path(directory)
            os.chmod(validation_directory, 0o700)
            validation_config = validation_directory / f"{self.settings.interface}.conf"
            shutil.copy2(candidate, validation_config)
            os.chmod(validation_config, 0o600)
            self.executor.run((str(self.settings.wg_quick_binary), "strip", str(validation_config)))

    def _activate(self) -> None:
        stripped = self.executor.run(
            (str(self.settings.wg_quick_binary), "strip", str(self.settings.config_path))
        ).stdout
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".wg-sync.", dir=self.settings.config_path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(stripped)
            os.chmod(temporary, 0o600)
            self.executor.run(
                (str(self.settings.wg_binary), "syncconf", self.settings.interface, str(temporary))
            )
        finally:
            temporary.unlink(missing_ok=True)

    def _next_address(self, state: dict[str, dict[str, Any]], config: str) -> ipaddress.IPv4Address:
        used = {self.settings.server_address}
        used.update(
            ipaddress.IPv4Address(str(record["address"]))
            for record in state.values()
            if "address" in record
        )
        for value in re.findall(r"^AllowedIPs\s*=\s*([^#\n]+)", config, flags=re.MULTILINE):
            for item in value.split(","):
                try:
                    network = ipaddress.ip_network(item.strip(), strict=False)
                except ValueError:
                    continue
                if isinstance(network, ipaddress.IPv4Network):
                    if network.prefixlen == 32:
                        used.add(network.network_address)
                    elif network.overlaps(self.settings.network):
                        raise StateConflictError(
                            "Existing WireGuard AllowedIPs overlaps the managed address pool"
                        )
        for address in self.settings.network.hosts():
            if address not in used:
                return address
        raise StateConflictError("WireGuard address pool is exhausted")

    @staticmethod
    def _record(state: dict[str, dict[str, Any]], device_ref: str) -> dict[str, Any]:
        try:
            return state[device_ref]
        except KeyError as exc:
            raise StateConflictError("WireGuard credential does not exist") from exc

    @staticmethod
    def _without_block(content: str, device_ref: str) -> str:
        begin = f"# BEGIN KENAI {device_ref}\n"
        end = f"# END KENAI {device_ref}\n"
        start = content.find(begin)
        if start < 0:
            return content.rstrip() + "\n"
        finish = content.find(end, start)
        if finish < 0:
            raise StateConflictError("WireGuard managed block is incomplete")
        finish += len(end)
        return (content[:start] + content[finish:]).rstrip() + "\n"

    @staticmethod
    def _peer_block(device_ref: str, public_key: str, address: ipaddress.IPv4Address) -> str:
        return (
            f"\n# BEGIN KENAI {device_ref}\n"
            "[Peer]\n"
            f"PublicKey = {public_key}\n"
            f"AllowedIPs = {address}/32\n"
            f"# END KENAI {device_ref}\n"
        )

    def _client_config(self, private_key: str, address: ipaddress.IPv4Address) -> str:
        dns = ", ".join(self.settings.dns_servers)
        extra = "".join(f"{name} = {value}\n" for name, value in self.settings.interface_settings)
        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            f"DNS = {dns}\n\n"
            f"{extra}"
            "[Peer]\n"
            f"PublicKey = {self.settings.server_public_key}\n"
            f"Endpoint = {self.settings.endpoint}:{self.settings.listen_port}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )
