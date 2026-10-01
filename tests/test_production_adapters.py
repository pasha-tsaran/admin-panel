from __future__ import annotations

import ipaddress
import json
import os
import stat
from pathlib import Path

import pytest

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.atomic_config import AtomicConfigEditor, ConfigurationApplyError
from kenai_vpn_admin.helper.command_runner import CommandExecutionError, CommandResult
from kenai_vpn_admin.helper.production import ProductionHelperOperations
from kenai_vpn_admin.helper.state_store import StateConflictError
from kenai_vpn_admin.helper.wireguard_adapter import WireGuardAdapter, WireGuardSettings
from kenai_vpn_admin.helper.xray_adapter import XrayAdapter, XraySettings


class FakeExecutor:
    def __init__(self, *, fail_xray_validation: bool = False) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail_xray_validation = fail_xray_validation
        self.wg_dump = ""
        self.xray_stats = ""
        self.xray_online = ""

    def run(self, arguments: tuple[str, ...], *, input_text: str | None = None) -> CommandResult:
        self.commands.append(arguments)
        if self.fail_xray_validation and "-test" in arguments:
            raise CommandExecutionError("validation failed")
        if len(arguments) >= 3 and arguments[1:2] == ("strip",):
            return CommandResult(Path(arguments[2]).read_text(encoding="utf-8"))
        if len(arguments) >= 4 and arguments[1] == "show" and arguments[3] == "dump":
            return CommandResult(self.wg_dump)
        if len(arguments) >= 2 and arguments[1:3] == ("api", "statsquery"):
            return CommandResult(self.xray_stats)
        if len(arguments) >= 2 and arguments[1:3] == ("api", "statsonline"):
            return CommandResult(self.xray_online)
        return CommandResult("")


@pytest.fixture
def wireguard_adapter(tmp_path: Path) -> tuple[WireGuardAdapter, FakeExecutor, Path, Path]:
    config = tmp_path / "wg0.conf"
    config.write_text(
        "[Interface]\nAddress = 10.66.66.1/24\nListenPort = 51820\n"
        "PrivateKey = server-private-placeholder\n\n"
        "[Peer]\nPublicKey = existing-peer\nAllowedIPs = 10.66.66.2/32\n",
        encoding="utf-8",
    )
    state = tmp_path / "wireguard-state.json"
    executor = FakeExecutor()
    adapter = WireGuardAdapter(
        WireGuardSettings(
            config_path=config,
            state_path=state,
            interface="wg0",
            network=ipaddress.IPv4Network("10.66.66.0/24"),
            server_address=ipaddress.IPv4Address("10.66.66.1"),
            listen_port=51820,
            endpoint="88.218.94.3",
            server_public_key="server-public-placeholder",
            dns_servers=("1.1.1.1", "1.0.0.1"),
            wg_binary=Path("C:/fake/wg.exe"),
            wg_quick_binary=Path("C:/fake/wg-quick.exe"),
        ),
        executor,
    )
    return adapter, executor, config, state


def test_wireguard_issue_disable_enable_and_revoke(
    wireguard_adapter: tuple[WireGuardAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, executor, config, state_path = wireguard_adapter

    credential = adapter.issue("ivan-windows-pc")

    assert credential.protocol is Protocol.WIREGUARD
    assert credential.tunnel_address == "10.66.66.3/32"
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in credential.client_material
    assert "# BEGIN KENAI ivan-windows-pc" in config.read_text(encoding="utf-8")
    assert "PublicKey = existing-peer" in config.read_text(encoding="utf-8")
    state_text = state_path.read_text(encoding="utf-8")
    assert "private" not in state_text.lower()
    assert credential.client_material not in state_text

    adapter.set_enabled("ivan-windows-pc", False)
    assert "ivan-windows-pc" not in config.read_text(encoding="utf-8")

    adapter.set_enabled("ivan-windows-pc", True)
    assert "# BEGIN KENAI ivan-windows-pc" in config.read_text(encoding="utf-8")

    adapter.revoke("ivan-windows-pc")
    assert "ivan-windows-pc" not in config.read_text(encoding="utf-8")
    assert json.loads(state_text)["ivan-windows-pc"]["address"] == "10.66.66.3"
    assert any(command[1:2] == ("syncconf",) for command in executor.commands)
    strip_paths = [Path(command[2]) for command in executor.commands if command[1:2] == ("strip",)]
    assert strip_paths
    assert all(path.name == "wg0.conf" for path in strip_paths)


def test_wireguard_runtime_status_matches_managed_public_key(
    wireguard_adapter: tuple[WireGuardAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, executor, _, _ = wireguard_adapter
    credential = adapter.issue("ivan-windows-pc")
    executor.wg_dump = (
        "server-private\tserver-public\t51820\toff\n"
        f"{credential.public_identifier}\t(none)\t198.51.100.10:54321\t"
        "10.66.66.3/32\t1700000000\t1572864\t524288\t25\n"
    )

    status = adapter.runtime_status("ivan-windows-pc")

    assert status is not None
    assert status.active is True
    assert status.enabled is True
    assert status.last_seen_at is not None
    assert status.received_bytes == 1_572_864
    assert status.transmitted_bytes == 524_288


def test_wireguard_allocator_reserves_revoked_state_addresses(
    wireguard_adapter: tuple[WireGuardAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, _, _, _ = wireguard_adapter
    first = adapter.issue("first-device")
    adapter.revoke("first-device")

    second = adapter.issue("second-device")

    assert first.tunnel_address == "10.66.66.3/32"
    assert second.tunnel_address == "10.66.66.4/32"


def test_amneziawg_uses_independent_pool_binary_and_obfuscation(tmp_path: Path) -> None:
    config = tmp_path / "awg0.conf"
    config.write_text(
        "[Interface]\nAddress = 10.67.67.1/24\nListenPort = 585\n"
        "PrivateKey = server-private-placeholder\n",
        encoding="utf-8",
    )
    executor = FakeExecutor()
    adapter = WireGuardAdapter(
        WireGuardSettings(
            config_path=config,
            state_path=tmp_path / "amneziawg-state.json",
            interface="awg0",
            network=ipaddress.IPv4Network("10.67.67.0/24"),
            server_address=ipaddress.IPv4Address("10.67.67.1"),
            listen_port=585,
            endpoint="88.218.94.3",
            server_public_key="awg-server-public-placeholder",
            dns_servers=("1.1.1.1", "1.0.0.1"),
            credential_protocol=Protocol.AMNEZIAWG,
            interface_settings=(
                ("Jc", "7"),
                ("Jmin", "64"),
                ("Jmax", "256"),
                ("S1", "32"),
                ("S2", "32"),
                ("S3", "32"),
                ("S4", "16"),
                ("H1", "100000000-199999999"),
                ("H2", "200000000-299999999"),
                ("H3", "300000000-399999999"),
                ("H4", "400000000-499999999"),
                ("I1", "<b 0x170303><r 32><t>"),
            ),
            wg_binary=Path("C:/fake/awg.exe"),
            wg_quick_binary=Path("C:/fake/awg-quick.exe"),
        ),
        executor,
    )

    credential = adapter.issue("ivan-windows-pc")

    assert credential.protocol is Protocol.AMNEZIAWG
    assert credential.tunnel_address == "10.67.67.2/32"
    assert "Endpoint = 88.218.94.3:585" in credential.client_material
    assert "Jc = 7" in credential.client_material
    assert "H4 = 400000000-499999999" in credential.client_material
    assert "I1 = <b 0x170303><r 32><t>" in credential.client_material
    assert any(command[0] == str(Path("C:/fake/awg-quick.exe")) for command in executor.commands)
    assert any(command[0] == str(Path("C:/fake/awg.exe")) for command in executor.commands)


def test_amneziawg_rejects_multiline_interface_parameter(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="value is invalid"):
        WireGuardAdapter(
            WireGuardSettings(
                config_path=tmp_path / "awg0.conf",
                state_path=tmp_path / "state.json",
                interface="awg0",
                network=ipaddress.IPv4Network("10.67.67.0/24"),
                server_address=ipaddress.IPv4Address("10.67.67.1"),
                listen_port=585,
                endpoint="88.218.94.3",
                server_public_key="awg-server-public-placeholder",
                dns_servers=("1.1.1.1",),
                interface_settings=(("I1", "valid\nPostUp = unsafe"),),
            ),
            FakeExecutor(),
        )


@pytest.fixture
def xray_adapter(tmp_path: Path) -> tuple[XrayAdapter, FakeExecutor, Path, Path]:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality",
                        "protocol": "vless",
                        "settings": {"clients": []},
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
        encoding="utf-8",
    )
    state = tmp_path / "xray-state.json"
    executor = FakeExecutor()
    adapter = XrayAdapter(
        XraySettings(
            config_path=config,
            state_path=state,
            inbound_tag="vless-reality",
            endpoint="88.218.94.3",
            port=443,
            server_name="example.org",
            reality_public_key="public-key",
            short_id="01234567",
            xray_binary=Path("C:/fake/xray.exe"),
            systemctl_binary=Path("C:/fake/systemctl.exe"),
        ),
        executor,
    )
    return adapter, executor, config, state


def test_xray_issue_disable_enable_and_revoke(
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, executor, config, state_path = xray_adapter

    credential = adapter.issue("ivan-android")

    assert credential.protocol is Protocol.VLESS
    assert credential.client_material.startswith("vless://")
    clients = json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]
    assert clients == [
        {"id": credential.public_identifier, "email": "ivan-android", "flow": "xtls-rprx-vision"}
    ]
    assert "vless://" not in state_path.read_text(encoding="utf-8")

    adapter.set_enabled("ivan-android", False)
    assert (
        json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"] == []
    )

    adapter.set_enabled("ivan-android", True)
    adapter.revoke("ivan-android")
    assert (
        json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"] == []
    )
    assert any("reload-or-restart" in command for command in executor.commands)
    validation_paths = [
        Path(command[4])
        for command in executor.commands
        if len(command) >= 5 and command[1:4] == ("run", "-test", "-config")
    ]
    assert validation_paths
    assert all(path.name == "config.json" for path in validation_paths)


def test_xray_runtime_status_reads_only_matching_user_counters(
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    _, executor, config, state_path = xray_adapter
    adapter = XrayAdapter(
        XraySettings(
            config_path=config,
            state_path=state_path,
            inbound_tag="vless-reality",
            endpoint="88.218.94.3",
            port=443,
            server_name="example.org",
            reality_public_key="public-key",
            short_id="01234567",
            stats_server="127.0.0.1:10085",
            xray_binary=Path("C:/fake/xray.exe"),
            systemctl_binary=Path("C:/fake/systemctl.exe"),
        ),
        executor,
    )
    adapter.issue("ivan-android")
    executor.xray_stats = json.dumps(
        {
            "stat": [
                {"name": "user>>>ivan-android>>>traffic>>>downlink", "value": "3145728"},
                {"name": "user>>>ivan-android>>>traffic>>>uplink", "value": 1048576},
                {"name": "user>>>another-device>>>traffic>>>downlink", "value": 999},
            ]
        }
    )
    executor.xray_online = json.dumps(
        {"stat": {"name": "user>>>ivan-android>>>online", "value": "2"}}
    )

    status = adapter.runtime_status("ivan-android")

    assert status is not None
    assert status.received_bytes == 3_145_728
    assert status.transmitted_bytes == 1_048_576
    assert status.current_connections == 2
    assert status.active is True
    stats_command = executor.commands[-2]
    assert "--server=127.0.0.1:10085" in stats_command
    assert "--pattern=user>>>ivan-android>>>traffic>>>" in stats_command
    assert "--reset=false" in stats_command
    online_command = executor.commands[-1]
    assert "statsonline" in online_command
    assert "--email=ivan-android" in online_command


def test_xray_runtime_status_rejects_invalid_counter(
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, _, _, _ = xray_adapter

    with pytest.raises(StateConflictError):
        adapter._parse_stats(
            '{"stat":[{"name":"user>>>device>>>traffic>>>uplink","value":-1}]}',
            "user>>>device>>>traffic>>>",
        )


def test_xray_rejects_online_counter_for_another_user() -> None:
    with pytest.raises(StateConflictError):
        XrayAdapter._parse_online_connections(
            '{"stat":{"name":"user>>>another-device>>>online","value":1}}',
            "device",
        )


def test_xray_treats_an_online_counter_without_value_as_offline() -> None:
    assert (
        XrayAdapter._parse_online_connections(
            '{"stat":{"name":"user>>>device>>>online"}}',
            "device",
        )
        == 0
    )


def test_xray_refuses_to_replace_an_unmanaged_client(
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    adapter, _, config, _ = xray_adapter
    value = json.loads(config.read_text(encoding="utf-8"))
    value["inbounds"][0]["settings"]["clients"].append(
        {"id": "existing-uuid", "email": "existing-device", "flow": "xtls-rprx-vision"}
    )
    config.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(StateConflictError):
        adapter.issue("existing-device")

    clients = json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]
    assert clients[0]["id"] == "existing-uuid"


def test_atomic_editor_restores_original_when_activation_fails(tmp_path: Path) -> None:
    config = tmp_path / "service.conf"
    config.write_text("original\n", encoding="utf-8")
    editor = AtomicConfigEditor(config)

    with pytest.raises(ConfigurationApplyError):
        editor.apply(
            "candidate\n",
            validate=lambda _: None,
            activate=lambda: (_ for _ in ()).throw(RuntimeError("activation failed")),
        )

    assert config.read_text(encoding="utf-8") == "original\n"


def test_atomic_editor_preserves_file_mode(tmp_path: Path) -> None:
    config = tmp_path / "service.conf"
    config.write_text("original\n", encoding="utf-8")
    os.chmod(config, 0o640)
    original_mode = stat.S_IMODE(config.stat().st_mode)

    AtomicConfigEditor(config).apply("candidate\n", validate=lambda _: None, activate=lambda: None)

    assert stat.S_IMODE(config.stat().st_mode) == original_mode


def test_adapters_accept_sanitized_vps_structure(tmp_path: Path) -> None:
    fixture_root = Path("tests/fixtures/vps")
    wg_config = tmp_path / "wg0.conf"
    wg_config.write_text(
        (fixture_root / "wg0.sanitized.txt").read_text(encoding="utf-8"), encoding="utf-8"
    )
    xray_config = tmp_path / "config.json"
    xray_config.write_text(
        (fixture_root / "xray.sanitized.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    executor = FakeExecutor()
    wireguard = WireGuardAdapter(
        WireGuardSettings(
            config_path=wg_config,
            state_path=tmp_path / "wg-state.json",
            interface="wg0",
            network=ipaddress.IPv4Network("10.66.66.0/24"),
            server_address=ipaddress.IPv4Address("10.66.66.1"),
            listen_port=51820,
            endpoint="88.218.94.3",
            server_public_key="server-public-placeholder",
            dns_servers=("1.1.1.1", "1.0.0.1"),
            wg_binary=Path("C:/fake/wg.exe"),
            wg_quick_binary=Path("C:/fake/wg-quick.exe"),
        ),
        executor,
    )
    xray = XrayAdapter(
        XraySettings(
            config_path=xray_config,
            state_path=tmp_path / "xray-state.json",
            inbound_tag=None,
            endpoint="88.218.94.3",
            port=443,
            server_name="mirrors.teamcloud.am",
            reality_public_key="public-key-placeholder",
            short_id="01234567",
            xray_binary=Path("C:/fake/xray.exe"),
            systemctl_binary=Path("C:/fake/systemctl.exe"),
        ),
        executor,
    )

    issued = ProductionHelperOperations(wireguard, xray, executor).issue(
        "fixture-test-device", {Protocol.WIREGUARD, Protocol.VLESS}
    )

    assert {credential.protocol for credential in issued} == {Protocol.WIREGUARD, Protocol.VLESS}
    assert (
        next(
            credential.tunnel_address
            for credential in issued
            if credential.protocol is Protocol.WIREGUARD
        )
        == "10.66.66.3/32"
    )
    updated_xray = json.loads(xray_config.read_text(encoding="utf-8"))
    assert len(updated_xray["inbounds"][0]["settings"]["clients"]) == 2


def test_dual_protocol_issue_revokes_wireguard_if_xray_fails(
    wireguard_adapter: tuple[WireGuardAdapter, FakeExecutor, Path, Path],
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    wireguard, _, wireguard_config, wireguard_state = wireguard_adapter
    xray, _, _, _ = xray_adapter
    xray.executor = FakeExecutor(fail_xray_validation=True)
    operations = ProductionHelperOperations(wireguard, xray, FakeExecutor())

    with pytest.raises(CommandExecutionError):
        operations.issue("rollback-test-device", {Protocol.WIREGUARD, Protocol.VLESS})

    assert "rollback-test-device" not in wireguard_config.read_text(encoding="utf-8")
    state = json.loads(wireguard_state.read_text(encoding="utf-8"))
    assert state["rollback-test-device"]["revoked"] is True


def test_vless_only_operations_do_not_require_wireguard(
    xray_adapter: tuple[XrayAdapter, FakeExecutor, Path, Path],
) -> None:
    xray, executor, _, _ = xray_adapter
    operations = ProductionHelperOperations(None, xray, executor)

    issued = operations.issue("vless-only-device", {Protocol.VLESS})

    assert [credential.protocol for credential in issued] == [Protocol.VLESS]
    assert operations.device_status("vless-only-device").wireguard is None
