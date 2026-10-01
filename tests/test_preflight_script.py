from pathlib import Path


def test_preflight_script_has_no_mutating_commands_or_secret_dump() -> None:
    script = Path("deploy/preflight/01-readonly-vps-inventory.sh").read_text(encoding="utf-8")
    forbidden = (
        "systemctl start",
        "systemctl stop",
        "systemctl restart",
        "systemctl enable",
        "systemctl disable",
        "apt-get",
        "nft -f",
        "nft flush",
        "sed -i",
        "PrivateKey",
        ".settings.clients[]",
        "shortIds",
    )

    assert all(value not in script for value in forbidden)
    assert "wg-quick strip" in script
    assert "xray run -test" in script
    assert "read_only_inventory=completed" in script


def test_vless_only_helper_unit_allows_only_required_runtime_paths() -> None:
    unit = Path("deploy/systemd/kenai-vpn-helper.service").read_text(encoding="utf-8")

    assert "ProtectSystem=strict" in unit
    read_write_line = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
    paths = read_write_line.split("=", 1)[1].split()
    assert "/usr/local/etc/xray" in paths
    assert "/etc/wireguard" not in paths
    assert "/etc/amneziawg" not in paths
