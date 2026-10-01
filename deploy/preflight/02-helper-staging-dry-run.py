from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

from kenai_vpn_admin.domain.enums import Protocol
from kenai_vpn_admin.helper.dry_run import StagingCommandExecutor
from kenai_vpn_admin.helper.production import ProductionHelperOperations
from kenai_vpn_admin.helper.wireguard_adapter import WireGuardAdapter, WireGuardSettings
from kenai_vpn_admin.helper.xray_adapter import XrayAdapter, XraySettings


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular_source(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or path.is_symlink():
        raise RuntimeError(f"Source is not a regular non-symlink file: {path}")
    return resolved


def copy_with_metadata(source: Path, destination: Path) -> None:
    source_stat = source.stat()
    shutil.copy2(source, destination)
    os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
    if os.name == "posix":
        os.chown(destination, source_stat.st_uid, source_stat.st_gid)  # type: ignore[attr-defined]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kenai helper non-mutating staging dry-run")
    parser.add_argument("--wireguard-config", type=Path, required=True)
    parser.add_argument("--xray-config", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--work-root", type=Path, default=Path("/var/tmp"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    wg_source = regular_source(args.wireguard_config)
    xray_source = regular_source(args.xray_config)
    source_hashes = {"wireguard": sha256(wg_source), "xray": sha256(xray_source)}
    work_root = args.work_root.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="kenai-helper-dry-run-", dir=work_root) as directory:
        staging = Path(directory)
        os.chmod(staging, 0o700)
        wg_copy = staging / "wg0.conf"
        xray_copy = staging / "config.json"
        copy_with_metadata(wg_source, wg_copy)
        copy_with_metadata(xray_source, xray_copy)

        executor = StagingCommandExecutor(
            wg_quick_binary=Path("/usr/bin/wg-quick"),
            xray_binary=Path("/usr/local/bin/xray"),
            wg_binary=Path("/usr/bin/wg"),
            systemctl_binary=Path("/usr/bin/systemctl"),
        )
        wireguard = WireGuardAdapter(
            WireGuardSettings(
                config_path=wg_copy,
                state_path=staging / "wireguard-state.json",
                interface="wg0",
                network=ipaddress.IPv4Network("10.66.66.0/24"),
                server_address=ipaddress.IPv4Address("10.66.66.1"),
                listen_port=51820,
                endpoint=args.endpoint,
                server_public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                dns_servers=("1.1.1.1", "1.0.0.1"),
            ),
            executor,
        )
        xray = XrayAdapter(
            XraySettings(
                config_path=xray_copy,
                state_path=staging / "xray-state.json",
                inbound_tag=None,
                endpoint=args.endpoint,
                port=443,
                server_name=args.server_name,
                reality_public_key="DRY_RUN_PUBLIC_VALUE",
                short_id="00000000",
            ),
            executor,
        )
        operations = ProductionHelperOperations(wireguard, xray, executor)
        issued = operations.issue("kenai-staging-test", {Protocol.WIREGUARD, Protocol.VLESS})
        address = next(
            item.tunnel_address for item in issued if item.protocol is Protocol.WIREGUARD
        )
        operations.set_enabled("kenai-staging-test", Protocol.WIREGUARD, False)
        operations.set_enabled("kenai-staging-test", Protocol.WIREGUARD, True)
        operations.set_enabled("kenai-staging-test", Protocol.VLESS, False)
        operations.set_enabled("kenai-staging-test", Protocol.VLESS, True)
        operations.revoke("kenai-staging-test", Protocol.WIREGUARD)
        operations.revoke("kenai-staging-test", Protocol.VLESS)

        xray_value = json.loads(xray_copy.read_text(encoding="utf-8"))
        client_counts = [
            len(inbound.get("settings", {}).get("clients", []))
            for inbound in xray_value.get("inbounds", [])
            if inbound.get("protocol") == "vless" and inbound.get("port") == 443
        ]
        print("staging_dry_run=pass")
        print(f"allocated_wireguard_address={address}")
        print(f"xray_existing_client_count_after_revoke={client_counts[0]}")
        print(f"simulated_runtime_mutations={len(executor.simulated_mutations)}")
        print("runtime_mutations_executed=0")
        print("credentials_printed=0")

    if sha256(wg_source) != source_hashes["wireguard"]:
        raise RuntimeError("Live WireGuard source hash changed during dry-run")
    if sha256(xray_source) != source_hashes["xray"]:
        raise RuntimeError("Live Xray source hash changed during dry-run")
    print("live_source_hashes_unchanged=yes")


if __name__ == "__main__":
    main()
