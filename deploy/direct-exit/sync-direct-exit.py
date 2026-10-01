#!/usr/bin/env python3
"""Mirror Armenia's active VLESS UUID allowlist to the independent NL Xray.

All server-specific REALITY parameters live in a root-only local JSON file.
The SSH key must be restricted to the forced export command on Armenia.
"""

import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import UUID

XRAY = Path("/usr/local/bin/xray")
CONFIG = Path("/usr/local/etc/xray/config.json")
PRIVATE = Path("/etc/kenai-vpn/nl-reality.json")
SSH_KEY = Path("/etc/kenai-vpn/armenia-sync-key")
KNOWN_HOSTS = Path("/etc/kenai-vpn/armenia-known-hosts")
LAST_SUCCESS = Path("/usr/local/etc/xray/.last-success")
AWG_INTERFACE = Path("/etc/kenai-awg31/interface.conf")
AWG_CONFIG = Path("/etc/kenai-awg31/awg0.conf")
AWG_CONTAINER = "kenai-awg31"
MAX_STALENESS_SECONDS = 180
LABEL = re.compile(r"^[a-zA-Z0-9_.:@-]{1,253}$")


def fetch_manifest() -> tuple[list[dict[str, str]], list[dict[str, str | None]]]:
    completed = subprocess.run(
        [
            "/usr/bin/ssh",
            "-i",
            str(SSH_KEY),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-o",
            "ConnectTimeout=8",
            "root@88.218.94.3",
            "export-active-vless",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    if len(completed.stdout) > 256 * 1024:
        raise ValueError("VLESS manifest too large")
    manifest = json.loads(completed.stdout)
    if (
        manifest.get("version") != 2
        or not isinstance(manifest.get("clients"), list)
        or not isinstance(manifest.get("awg_peers"), list)
    ):
        raise ValueError("Invalid direct-exit manifest")
    clients = manifest["clients"]
    if len(clients) > 2000:
        raise ValueError("Too many VLESS clients")
    seen: set[str] = set()
    for client in clients:
        if not isinstance(client, dict) or set(client) != {"id", "email"}:
            raise ValueError("Invalid VLESS client")
        client["id"] = str(UUID(client["id"]))
        if not isinstance(client["email"], str) or not LABEL.fullmatch(client["email"]):
            raise ValueError("Invalid VLESS client label")
        if client["id"] in seen:
            raise ValueError("Duplicate VLESS client")
        seen.add(client["id"])
    peers = manifest["awg_peers"]
    if len(peers) > 2000:
        raise ValueError("Too many AmneziaWG peers")
    seen_keys: set[str] = set()
    seen_addresses: set[str] = set()
    pool = ipaddress.ip_network("10.67.67.0/24")
    for peer in peers:
        if not isinstance(peer, dict) or set(peer) != {
            "public_key",
            "preshared_key",
            "allowed_ips",
        }:
            raise ValueError("Invalid AmneziaWG peer")
        for name in ("public_key", "preshared_key"):
            value = peer[name]
            if name == "preshared_key" and value is None:
                continue
            if not isinstance(value, str):
                raise ValueError("Invalid AmneziaWG key")
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError("Invalid AmneziaWG key")
        allowed = ipaddress.ip_network(peer["allowed_ips"], strict=False)
        if (
            not isinstance(allowed, ipaddress.IPv4Network)
            or allowed.prefixlen != 32
            or not allowed.subnet_of(pool)
            or peer["public_key"] in seen_keys
            or str(allowed) in seen_addresses
        ):
            raise ValueError("Invalid AmneziaWG peer address")
        seen_keys.add(peer["public_key"])
        seen_addresses.add(str(allowed))
        peer["allowed_ips"] = str(allowed)
    return clients, peers


def fetch_clients() -> list[dict[str, str]]:
    return fetch_manifest()[0]


def build_config(private: dict, clients: list[dict[str, str]]) -> dict:
    target = private["target"]
    server_name = private["server_name"]
    if not isinstance(target, str) or not re.fullmatch(r"[a-zA-Z0-9.-]+:443", target):
        raise ValueError("Invalid REALITY target")
    if not isinstance(server_name, str) or not re.fullmatch(r"[a-zA-Z0-9.-]+", server_name):
        raise ValueError("Invalid REALITY server name")
    if not isinstance(private["private_key"], str) or len(private["private_key"]) != 43:
        raise ValueError("Invalid REALITY private key")
    if not isinstance(private["short_id"], str) or not re.fullmatch(
        r"[0-9a-f]{2,16}", private["short_id"]
    ):
        raise ValueError("Invalid REALITY short ID")
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": client["id"], "email": client["email"], "flow": "xtls-rprx-vision"}
                        for client in clients
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": target,
                        "serverNames": [server_name],
                        "privateKey": private["private_key"],
                        "shortIds": [private["short_id"]],
                    },
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def build_awg_config(interface: str, peers: list[dict[str, str | None]]) -> bytes:
    if (
        len(interface) > 64 * 1024
        or not interface.lstrip().startswith("[Interface]")
        or "[Peer]" in interface
        or "\x00" in interface
    ):
        raise ValueError("Invalid AmneziaWG interface configuration")
    blocks = [interface.rstrip(), ""]
    for peer in peers:
        blocks.extend(["[Peer]", f"PublicKey = {peer['public_key']}"])
        if peer["preshared_key"] is not None:
            blocks.append(f"PresharedKey = {peer['preshared_key']}")
        blocks.extend([f"AllowedIPs = {peer['allowed_ips']}", ""])
    return ("\n".join(blocks).rstrip() + "\n").encode()


def sync_awg(peers: list[dict[str, str | None]]) -> bool:
    rendered = build_awg_config(AWG_INTERFACE.read_text(encoding="utf-8"), peers)
    subprocess.run(
        ["/usr/bin/docker", "start", AWG_CONTAINER],
        check=True,
        capture_output=True,
        timeout=20,
    )
    if AWG_CONFIG.exists() and AWG_CONFIG.read_bytes() == rendered:
        subprocess.run(
            ["/usr/bin/docker", "exec", AWG_CONTAINER, "awg", "show", "awg0"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return False
    fd, temp_name = tempfile.mkstemp(prefix=".awg0-", suffix=".conf", dir=AWG_CONFIG.parent)
    temporary = Path(temp_name)
    previous = AWG_CONFIG.read_bytes() if AWG_CONFIG.exists() else None
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, AWG_CONFIG)
        try:
            subprocess.run(
                [
                    "/usr/bin/docker",
                    "exec",
                    AWG_CONTAINER,
                    "sh",
                    "-ec",
                    "awg-quick strip /etc/amnezia/awg/awg0.conf | awg syncconf awg0 /dev/stdin",
                ],
                check=True,
                capture_output=True,
                timeout=15,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if previous is not None:
                AWG_CONFIG.write_bytes(previous)
                os.chmod(AWG_CONFIG, 0o600)
                subprocess.run(
                    [
                        "/usr/bin/docker",
                        "exec",
                        AWG_CONTAINER,
                        "sh",
                        "-ec",
                        "awg-quick strip /etc/amnezia/awg/awg0.conf | awg syncconf awg0 /dev/stdin",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=15,
                )
            raise
        return True
    finally:
        temporary.unlink(missing_ok=True)


def sync_xray(clients: list[dict[str, str]]) -> bool:
    import grp  # POSIX-only deployment; keep pure config tests runnable on Windows.

    private = json.loads(PRIVATE.read_text(encoding="utf-8"))
    rendered = (json.dumps(build_config(private, clients), indent=2) + "\n").encode()
    if CONFIG.exists() and CONFIG.read_bytes() == rendered:
        subprocess.run(
            ["/usr/bin/systemctl", "start", "xray.service"],
            check=True,
            capture_output=True,
            timeout=20,
        )
        return False
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=CONFIG.parent)
    temporary = Path(temp_name)
    previous = CONFIG.read_bytes() if CONFIG.exists() else None
    try:
        os.fchown(fd, 0, grp.getgrnam("xray").gr_gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        subprocess.run(
            [str(XRAY), "run", "-test", "-config", str(temporary)],
            check=True,
            capture_output=True,
            timeout=15,
        )
        os.replace(temporary, CONFIG)
        try:
            subprocess.run(
                ["/usr/bin/systemctl", "reload-or-restart", "xray.service"],
                check=True,
                capture_output=True,
                timeout=20,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if previous is not None:
                fd, rollback_name = tempfile.mkstemp(
                    prefix=".rollback-", suffix=".json", dir=CONFIG.parent
                )
                with os.fdopen(fd, "wb") as output:
                    os.fchown(output.fileno(), 0, grp.getgrnam("xray").gr_gid)
                    os.fchmod(output.fileno(), 0o640)
                    output.write(previous)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(rollback_name, CONFIG)
                subprocess.run(
                    ["/usr/bin/systemctl", "restart", "xray.service"],
                    check=False,
                    capture_output=True,
                    timeout=20,
                )
            raise
        return True
    finally:
        temporary.unlink(missing_ok=True)


def sync() -> bool:
    clients, peers = fetch_manifest()
    xray_changed = sync_xray(clients)
    awg_changed = sync_awg(peers)
    LAST_SUCCESS.touch()
    return xray_changed or awg_changed


if __name__ == "__main__":
    try:
        sync()
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        if (
            not LAST_SUCCESS.exists()
            or time.time() - LAST_SUCCESS.stat().st_mtime > MAX_STALENESS_SECONDS
        ):
            subprocess.run(
                ["/usr/bin/systemctl", "stop", "xray.service"],
                check=False,
                capture_output=True,
                timeout=15,
            )
            subprocess.run(
                ["/usr/bin/docker", "stop", AWG_CONTAINER],
                check=False,
                capture_output=True,
                timeout=15,
            )
        print(f"Direct-exit sync failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
