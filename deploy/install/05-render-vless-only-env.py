"""Make new subscriptions VLESS-only while retaining legacy VPN files in backups."""

from __future__ import annotations

import argparse
import grp
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("protocol_env_error=root_required")
    if not args.source.is_file() or args.source.is_symlink():
        raise SystemExit("protocol_env_error=source_invalid")
    lines = args.source.read_text(encoding="utf-8").splitlines()
    updates = {
        "KENAI_SUBSCRIPTION_PROTOCOLS": "vless",
        "KENAI_BACKUP_PROTOCOLS": "wireguard,amneziawg,vless",
    }
    for name, value in updates.items():
        matches = [index for index, line in enumerate(lines) if line.startswith(f"{name}=")]
        if len(matches) > 1:
            raise SystemExit(f"protocol_env_error=duplicate_{name.lower()}")
        if matches:
            lines[matches[0]] = f"{name}={value}"
        else:
            lines.append(f"{name}={value}")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(args.output, 0, grp.getgrnam("kenai-vpn").gr_gid)
        os.chmod(args.output, 0o640)
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print("vless_only_environment_created=yes")
    print("secret_values_printed=0")


if __name__ == "__main__":
    main()
