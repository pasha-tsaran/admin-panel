"""Persist only the already-tested ACME and API ingress firewall rules."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("firewall_error=root_required")
    source = Path("/etc/nftables.conf")
    if not source.is_file() or source.is_symlink():
        raise SystemExit("firewall_error=source_invalid")
    original = source.read_text(encoding="utf-8")
    anchor = "        tcp dport 443 accept\n"
    if (
        original.count(anchor) != 1
        or "tcp dport 80 accept" in original
        or "tcp dport 9443 accept" in original
    ):
        raise SystemExit("firewall_error=unexpected_ruleset")
    updated = original.replace(
        anchor,
        anchor
        + '        tcp dport 80 accept comment "kenai-acme-http01"\n'
        + '        tcp dport 9443 accept comment "kenai-api-https"\n',
        1,
    )
    candidate = Path("/etc/.nftables.conf.kenai-api-candidate")
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        checked = subprocess.run(
            ["/usr/sbin/nft", "-c", "-f", str(candidate)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if checked.returncode != 0:
            raise SystemExit("firewall_error=candidate_invalid")

        current = subprocess.run(
            ["/usr/sbin/nft", "-nn", "list", "chain", "inet", "filter", "input"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if "tcp dport 80 accept" not in current or "tcp dport 9443 accept" not in current:
            raise SystemExit("firewall_error=runtime_rules_missing")

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = Path(f"/var/backups/kenai-vpn/pre-public-api-{timestamp}")
        backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        backup = backup_dir / "nftables.conf"
        shutil.copy2(source, backup)
        backup.chmod(0o600)
        metadata = source.stat()
        os.chown(candidate, metadata.st_uid, metadata.st_gid)
        os.chmod(candidate, stat.S_IMODE(metadata.st_mode))
        os.replace(candidate, source)
    finally:
        candidate.unlink(missing_ok=True)
    print("firewall_persisted_ports=80,9443")
    print("firewall_runtime_reloaded=no")
    print(f"firewall_previous_config={backup}")


if __name__ == "__main__":
    main()
