from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sqlite3
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kenai_vpn_admin.domain.enums import Protocol

MAGIC = b"KENAI-BACKUP-V1\n"
NONCE_BYTES = 12
MAX_PLAINTEXT_BYTES = 256 * 1024 * 1024


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupEntry:
    archive_name: str
    source_path: Path


@dataclass(frozen=True)
class BackupResult:
    path: Path
    sha256: str
    created_at: datetime
    entry_count: int


class BackupService:
    def __init__(self, key_path: Path, backup_directory: Path, *, retention: int = 14) -> None:
        if retention < 1:
            raise ValueError("Backup retention must be positive")
        self.key_path = key_path
        self.backup_directory = backup_directory
        self.retention = retention

    def initialize_key(self) -> None:
        if self.key_path.exists():
            raise BackupError("Backup key already exists")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            self.key_path.unlink(missing_ok=True)
            raise

    def create(self, database_path: Path, entries: tuple[BackupEntry, ...]) -> BackupResult:
        with tempfile.TemporaryDirectory(prefix="kenai-backup-") as directory:
            snapshot = Path(directory) / "database.sqlite"
            self._snapshot_database(database_path, snapshot)
            return self.create_from_snapshot(
                BackupEntry("database/kenai-admin.db", snapshot), entries
            )

    def create_from_snapshot(
        self, database: BackupEntry, entries: tuple[BackupEntry, ...]
    ) -> BackupResult:
        key = self._load_key()
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC)
        filename = timestamp.strftime("kenai-vpn-%Y%m%dT%H%M%SZ.kvbackup")
        target = self.backup_directory / filename
        if target.exists():
            raise BackupError("Backup target already exists")
        payload_entries = (database, *entries)
        plaintext = self._build_archive(payload_entries, timestamp)
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise BackupError("Backup exceeds the maximum supported size")
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
        self._atomic_write(target, MAGIC + nonce + ciphertext)
        self.verify(target)
        self._rotate()
        return BackupResult(
            path=target,
            sha256=self._sha256(target.read_bytes()),
            created_at=timestamp,
            entry_count=len(payload_entries),
        )

    def verify(self, backup_path: Path) -> dict[str, object]:
        plaintext = self._decrypt(backup_path)
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as archive:
            members = archive.getmembers()
            self._validate_members(members)
            manifest_member = archive.getmember("manifest.json")
            manifest_file = archive.extractfile(manifest_member)
            if manifest_file is None:
                raise BackupError("Backup manifest is unavailable")
            raw_manifest = json.loads(manifest_file.read())
            if not isinstance(raw_manifest, dict):
                raise BackupError("Backup manifest is invalid")
            manifest = cast(dict[str, object], raw_manifest)
            expected = manifest.get("entries")
            if not isinstance(expected, dict):
                raise BackupError("Backup manifest is invalid")
            actual_names = {member.name for member in members if member.name != "manifest.json"}
            if actual_names != set(expected):
                raise BackupError("Backup manifest does not match archive members")
            for member in members:
                if member.name == "manifest.json":
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise BackupError("Backup entry is unavailable")
                content = stream.read()
                metadata = expected[member.name]
                if not isinstance(metadata, dict):
                    raise BackupError("Backup entry metadata is invalid")
                if metadata.get("sha256") != self._sha256(content):
                    raise BackupError("Backup entry digest mismatch")
                if metadata.get("size") != len(content):
                    raise BackupError("Backup entry size mismatch")
            return manifest

    def extract_to_staging(self, backup_path: Path, destination: Path) -> Path:
        if destination.exists():
            raise BackupError("Restore staging destination already exists")
        plaintext = self._decrypt(backup_path)
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as archive:
            members = archive.getmembers()
            self._validate_members(members)
            self.verify(backup_path)
            destination.mkdir(parents=True, mode=0o700)
            try:
                for member in members:
                    target = destination / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise BackupError("Backup entry is unavailable")
                    target.write_bytes(stream.read())
                    target.chmod(0o600)
            except Exception:
                raise BackupError("Restore staging extraction failed") from None
        return destination

    def _build_archive(self, entries: tuple[BackupEntry, ...], created_at: datetime) -> bytes:
        names: set[str] = set()
        contents: dict[str, bytes] = {}
        manifest_entries: dict[str, dict[str, object]] = {}
        for entry in entries:
            self._validate_archive_name(entry.archive_name)
            if entry.archive_name in names:
                raise BackupError("Duplicate backup entry")
            names.add(entry.archive_name)
            if not entry.source_path.is_file() or entry.source_path.is_symlink():
                raise BackupError("Backup source must be a regular file")
            content = entry.source_path.read_bytes()
            contents[entry.archive_name] = content
            manifest_entries[entry.archive_name] = {
                "sha256": self._sha256(content),
                "size": len(content),
                "mode": stat.S_IMODE(entry.source_path.stat().st_mode),
            }
        manifest = {
            "format": 1,
            "created_at": created_at.isoformat(),
            "entries": manifest_entries,
        }
        contents["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:") as archive:
            for name in sorted(contents):
                content = contents[name]
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o600
                info.uid = 0
                info.gid = 0
                info.mtime = int(created_at.timestamp())
                archive.addfile(info, io.BytesIO(content))
        return buffer.getvalue()

    def _decrypt(self, backup_path: Path) -> bytes:
        if not backup_path.is_file() or backup_path.is_symlink():
            raise BackupError("Backup must be a regular file")
        encoded = backup_path.read_bytes()
        if not encoded.startswith(MAGIC) or len(encoded) <= len(MAGIC) + NONCE_BYTES:
            raise BackupError("Backup format is invalid")
        nonce_start = len(MAGIC)
        nonce = encoded[nonce_start : nonce_start + NONCE_BYTES]
        ciphertext = encoded[nonce_start + NONCE_BYTES :]
        try:
            return AESGCM(self._load_key()).decrypt(nonce, ciphertext, MAGIC)
        except Exception as exc:
            raise BackupError("Backup authentication failed") from exc

    def _load_key(self) -> bytes:
        if not self.key_path.is_file() or self.key_path.is_symlink():
            raise BackupError("Backup key is unavailable")
        try:
            key = base64.urlsafe_b64decode(self.key_path.read_bytes().strip())
        except Exception as exc:
            raise BackupError("Backup key is invalid") from exc
        if len(key) != 32:
            raise BackupError("Backup key is invalid")
        return key

    @staticmethod
    def _snapshot_database(source: Path, destination: Path) -> None:
        if not source.is_file() or source.is_symlink():
            raise BackupError("Database source must be a regular file")
        source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        destination_connection = sqlite3.connect(destination)
        try:
            source_connection.backup(destination_connection)
            if destination_connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise BackupError("Database snapshot integrity check failed")
        finally:
            destination_connection.close()
            source_connection.close()

    def _rotate(self) -> None:
        backups = sorted(self.backup_directory.glob("kenai-vpn-*.kvbackup"), reverse=True)
        for obsolete in backups[self.retention :]:
            if obsolete.is_file() and not obsolete.is_symlink():
                obsolete.unlink()

    @staticmethod
    def _atomic_write(target: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _validate_members(members: list[tarfile.TarInfo]) -> None:
        names: set[str] = set()
        for member in members:
            BackupService._validate_archive_name(member.name)
            if member.name in names or not member.isfile():
                raise BackupError("Backup archive contains an invalid member")
            names.add(member.name)
        if "manifest.json" not in names:
            raise BackupError("Backup manifest is missing")

    @staticmethod
    def _validate_archive_name(name: str) -> None:
        value = PurePosixPath(name)
        if not name or value.is_absolute() or ".." in value.parts or "\\" in name:
            raise BackupError("Unsafe backup archive path")

    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()


def production_backup_entries(
    protocols: set[Protocol] | None = None,
) -> tuple[BackupEntry, ...]:
    enabled = set(Protocol) if protocols is None else protocols
    entries = [
        BackupEntry("config/xray/config.json", Path("/usr/local/etc/xray/config.json")),
        BackupEntry("state/helper/xray.json", Path("/var/lib/kenai-vpn-helper/xray.json")),
        BackupEntry("secrets/web.env", Path("/etc/kenai-vpn/web.env")),
        BackupEntry("secrets/helper.env", Path("/etc/kenai-vpn/helper.env")),
    ]
    if Protocol.WIREGUARD in enabled:
        entries.extend(
            (
                BackupEntry("config/wireguard/wg0.conf", Path("/etc/wireguard/wg0.conf")),
                BackupEntry(
                    "state/helper/wireguard.json",
                    Path("/var/lib/kenai-vpn-helper/wireguard.json"),
                ),
            )
        )
    if Protocol.AMNEZIAWG in enabled:
        entries.extend(
            (
                BackupEntry("config/amneziawg/awg0.conf", Path("/etc/amneziawg/awg0.conf")),
                BackupEntry(
                    "state/helper/amneziawg.json",
                    Path("/var/lib/kenai-vpn-helper/amneziawg.json"),
                ),
            )
        )
    return tuple(entries)
