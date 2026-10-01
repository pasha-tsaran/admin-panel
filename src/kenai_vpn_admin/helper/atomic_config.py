from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import cast


class ConfigurationApplyError(RuntimeError):
    pass


class AtomicConfigEditor:
    """Validate a candidate, replace atomically, and restore on activation failure."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def apply(
        self,
        content: str,
        *,
        validate: Callable[[Path], None],
        activate: Callable[[], None],
    ) -> None:
        if not self.path.is_file() or self.path.is_symlink():
            raise ConfigurationApplyError("Managed configuration is not a regular file")
        original_stat = self.path.stat()
        descriptor, candidate_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.candidate.", dir=self.path.parent
        )
        candidate = Path(candidate_name)
        backup = self.path.with_name(f".{self.path.name}.rollback")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(candidate, stat.S_IMODE(original_stat.st_mode))
            if os.name == "posix":
                chown = cast(
                    Callable[[object, int, int], None],
                    getattr(os, "chown"),  # noqa: B009
                )
                chown(candidate, original_stat.st_uid, original_stat.st_gid)
            validate(candidate)
            shutil.copy2(self.path, backup)
            os.replace(candidate, self.path)
            try:
                activate()
            except Exception as exc:
                os.replace(backup, self.path)
                with suppress(Exception):
                    activate()
                raise ConfigurationApplyError("Activation failed; configuration restored") from exc
            backup.unlink(missing_ok=True)
        finally:
            candidate.unlink(missing_ok=True)
