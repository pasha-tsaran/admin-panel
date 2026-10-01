from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class CommandRejectedError(ValueError):
    pass


class CommandExecutionError(RuntimeError):
    """A deliberately non-diagnostic exception that cannot expose command output."""


@dataclass(frozen=True)
class CommandResult:
    stdout: str


class SafeCommandRunner:
    """Execute only explicitly allowlisted binaries, never through a shell."""

    def __init__(
        self,
        allowed_executables: set[Path],
        *,
        timeout_seconds: float = 15.0,
    ) -> None:
        if not allowed_executables:
            raise ValueError("At least one executable must be allowlisted")
        self.allowed_executables = frozenset(path.resolve() for path in allowed_executables)
        self.timeout_seconds = timeout_seconds

    def run(self, arguments: tuple[str, ...], *, input_text: str | None = None) -> CommandResult:
        if not arguments:
            raise CommandRejectedError("Empty command")
        executable = Path(arguments[0])
        if not executable.is_absolute() or executable.resolve() not in self.allowed_executables:
            raise CommandRejectedError("Executable is not allowlisted")
        has_control_character = any(
            "\x00" in argument or "\n" in argument or "\r" in argument for argument in arguments
        )
        if has_control_character:
            raise CommandRejectedError("Command arguments contain control characters")
        try:
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                input=input_text,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandExecutionError("Allowlisted command could not be executed") from exc
        if completed.returncode != 0:
            raise CommandExecutionError("Allowlisted command returned a failure status")
        return CommandResult(stdout=completed.stdout)
