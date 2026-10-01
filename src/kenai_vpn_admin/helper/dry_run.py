from __future__ import annotations

from pathlib import Path

from kenai_vpn_admin.helper.command_runner import (
    CommandRejectedError,
    CommandResult,
    SafeCommandRunner,
)


class StagingCommandExecutor:
    """Run native validators while simulating every runtime-changing command."""

    def __init__(
        self,
        *,
        wg_quick_binary: Path,
        xray_binary: Path,
        wg_binary: Path,
        systemctl_binary: Path,
    ) -> None:
        self.wg_quick_binary = wg_quick_binary.resolve()
        self.xray_binary = xray_binary.resolve()
        self.wg_binary = wg_binary.resolve()
        self.systemctl_binary = systemctl_binary.resolve()
        self.validator = SafeCommandRunner({self.wg_quick_binary, self.xray_binary})
        self.simulated_mutations: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...], *, input_text: str | None = None) -> CommandResult:
        if not arguments:
            raise CommandRejectedError("Empty dry-run command")
        executable = Path(arguments[0]).resolve()
        if executable == self.wg_quick_binary and arguments[1:2] == ("strip",):
            return self.validator.run(arguments, input_text=input_text)
        if executable == self.xray_binary and arguments[1:3] == ("run", "-test"):
            return self.validator.run(arguments, input_text=input_text)
        if executable == self.wg_binary and arguments[1:2] == ("syncconf",):
            self.simulated_mutations.append(arguments)
            return CommandResult("")
        if executable == self.systemctl_binary and arguments[1:] == (
            "reload-or-restart",
            "xray.service",
        ):
            self.simulated_mutations.append(arguments)
            return CommandResult("")
        raise CommandRejectedError("Command is outside the staging dry-run allowlist")
