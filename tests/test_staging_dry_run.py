from pathlib import Path

import pytest

from kenai_vpn_admin.helper.command_runner import CommandRejectedError, CommandResult
from kenai_vpn_admin.helper.dry_run import StagingCommandExecutor


class ValidatorStub:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...], *, input_text: str | None = None) -> CommandResult:
        self.commands.append(arguments)
        return CommandResult("validated")


def build_executor() -> StagingCommandExecutor:
    executor = StagingCommandExecutor(
        wg_quick_binary=Path("C:/bin/wg-quick.exe"),
        xray_binary=Path("C:/bin/xray.exe"),
        wg_binary=Path("C:/bin/wg.exe"),
        systemctl_binary=Path("C:/bin/systemctl.exe"),
    )
    executor.validator = ValidatorStub()  # type: ignore[assignment]
    return executor


def test_staging_executor_runs_only_native_validators() -> None:
    executor = build_executor()

    wg_result = executor.run(("C:/bin/wg-quick.exe", "strip", "C:/staging/wg0.conf"))
    xray_result = executor.run(
        ("C:/bin/xray.exe", "run", "-test", "-config", "C:/staging/config.json")
    )

    assert wg_result.stdout == "validated"
    assert xray_result.stdout == "validated"
    assert executor.simulated_mutations == []


def test_staging_executor_simulates_runtime_mutations() -> None:
    executor = build_executor()

    executor.run(("C:/bin/wg.exe", "syncconf", "wg0", "C:/staging/stripped.conf"))
    executor.run(("C:/bin/systemctl.exe", "reload-or-restart", "xray.service"))

    assert len(executor.simulated_mutations) == 2


def test_staging_executor_rejects_every_other_command() -> None:
    executor = build_executor()

    with pytest.raises(CommandRejectedError):
        executor.run(("C:/bin/systemctl.exe", "restart", "ssh.service"))

    with pytest.raises(CommandRejectedError):
        executor.run(("C:/bin/wg.exe", "set", "wg0", "private-key", "/tmp/key"))
