from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from kenai_vpn_admin.helper.command_runner import (
    CommandExecutionError,
    CommandRejectedError,
    SafeCommandRunner,
)


def test_runner_uses_shell_false_and_returns_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    executable = Path("C:/test-bin/wg.exe").resolve()
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = SafeCommandRunner({executable})

    result = runner.run((str(executable), "show", "wg0"))

    assert result.stdout == "ok\n"
    assert captured["kwargs"]["shell"] is False  # type: ignore[index]


def test_runner_rejects_non_allowlisted_executable() -> None:
    runner = SafeCommandRunner({Path("C:/test-bin/wg.exe").resolve()})

    with pytest.raises(CommandRejectedError):
        runner.run((str(Path("C:/test-bin/sh.exe").resolve()), "-c", "id"))


@pytest.mark.parametrize("argument", ["line\nnext", "line\rnext", "null\x00byte"])
def test_runner_rejects_control_characters(argument: str) -> None:
    executable = Path("C:/test-bin/wg.exe").resolve()
    runner = SafeCommandRunner({executable})

    with pytest.raises(CommandRejectedError):
        runner.run((str(executable), argument))


def test_runner_does_not_expose_stderr_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    executable = Path("C:/test-bin/wg.exe").resolve()
    secret = "private-key-must-not-leak"

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args[0], 1, stdout="", stderr=secret)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = SafeCommandRunner({executable})

    with pytest.raises(CommandExecutionError) as error:
        runner.run((str(executable), "set", "wg0"), input_text=secret)

    assert secret not in str(error.value)
