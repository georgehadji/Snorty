import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from snorty.snort.commands import tasklist_command
from snorty.snort.models import RunResult, SnortError, SnortPaths
from snorty.snort.runner import SubprocessRunner
from snorty.snort.service import is_snort_running, list_interfaces, start_live, stop_live


class FakeRunner:
    def __init__(self, result: RunResult | SnortError) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        self.calls.append(list(argv))
        if isinstance(self.result, SnortError):
            raise self.result
        return self.result


def test_tasklist_command() -> None:
    assert tasklist_command(123) == ["tasklist", "/FI", "PID eq 123", "/FO", "CSV", "/NH"]


async def test_snort_image_is_running() -> None:
    row = '"snort.exe","4242","Console","1","512,000 K"\n'
    runner = FakeRunner(RunResult(0, row, ""))
    assert await is_snort_running(4242, runner) is True
    assert runner.calls == [tasklist_command(4242)]


async def test_image_name_match_ignores_case() -> None:
    assert await is_snort_running(7, FakeRunner(RunResult(0, '"SNORT.EXE","7","c","1","1 K"', "")))


async def test_other_image_is_not_snort() -> None:
    row = '"python.exe","4242","Console","1","30,000 K"\n'
    assert await is_snort_running(4242, FakeRunner(RunResult(0, row, ""))) is False


async def test_pid_column_must_match() -> None:
    row = '"snort.exe","1111","Console","1","1 K"\n'
    assert await is_snort_running(4242, FakeRunner(RunResult(0, row, ""))) is False


async def test_no_task_message_means_not_running() -> None:
    msg = "INFO: No tasks are running which match the specified criteria.\n"
    assert await is_snort_running(1, FakeRunner(RunResult(0, msg, ""))) is False


async def test_runner_error_means_not_running() -> None:
    assert await is_snort_running(1, FakeRunner(SnortError("cannot start tasklist"))) is False


@pytest.mark.snort
async def test_real_this_process_is_not_snort() -> None:
    assert await is_snort_running(os.getpid(), SubprocessRunner()) is False


@pytest.mark.snort
async def test_real_started_snort_is_running(tmp_path: Path) -> None:
    runner = SubprocessRunner()
    base = SnortPaths()
    ifaces = await list_interfaces(base, runner)
    loopback = next(i for i in ifaces if i.device.endswith("NPF_Loopback"))
    proc = await start_live(SnortPaths(log_dir=tmp_path), loopback)
    try:
        assert await is_snort_running(proc.pid, runner) is True
    finally:
        await stop_live(proc)
    await asyncio.sleep(0.5)
    assert await is_snort_running(proc.pid, runner) is False
