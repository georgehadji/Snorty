"""DumpcapRecorder with a fake runner, and the capture argv as data."""

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from snorty.packets import CAPTURE_MAX_KB, Failed, Recorded
from snorty.wireshark import DumpcapRecorder
from snorty.wireshark.commands import capture_command
from snorty.wireshark.runner import Output, ToolError

EXE = Path("C:/Program Files/Wireshark/dumpcap.exe")
DEVICE = r"\Device\NPF_{BED98EAD-7F85-47BD-A28D-BF65D85072EE}"


class FakeRun:
    def __init__(self, out: Output | Exception, write: bytes | None = b"x" * 24) -> None:
        self.out, self.write = out, write
        self.calls: list[tuple[list[str], float, int]] = []

    async def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_bytes: int,
        env: Mapping[str, str] | None = None,
    ) -> Output:
        self.calls.append((list(argv), timeout, max_bytes))
        if self.write is not None:
            Path(argv[argv.index("-w") + 1]).write_bytes(self.write)
        if isinstance(self.out, Exception):
            raise self.out
        return self.out


def ok(code: int = 0, err: str = "") -> Output:
    return Output(code, b"", err, False)


def test_the_capture_argv_is_a_fixed_list_with_both_stop_rules(tmp_path: Path) -> None:
    argv = capture_command(EXE, DEVICE, 10, CAPTURE_MAX_KB, tmp_path / "c.tmp")
    assert argv == [
        str(EXE), "-i", DEVICE, "-q", "-P",
        "-a", "duration:10", "-a", f"filesize:{CAPTURE_MAX_KB}", "-w", str(tmp_path / "c.tmp"),
    ]  # fmt: skip


async def test_a_good_capture_reports_the_size_and_allows_a_grace_period(tmp_path: Path) -> None:
    run = FakeRun(ok(), write=b"x" * 500)
    result = await DumpcapRecorder(EXE, run=run).record(DEVICE, 10, tmp_path / "c.tmp")
    assert result == Recorded(500)
    argv, timeout, _ = run.calls[0]
    assert "duration:10" in argv and 10 < timeout <= 60


@pytest.mark.parametrize(
    "device",
    ["-w", "", "Ethernet", r"\Device\NPF_{x}", r"\Device\NPF_{BED98EAD}; calc", "1", r"\\.\pipe\x"],
)
async def test_only_adapter_names_snort_lists_are_accepted(device: str, tmp_path: Path) -> None:
    run = FakeRun(ok())
    result = await DumpcapRecorder(EXE, run=run).record(device, 10, tmp_path / "c.tmp")
    assert isinstance(result, Failed) and run.calls == []


async def test_the_loopback_adapter_name_is_accepted(tmp_path: Path) -> None:
    run = FakeRun(ok())
    result = await DumpcapRecorder(EXE, run=run).record(r"\Device\NPF_Loopback", 5, tmp_path / "c")
    assert isinstance(result, Recorded)


async def test_a_failing_tool_gives_its_last_message(tmp_path: Path) -> None:
    run = FakeRun(ok(1, "dumpcap: starting\ndumpcap: The capture session could not be initiated\n"))
    result = await DumpcapRecorder(EXE, run=run).record(DEVICE, 10, tmp_path / "c.tmp")
    assert isinstance(result, Failed) and "could not be initiated" in result.message


async def test_a_tool_that_cannot_start_or_hangs_is_a_failure(tmp_path: Path) -> None:
    run = FakeRun(ToolError("dumpcap took longer than 30 s"))
    result = await DumpcapRecorder(EXE, run=run).record(DEVICE, 10, tmp_path / "c.tmp")
    assert result == Failed("dumpcap took longer than 30 s")


async def test_no_file_after_a_clean_exit_is_a_failure(tmp_path: Path) -> None:
    run = FakeRun(ok(), write=None)
    result = await DumpcapRecorder(EXE, run=run).record(DEVICE, 10, tmp_path / "c.tmp")
    assert isinstance(result, Failed)
