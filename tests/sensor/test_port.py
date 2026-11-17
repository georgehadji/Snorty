from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from snorty.sensor import port as port_module
from snorty.sensor.port import SnortAdapter
from snorty.snort.models import Interface, RunResult, SnortPaths, StopResult

FIX = Path(__file__).parent.parent / "fixtures"
IFACE = Interface(4, "aa", "1.2.3.4", "dev", "desc")


class FakeRunner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        self.calls.append(list(argv))
        return RunResult(0, self.stdout, "")


async def test_list_interfaces_goes_through_the_runner() -> None:
    runner = FakeRunner((FIX / "snort_W.txt").read_text())
    adapter = SnortAdapter(SnortPaths(), runner)
    assert len(await adapter.list_interfaces()) == 10
    assert runner.calls[0][-1] == "-W"


async def test_is_snort_running_goes_through_the_runner() -> None:
    adapter = SnortAdapter(SnortPaths(), FakeRunner('"snort.exe","9","c","1","1 K"'))
    assert await adapter.is_snort_running(9) is True


async def test_start_and_stop_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    sentinel = object()

    async def fake_start(paths: SnortPaths, iface: Interface, **kw: Any) -> object:
        seen["start"] = (paths, iface)
        return sentinel

    async def fake_stop(proc: object, *, timeout: float) -> StopResult:
        seen["stop"] = (proc, timeout)
        return StopResult("clean", 0)

    async def no_perfmon(*_: Any) -> None:  # never edit the real snort.conf from a test
        seen["perfmon"] = True

    monkeypatch.setattr(port_module, "enable_perfmon", no_perfmon)
    monkeypatch.setattr(port_module, "start_live", fake_start)
    monkeypatch.setattr(port_module, "stop_live", fake_stop)
    paths = SnortPaths()
    adapter = SnortAdapter(paths, FakeRunner(""))
    assert await adapter.start(IFACE) is sentinel
    assert seen["start"] == (paths, IFACE) and seen["perfmon"]
    result = await adapter.stop(sentinel, 7.5)  # type: ignore[arg-type]
    assert result.how == "clean" and seen["stop"] == (sentinel, 7.5)


def test_local_ip_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(port_module, "find_local_ip", lambda: "10.1.2.3")
    assert SnortAdapter(SnortPaths(), FakeRunner("")).local_ip() == "10.1.2.3"
