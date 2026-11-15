from collections.abc import Sequence
from pathlib import Path

import pytest

from snorty.snort.models import Interface, RunResult, SnortError, SnortPaths
from snorty.snort.runner import SubprocessRunner
from snorty.snort.service import check_config, list_interfaces

FIX = Path(__file__).parent.parent / "fixtures"
PATHS = SnortPaths()
IFACE = Interface(4, "aa", "1.2.3.4", "dev", "desc")


class FakeRunner:
    def __init__(self, result: RunResult | SnortError) -> None:
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        self.calls.append((list(argv), timeout))
        if isinstance(self.result, SnortError):
            raise self.result
        return self.result


async def test_list_interfaces_runs_dash_w_and_parses() -> None:
    runner = FakeRunner(RunResult(0, (FIX / "snort_W.txt").read_text(), "banner on stderr"))
    ifaces = await list_interfaces(PATHS, runner)
    assert runner.calls[0][0] == [str(PATHS.exe), "-W"]
    assert len(ifaces) == 10


async def test_check_config_good_output() -> None:
    # Snort writes everything to stderr for -T; stdout is empty.
    runner = FakeRunner(RunResult(0, "", (FIX / "snort_T_ok.txt").read_text()))
    check = await check_config(PATHS, IFACE, runner)
    assert check.ok is True
    assert check.rule_count == 52442
    assert check.errors == ()
    assert runner.calls[0][0][:5] == [str(PATHS.exe), "-T", "-i", "4", "-c"]


async def test_check_config_bad_output_reports_error_lines() -> None:
    runner = FakeRunner(RunResult(255, "", (FIX / "snort_T_bad.txt").read_text()))
    check = await check_config(PATHS, IFACE, runner)
    assert check.ok is False
    assert check.rule_count is None
    assert any("Unknown rule type: badkeyword_xyz" in e for e in check.errors)


async def test_check_config_zero_exit_without_success_marker_is_not_ok() -> None:
    check = await check_config(PATHS, IFACE, FakeRunner(RunResult(0, "", "something odd")))
    assert check.ok is False


async def test_check_config_failure_with_unknown_output_still_explains() -> None:
    check = await check_config(PATHS, IFACE, FakeRunner(RunResult(3, "", "")))
    assert check.ok is False
    assert check.errors == ("snort exited with code 3 and no error text",)


async def test_check_config_converts_runner_error() -> None:
    check = await check_config(PATHS, IFACE, FakeRunner(SnortError("timeout after 5s: snort")))
    assert check == check.__class__(False, None, ("timeout after 5s: snort",))


async def test_conf_override_is_used() -> None:
    runner = FakeRunner(RunResult(0, "", (FIX / "snort_T_ok.txt").read_text()))
    await check_config(PATHS, IFACE, runner, conf=Path("C:/lab/lab.conf"))
    assert runner.calls[0][0][-1] == str(Path("C:/lab/lab.conf"))


@pytest.mark.snort
async def test_real_interfaces_include_loopback() -> None:
    ifaces = await list_interfaces(PATHS, SubprocessRunner())
    assert any(i.device.endswith("NPF_Loopback") for i in ifaces)


@pytest.mark.snort
async def test_real_config_validates() -> None:
    runner = SubprocessRunner()
    ifaces = await list_interfaces(PATHS, runner)
    loopback = next(i for i in ifaces if i.device.endswith("NPF_Loopback"))
    check = await check_config(PATHS, loopback, runner)
    assert check.ok, check.errors
    assert check.rule_count is not None and check.rule_count > 50000
