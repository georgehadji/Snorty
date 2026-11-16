import asyncio
from pathlib import Path

import pytest
from rules_fakes import FlakyRename, Rig, make_archive, rule

from snorty.rules.ports import DownloadError
from snorty.sensor.states import State
from snorty.snort.models import ConfigCheck


def hostile_only() -> bytes:
    return make_archive({"../escape.rules": rule(9), "rules/README.txt": "x"})


def shrinking() -> bytes:
    return make_archive({"emerging-old.rules": "# emptied\n"})


async def assert_clean_failure(rig: Rig, before: dict[str, bytes], detail: str) -> None:
    report = await rig.service.update()
    assert report.outcome == "failed"
    assert detail in report.detail, report.detail
    assert rig.snapshot() == before  # rules, conf, state: byte-identical, nothing left over
    assert not (rig.root / "rules.new").exists() and not (rig.root / "rules.swap").exists()
    assert not list(rig.etc.glob("snorty-*"))
    (event,) = rig.events()
    assert event.ok is False and detail in event.detail


async def test_download_error(tmp_path: Path) -> None:
    rig = Rig(tmp_path, DownloadError("network down"))
    await assert_clean_failure(rig, rig.snapshot(), "network down")
    assert rig.sensor.restarts == 0


async def test_tarball_download_error(tmp_path: Path) -> None:
    rig = Rig(tmp_path, DownloadError("reset by peer"), md5_text="a" * 32)
    await assert_clean_failure(rig, rig.snapshot(), "reset by peer")


async def test_md5_mismatch(tmp_path: Path) -> None:
    rig = Rig(tmp_path, md5_text="0" * 32)
    await assert_clean_failure(rig, rig.snapshot(), "md5 mismatch")


async def test_oversize_download(tmp_path: Path) -> None:
    rig = Rig(tmp_path, max_download=10)
    await assert_clean_failure(rig, rig.snapshot(), "too big")


async def test_not_an_archive(tmp_path: Path) -> None:
    rig = Rig(tmp_path, b"<html>captive portal</html>")
    await assert_clean_failure(rig, rig.snapshot(), "not a readable rules archive")


async def test_hostile_archive_writes_nothing_and_fails(tmp_path: Path) -> None:
    rig = Rig(tmp_path, hostile_only())
    await assert_clean_failure(rig, rig.snapshot(), "no rules files")
    assert not (tmp_path / "escape.rules").exists()
    assert not (rig.root.parent / "escape.rules").exists()


async def test_sanity_ratio(tmp_path: Path) -> None:
    rig = Rig(tmp_path, shrinking())
    await assert_clean_failure(rig, rig.snapshot(), "much smaller")


async def test_validation_failure_reports_first_errors(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.validator.results = [ConfigCheck(False, None, ("FATAL ERROR: bad rule at line 3",))]
    await assert_clean_failure(rig, rig.snapshot(), "FATAL ERROR: bad rule at line 3")
    assert rig.sensor.restarts == 0


@pytest.mark.parametrize("fail_on", [{1}, {2}, {3}])
async def test_each_rename_failure_is_undone(tmp_path: Path, fail_on: set[int]) -> None:
    rig = Rig(tmp_path, rename=FlakyRename(fail_on))
    await assert_clean_failure(rig, rig.snapshot(), "refused")
    assert rig.sensor.restarts == 0


async def test_failed_health_gate_rolls_back_and_restarts_again(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    before = rig.snapshot()
    rig.sensor.results = [State.FAILED, State.RUNNING]
    report = await rig.service.update()
    assert report.outcome == "failed" and "did not come back" in report.detail
    assert rig.snapshot() == before
    assert rig.sensor.restarts == 2 and rig.sensor.state is State.RUNNING
    (event,) = rig.events()
    assert event.ok is False


async def test_hanging_restart_times_out_and_rolls_back(tmp_path: Path) -> None:
    rig = Rig(tmp_path, health_timeout=0.05)
    before = rig.snapshot()
    rig.sensor.results = [None, State.RUNNING]
    report = await rig.service.update()
    assert report.outcome == "failed" and "did not come back" in report.detail
    assert rig.snapshot() == before and rig.sensor.restarts == 2


async def test_rollback_that_also_fails_says_where_the_old_rules_are(tmp_path: Path) -> None:
    # calls 1-3 are the swap, 4 is the rollback's first rename
    rig = Rig(tmp_path, rename=FlakyRename({4}))
    rig.sensor.results = [State.FAILED]
    report = await rig.service.update()
    assert report.outcome == "failed" and "rules.prev" in report.detail


async def test_failed_update_does_not_advance_state(tmp_path: Path) -> None:
    rig = Rig(tmp_path, md5_text="0" * 32)
    await rig.service.update()
    assert not rig.config.state_path.exists()


async def test_concurrent_updates_run_one_after_the_other(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    gate = asyncio.Event()
    real_check = rig.validator.check

    async def slow_check(conf: Path) -> ConfigCheck:
        await gate.wait()
        return await real_check(conf)

    rig.validator.check = slow_check  # type: ignore[method-assign]
    first = asyncio.create_task(rig.service.update())
    await asyncio.sleep(0.05)
    second = asyncio.create_task(rig.service.update())
    await asyncio.sleep(0.05)
    assert len(rig.downloader.calls) == 2  # only the first update has downloaded anything
    gate.set()
    assert [(await first).outcome, (await second).outcome] == ["updated", "up_to_date"]
