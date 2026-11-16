import asyncio
from pathlib import Path

from rules_fakes import Rig

from snorty.rules.blocks import END, START, MutedRule
from snorty.sensor.states import State
from snorty.snort.models import ConfigCheck

ORIGINAL = b"# thresholds\r\n"


def threshold(rig: Rig) -> bytes:
    return (rig.etc / "threshold.conf").read_bytes()


async def test_mute_adds_block_validates_backs_up_and_restarts(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    report = await rig.service.mute(2100498, "id check returned root")

    assert report.ok and report.changed
    text = threshold(rig).decode()
    assert text.startswith(ORIGINAL.decode())
    assert (
        f"{START}\r\n# 2100498: id check returned root\r\nsuppress gen_id 1, sig_id 2100498\r\n"
        in text
    )
    assert text.endswith(f"{END}\r\n")
    assert (rig.etc / "threshold.conf.snorty.bak").read_bytes() == ORIGINAL
    # validated through a temp conf: only the threshold include line pointed elsewhere
    (checked,) = rig.validator.seen
    assert "include threshold.conf" not in checked
    assert "snorty-candidate" in checked and "ipvar HOME_NET [192.168.1.0/24]" in checked
    assert not list(rig.etc.glob("snorty-*")) and not list(rig.etc.glob("*.tmp"))
    assert rig.sensor.restarts == 1
    assert [m.sid for m in await rig.service.muted()] == [2100498]


async def test_mute_is_idempotent(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.service.mute(7, "x")
    again = await rig.service.mute(7, "x")
    assert again.ok and not again.changed
    assert len(rig.validator.seen) == 1 and rig.sensor.restarts == 1


async def test_remute_with_new_note_updates_it(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.service.mute(7, "old")
    assert (await rig.service.mute(7, "new")).changed
    assert await rig.service.muted() == [MutedRule(7, "new")]


async def test_unmute_restores_the_original_bytes(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.service.mute(7)
    await rig.service.mute(9)
    assert (await rig.service.unmute(7)).changed
    assert await rig.service.muted() == [MutedRule(9)]
    assert (await rig.service.unmute(9)).changed
    assert threshold(rig) == ORIGINAL
    missing = await rig.service.unmute(9)
    assert missing.ok and not missing.changed


async def test_lf_files_stay_lf(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    (rig.etc / "threshold.conf").write_bytes(b"# lf only\n")
    await rig.service.mute(5)
    assert b"\r" not in threshold(rig)


async def test_validation_failure_leaves_file_untouched(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.validator.results = [ConfigCheck(False, None, ("ERROR: bad suppress",))]
    report = await rig.service.mute(5)
    assert not report.ok and "ERROR: bad suppress" in report.detail
    assert threshold(rig) == ORIGINAL
    assert not (rig.etc / "threshold.conf.snorty.bak").exists()
    assert not list(rig.etc.glob("snorty-*")) and rig.sensor.restarts == 0


async def test_bad_sid_is_a_failed_report(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    report = await rig.service.mute(0)
    assert not report.ok and "positive" in report.detail
    assert threshold(rig) == ORIGINAL


async def test_no_restart_when_asked_or_when_sensor_is_stopped(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.service.mute(1, restart=False)
    assert rig.sensor.restarts == 0
    rig.sensor._state = State.STOPPED
    await rig.service.mute(2)
    assert rig.sensor.restarts == 0


async def test_sensor_not_coming_back_is_reported(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.sensor.results = [State.FAILED]
    report = await rig.service.mute(3)
    assert not report.ok and report.changed and "did not come back" in report.detail


async def test_existing_text_outside_block_survives_a_second_mute(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    await rig.service.mute(1)
    # user adds a line after our block
    (rig.etc / "threshold.conf").write_bytes(threshold(rig) + b"# user line\r\n")
    await rig.service.mute(2)
    text = threshold(rig).decode()
    assert text.endswith("# user line\r\n") and text.startswith("# thresholds\r\n")
    assert [m.sid for m in await rig.service.muted()] == [1, 2]


async def test_mute_waits_for_a_running_update(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    gate = asyncio.Event()
    real = rig.validator.check

    async def slow(conf: Path) -> ConfigCheck:
        await gate.wait()
        return await real(conf)

    rig.validator.check = slow  # type: ignore[method-assign]
    update = asyncio.create_task(rig.service.update())
    await asyncio.sleep(0.05)
    mute = asyncio.create_task(rig.service.mute(4))
    await asyncio.sleep(0.05)
    assert len(rig.validator.seen) == 0 and threshold(rig) == ORIGINAL  # mute has not started
    gate.set()
    assert (await update).outcome == "updated"
    assert (await mute).changed
    assert [m.sid for m in await rig.service.muted()] == [4]
