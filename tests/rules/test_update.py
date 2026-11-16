from pathlib import Path

from rules_fakes import NOW, URL, Rig, rule

from snorty.rules.state import RulesState, load_state, save_state
from snorty.sensor.states import State


async def test_good_update_swaps_the_ruleset(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    before = rig.snapshot()

    report = await rig.service.update()

    assert report.outcome == "updated"
    assert report.rule_count == 6  # 3 in emerging-old + 2 in emerging-a + 1 in local
    assert report.skipped == 2  # README.txt and the hostile local.rules
    # new rules live, user files untouched
    assert (rig.rules / "emerging-old.rules").read_text() == rule(1) + rule(2) + rule(5)
    assert (rig.rules / "emerging-a.rules").read_text() == rule(10) + rule(11)
    for name in ("local.rules", "white_list.rules"):
        assert (rig.rules / name).read_bytes() == before[str(Path("rules") / name)]
    # old set kept as the memento
    assert (rig.root / "rules.prev" / "emerging-old.rules").read_text() == (
        rule(1) + rule(2) + rule(3) + rule(4)
    )
    # nothing left behind
    assert sorted(p.name for p in rig.root.iterdir()) == [
        "etc",
        "rules",
        "rules-state.json",
        "rules.prev",
    ]
    assert not list(rig.etc.glob("snorty-*"))
    # validated against a conf that pointed at the staging dir, with the rest unchanged
    (checked,) = rig.validator.seen
    assert f"var RULE_PATH {rig.root / 'rules.new'}" in checked
    assert "ipvar HOME_NET [192.168.1.0/24]" in checked
    assert rig.sensor.restarts == 1
    # state and event
    state = load_state(rig.config.state_path)
    assert state.last_md5 == report.md5 and state.rule_count == 6
    assert state.updated_at == NOW.isoformat() and state.result == "ok"
    (event,) = rig.events()
    assert event.ok and event.rule_count == 6


async def test_same_md5_is_up_to_date_unless_forced(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    first = await rig.service.update()
    rig.downloader.calls.clear()
    rig.events()

    again = await rig.service.update()
    assert again.outcome == "up_to_date" and again.md5 == first.md5
    assert rig.downloader.calls == [URL + ".md5"]  # the tarball is not fetched
    assert rig.sensor.restarts == 1 and rig.events() == []

    forced = await rig.service.update(force=True)
    assert forced.outcome == "updated" and rig.sensor.restarts == 2


async def test_stopped_sensor_stays_stopped(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.sensor = type(rig.sensor)(State.STOPPED)
    rig.service._sensor = rig.sensor
    report = await rig.service.update()
    assert report.outcome == "updated"
    assert rig.sensor.restarts == 0 and rig.sensor.state is State.STOPPED


async def test_old_state_with_other_md5_does_not_block(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    save_state(rig.config.state_path, RulesState(last_md5="f" * 32))
    assert (await rig.service.update()).outcome == "updated"
