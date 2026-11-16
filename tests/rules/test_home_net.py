from pathlib import Path

from rules_fakes import Rig

from snorty.rules.config import ALL_PRIVATE
from snorty.snort.models import ConfigCheck


def conf(rig: Rig) -> str:
    return (rig.etc / "snort.conf").read_bytes().decode()


async def test_set_home_net_default_changes_only_that_line(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    original = conf(rig)
    report = await rig.service.set_home_net()
    assert report.ok and report.changed
    assert conf(rig) == original.replace(
        "ipvar HOME_NET [192.168.1.0/24]", f"ipvar HOME_NET {ALL_PRIVATE}"
    )
    assert (rig.etc / "snort.conf.snorty.bak").read_bytes().decode() == original
    (checked,) = rig.validator.seen
    assert f"ipvar HOME_NET {ALL_PRIVATE}" in checked
    assert not list(rig.etc.glob("snorty-*")) and not list(rig.etc.glob("*.tmp"))
    assert rig.sensor.restarts == 1


async def test_explicit_value_and_unchanged_value(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    assert (await rig.service.set_home_net("[10.1.0.0/16]")).changed
    again = await rig.service.set_home_net("[10.1.0.0/16]")
    assert again.ok and not again.changed
    assert len(rig.validator.seen) == 1 and rig.sensor.restarts == 1


async def test_show_current_and_default(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    assert await rig.service.home_net() == ("[192.168.1.0/24]", ALL_PRIVATE)


async def test_missing_line_is_an_error_and_changes_nothing(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    (rig.etc / "snort.conf").write_bytes(b"# no home net here\r\n")
    before = conf(rig)
    report = await rig.service.set_home_net()
    assert not report.ok and "not found" in report.detail
    assert conf(rig) == before and not (rig.etc / "snort.conf.snorty.bak").exists()


async def test_validation_failure_leaves_conf_untouched(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    before = conf(rig)
    rig.validator.results = [ConfigCheck(False, None, ("ERROR: bad ipvar",))]
    report = await rig.service.set_home_net("[bogus")
    assert not report.ok and "bad ipvar" in report.detail
    assert conf(rig) == before and rig.sensor.restarts == 0
    assert not list(rig.etc.glob("snorty-*"))
