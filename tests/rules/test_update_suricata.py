from pathlib import Path

from rules_fakes import Rig, make_archive, rule

from snorty.snort.models import ConfigCheck

YAML = (
    "default-rule-path: C:\\old\r\n"
    "rule-files:\r\n"
    " - emerging-a.rules\r\n"
    " - emerging-retired.rules\r\n"
    "outputs:\r\n"
)


def archive() -> bytes:
    return make_archive({"rules/emerging-a.rules": rule(10) + rule(11) + rule(12)})


def suricata_rig(tmp_path: Path) -> Rig:
    rig = Rig(tmp_path, archive(), engine="suricata", min_ratio=0.1)
    (rig.etc / "snort.conf").write_bytes(YAML.encode())
    return rig


def refusal(rig: Rig, line: int) -> ConfigCheck:
    bad = rig.root / "rules.new" / "emerging-a.rules"
    err = f'E: detect: error parsing signature "alert x" from file {bad} at line {line}'
    return ConfigCheck(False, None, (err,))


async def test_unloadable_rule_is_switched_off_and_the_check_repeated(tmp_path: Path) -> None:
    rig = suricata_rig(tmp_path)
    rig.validator.results = [refusal(rig, 2)]

    report = await rig.service.update()

    assert report.outcome == "updated"
    assert len(rig.validator.seen) == 2
    lines = (rig.rules / "emerging-a.rules").read_text().splitlines()
    assert lines[1].startswith("#") and not lines[0].startswith("#")
    assert "1 switched off" in report.detail
    assert report.rule_count == 2 + 4 + 1  # emerging-a minus one, plus the untouched old files


async def test_rule_files_the_ruleset_no_longer_has_are_dropped_from_the_config(
    tmp_path: Path,
) -> None:
    rig = suricata_rig(tmp_path)

    await rig.service.update()

    live = (rig.etc / "snort.conf").read_text()
    assert " - emerging-a.rules" in live
    assert "emerging-retired.rules" not in live
    (checked,) = rig.validator.seen
    assert "emerging-retired.rules" not in checked  # the staged copy was checked without it


async def test_a_refusal_that_names_no_rule_fails_the_update(tmp_path: Path) -> None:
    rig = suricata_rig(tmp_path)
    rig.validator.results = [ConfigCheck(False, None, ("E: runmodes: output module failed",))]
    before = rig.snapshot()

    report = await rig.service.update()

    assert report.outcome == "failed" and "output module failed" in report.detail
    assert rig.snapshot() == before


async def test_a_rule_outside_the_staging_dir_is_never_touched(tmp_path: Path) -> None:
    rig = suricata_rig(tmp_path)
    elsewhere = tmp_path / "other.rules"
    elsewhere.write_text(rule(7))
    err = f'E: detect: error parsing signature "x" from file {elsewhere} at line 1'
    rig.validator.results = [ConfigCheck(False, None, (err,))]

    report = await rig.service.update()

    assert report.outcome == "failed"
    assert elsewhere.read_text() == rule(7)
