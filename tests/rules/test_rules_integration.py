"""Real `snort -T` over a temp copy of C:\\Snort. Needs Snort; run with `pytest -m snort`."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rules_fakes import URL, FakeDownloader, FakeSensor, make_archive, rule

from snorty.core.bus import EventBus
from snorty.rules.config import RulesConfig
from snorty.rules.ports import SnortValidator
from snorty.rules.service import RulesService
from snorty.sensor.states import State
from snorty.snort.models import SnortPaths

pytestmark = pytest.mark.snort

REAL = Path(r"C:\Snort")


def fingerprint() -> dict[str, tuple[int, int]]:
    """Size and mtime of every real rules/etc file, to prove the tests never touch them."""
    return {
        str(p): (p.stat().st_size, p.stat().st_mtime_ns)
        for d in ("rules", "etc")
        for p in sorted((REAL / d).glob("*"))
        if p.is_file()
    }


class Lab:
    """A temp copy of the installed Snort's rules and etc, checked by the real snort.exe."""

    def __init__(self, root: Path) -> None:
        self.root = root
        for d in ("rules", "etc"):
            shutil.copytree(REAL / d, root / d)
        (root / "log").mkdir()
        self.paths = SnortPaths(
            exe=REAL / "bin" / "snort.exe", conf=root / "etc" / "snort.conf", log_dir=root / "log"
        )
        self.config = RulesConfig(paths=self.paths, rules_dir=root / "rules", url=URL)

    def service(self, archive: bytes) -> RulesService:
        return RulesService(
            self.config,
            FakeDownloader(archive),
            SnortValidator(self.paths),
            FakeSensor(State.STOPPED),
            EventBus(),
            clock=lambda: datetime.now(UTC),
        )

    def rules_file(self, name: str) -> Path:
        return self.root / "rules" / name


async def test_real_snort_accepts_a_good_set_and_rejects_a_broken_one(tmp_path: Path) -> None:
    before = fingerprint()
    lab = Lab(tmp_path)

    original = lab.rules_file("emerging-dos.rules").read_text(encoding="utf-8", errors="replace")
    good = make_archive({"rules/emerging-dos.rules": original})
    report = await lab.service(good).update()
    assert report.outcome == "updated", report.detail
    assert report.rule_count is not None and report.rule_count > 1000

    broken_rule = rule(9000002).replace("sid:", "no_such_option:1; sid:")
    broken = make_archive({"rules/emerging-dos.rules": rule(9000001) + broken_rule})
    live_before = lab.rules_file("emerging-dos.rules").read_bytes()
    report = await lab.service(broken).update(force=True)
    assert report.outcome == "failed" and report.detail.startswith("validate:"), report.detail
    assert lab.rules_file("emerging-dos.rules").read_bytes() == live_before
    assert not (tmp_path / "rules.new").exists()

    assert fingerprint() == before  # the real C:\Snort was never touched
