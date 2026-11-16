from pathlib import Path

import pytest
from rules_fakes import Rig, make_archive

from snorty.rules.__main__ import main
from snorty.rules.config import ALL_PRIVATE
from snorty.snort.models import ConfigCheck


def run(rig: Rig, *argv: str) -> int:
    return main(list(argv), service=rig.service)


def test_update_prints_result_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = Rig(tmp_path)
    assert run(rig, "update") == 0
    out = capsys.readouterr().out
    assert "updated" in out and "6 rules" in out
    assert run(rig, "update") == 0
    assert "up to date" in capsys.readouterr().out


def test_failed_update_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path, make_archive({"emerging-old.rules": "# emptied\n"}))
    assert run(rig, "update") == 1
    assert "much smaller" in capsys.readouterr().out


def test_mute_muted_unmute_roundtrip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path)
    assert run(rig, "mute", "2100498", "--note", "id check") == 0
    capsys.readouterr()
    assert run(rig, "muted") == 0
    assert (
        "2100498" in capsys.readouterr().out
        and "id check" in (rig.etc / "threshold.conf").read_text()
    )
    assert run(rig, "unmute", "2100498") == 0
    assert run(rig, "muted") == 0
    assert "no muted rules" in capsys.readouterr().out


def test_failed_mute_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path)
    rig.validator.results = [ConfigCheck(False, None, ("ERROR: nope",))]
    assert run(rig, "mute", "5") == 1
    assert "ERROR: nope" in capsys.readouterr().out


def test_home_net_show_and_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path)
    assert run(rig, "home-net") == 0
    out = capsys.readouterr().out
    assert "192.168.1.0/24" in out and ALL_PRIVATE in out
    assert run(rig, "home-net", "--set", ALL_PRIVATE) == 0
    assert run(rig, "home-net") == 0
    assert capsys.readouterr().out.count(ALL_PRIVATE) >= 2


def test_status_shows_last_update(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path)
    run(rig, "update")
    capsys.readouterr()
    assert run(rig, "status") == 0
    out = capsys.readouterr().out
    assert "6" in out and "ok" in out


def test_bad_arguments_exit_two(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    for argv in (["mute"], ["mute", "abc"], ["frobnicate"], []):
        with pytest.raises(SystemExit) as exc:
            run(rig, *argv)
        assert exc.value.code == 2
