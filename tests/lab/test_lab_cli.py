import json
import struct
from pathlib import Path

import pytest
from lab_fakes import FakeSnort, alert_line, make_paths, rule

from snorty.lab.__main__ import main
from snorty.snort.models import SnortPaths


@pytest.fixture
def paths(tmp_path: Path) -> SnortPaths:
    return make_paths(tmp_path / "snort")


@pytest.fixture
def pcap(tmp_path: Path) -> Path:
    path = tmp_path / "t.pcap"
    path.write_bytes(b"pcap")
    return path


def write_rules(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "my.rules"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_check_ok_runs_lint_and_t_only(
    paths: SnortPaths, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeSnort()
    code = main(["check", str(write_rules(tmp_path, rule(9000001)))], paths=paths, runner=fake)
    assert code == 0 and "ok: 1 rule" in capsys.readouterr().out
    assert fake.flags() == ["W", "T"]


def test_check_reports_the_line_of_a_bad_line(
    paths: SnortPaths, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = write_rules(tmp_path, rule(9000001), "include /etc/passwd")
    assert main(["check", str(rules)], paths=paths, runner=FakeSnort()) == 1
    assert "rule line 2:" in capsys.readouterr().out


def test_run_prints_the_hit_table_and_matches(
    paths: SnortPaths, tmp_path: Path, pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeSnort(alert_text=alert_line(9000001, "rule a"))
    rules = write_rules(tmp_path, rule(9000001, "rule a"), rule(9000002, "rule b"))
    assert main(["run", str(rules), str(pcap)], paths=paths, runner=fake) == 0
    out = capsys.readouterr().out
    assert "Rule hits" in out and "Matches (1)" in out
    assert "9000001" in out and "rule a" in out and "9000002" in out
    assert "10.0.0.1:4444 -> 10.0.0.2:80" in out


def test_run_json(
    paths: SnortPaths, tmp_path: Path, pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeSnort(alert_text=alert_line(9000001, "rule a"))
    rules = write_rules(tmp_path, rule(9000001, "rule a"))
    assert main(["run", str(rules), str(pcap), "--json"], paths=paths, runner=fake) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["error"] is None and data["problems"] == []
    assert data["hits"] == [{"sid": 9000001, "msg": "rule a", "line": 1, "count": 1}]
    assert data["matches"][0]["sid"] == 9000001 and data["matches"][0]["src_port"] == 4444


def test_run_with_rule_problems_exits_one_and_never_runs_the_pcap(
    paths: SnortPaths, tmp_path: Path, pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeSnort(check_output="ERROR: x/lab.rules(1) Unknown ruleoption.\n", check_code=1)
    rules = write_rules(tmp_path, rule(9000001))
    assert main(["run", str(rules), str(pcap)], paths=paths, runner=fake) == 1
    assert "rule line 1: Unknown ruleoption." in capsys.readouterr().out
    assert fake.flags() == ["W", "T"]


def test_a_missing_pcap_exits_one_with_the_error_on_stderr(
    paths: SnortPaths, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = write_rules(tmp_path, rule(9000001))
    code = main(["run", str(rules), str(tmp_path / "nope.pcap")], paths=paths, runner=FakeSnort())
    assert code == 1 and "pcap not found" in capsys.readouterr().err


def test_a_missing_rules_file_exits_one(
    paths: SnortPaths, tmp_path: Path, pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["run", str(tmp_path / "none.rules"), str(pcap)], paths=paths, runner=FakeSnort())
    assert code == 1 and "could not read" in capsys.readouterr().err


def test_a_huge_rules_file_is_refused_not_read_whole(
    paths: SnortPaths, tmp_path: Path, pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    big = tmp_path / "big.rules"
    big.write_text("#" * 200_000)
    assert main(["check", str(big)], paths=paths, runner=FakeSnort()) == 1
    assert "64 KB" in capsys.readouterr().out


def test_make_pcap_writes_a_readable_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "x.pcap"
    code = main(["make-pcap", "--out", str(out), "--payload", "uid=0(root)", "--count", "2"])
    assert code == 0 and "wrote 2 packet(s)" in capsys.readouterr().out
    blob = out.read_bytes()
    assert struct.unpack("<I", blob[:4])[0] == 0xA1B2C3D4
    assert blob.count(b"uid=0(root)") == 2


def test_make_pcap_handshake_adds_three_packets(tmp_path: Path) -> None:
    out = tmp_path / "h.pcap"
    assert main(["make-pcap", "--out", str(out), "--payload", "x", "--handshake"]) == 0
    assert out.read_bytes().count(bytes([8, 0, 0x45])) == 4  # 3 handshake + 1 data frame


def test_make_pcap_bad_arguments_exit_two(tmp_path: Path) -> None:
    out = tmp_path / "bad.pcap"
    for extra in (["--src", "999.1.1.1"], ["--dport", "99999"], ["--count", "0"]):
        with pytest.raises(SystemExit) as exc:
            main(["make-pcap", "--out", str(out), "--payload", "x", *extra])
        assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["make-pcap", "--out", str(out), "--payload", "x", "--proto", "udp", "--handshake"])
    assert exc.value.code == 2
    assert not out.exists()


def test_no_command_exits_two() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_non_ascii_rule_text_does_not_crash_the_console(
    paths: SnortPaths, tmp_path: Path, pcap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io

    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(raw, encoding="cp1252", errors="strict"))
    fake = FakeSnort(alert_text=alert_line(9000001, "café → x"))
    rules = write_rules(tmp_path, rule(9000001, "café → x"))
    assert main(["run", str(rules), str(pcap)], paths=paths, runner=fake) == 0
