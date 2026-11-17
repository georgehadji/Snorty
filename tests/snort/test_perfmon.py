from collections.abc import Sequence
from pathlib import Path

from snorty.snort import Interface, RunResult, SnortPaths, enable_perfmon
from snorty.snort.perfmon import MARK, DropReader, drop_column, newest_drop_pct, with_perfmon

CSV = Path(r"C:\Snort\log\perfmon.csv")
HEAD = "################ Perfmon start: pid=1 ####\n#time,pkt_drop_percent,wire_mbits\n"


def test_the_line_is_added_once_and_the_rest_is_kept() -> None:
    once = with_perfmon("a\r\nb", CSV)
    assert once.startswith("a\r\nb\r\n") and MARK in once and "\n" not in once.replace("\r\n", "")
    assert once.count("preprocessor perfmonitor") == 1
    assert with_perfmon(once, CSV) == once


def test_a_moved_log_folder_rewrites_our_line_only() -> None:
    once = with_perfmon("x\n", CSV)
    moved = with_perfmon(once, Path(r"D:\log\perfmon.csv"))
    assert moved.count("preprocessor perfmonitor") == 1 and r"D:\log" in moved
    assert moved.startswith("x\n")


def test_the_column_comes_from_the_header_and_the_last_row_wins() -> None:
    text = HEAD + "1,0.5,3\n2,1.25,4\n"
    col = drop_column(text)
    assert col == 1 and newest_drop_pct(text, col) == 1.25
    assert drop_column("no header") is None
    assert newest_drop_pct(HEAD, 1) is None


def test_a_half_written_or_odd_row_is_skipped() -> None:
    assert newest_drop_pct(HEAD + "1,2.5,3\n2,x,4\n3", 1) == 2.5


def test_reader_follows_the_file_and_survives_it_missing(tmp_path: Path) -> None:
    f = tmp_path / "perfmon.csv"
    read = DropReader(f)
    assert read() is None
    f.write_text(HEAD + "1,0.5,3\n")
    assert read() == 0.5
    f.write_text(HEAD + "1,0.5,3\n2,7.0,4\n")
    assert read() == 7.0
    f.unlink()
    assert read() == 7.0  # unreadable: keep what was known


async def _enable(tmp_path: Path, result: RunResult) -> tuple[Path | None, Path, list[list[str]]]:
    conf = tmp_path / "snort.conf"
    conf.write_bytes(b"var X 1\r\n")
    paths = SnortPaths(exe=tmp_path / "snort.exe", conf=conf, log_dir=tmp_path / "log")
    calls: list[list[str]] = []

    async def runner(argv: Sequence[str], *, timeout: float) -> RunResult:
        calls.append(list(argv))
        return result

    iface = Interface(1, "00", "10.0.0.2", r"\Device\NPF_{X}", "nic")
    return await enable_perfmon(paths, iface, runner), conf, calls


async def test_the_line_is_added_checked_and_stale_figures_removed(tmp_path: Path) -> None:
    (tmp_path / "log").mkdir()
    (tmp_path / "log" / "perfmon.csv").write_text("old")
    ok = RunResult(0, "", "Snort successfully validated the configuration!")
    csv, conf, calls = await _enable(tmp_path, ok)
    assert csv == tmp_path / "log" / "perfmon.csv" and not csv.exists()
    assert MARK in conf.read_text() and len(calls) == 1 and "-T" in calls[0]
    assert (tmp_path / "snort.conf.snorty-perfmon.bak").read_bytes() == b"var X 1\r\n"


async def test_a_config_snort_refuses_is_put_back(tmp_path: Path) -> None:
    bad = RunResult(1, "", "ERROR: snort.conf(9) Unknown preprocessor: perfmonitor")
    csv, conf, _ = await _enable(tmp_path, bad)
    assert csv is None and conf.read_bytes() == b"var X 1\r\n"


async def test_a_config_that_already_has_the_line_is_not_checked_again(tmp_path: Path) -> None:
    ok = RunResult(0, "", "Snort successfully validated the configuration!")
    await _enable(tmp_path, ok)
    paths = SnortPaths(conf=tmp_path / "snort.conf", log_dir=tmp_path / "log")
    called: list[int] = []

    async def runner(argv: Sequence[str], *, timeout: float) -> RunResult:
        called.append(1)
        return ok

    iface = Interface(1, "00", None, "d", "nic")
    assert await enable_perfmon(paths, iface, runner) is not None and called == []
