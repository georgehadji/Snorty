"""packets.logs: which Snort logs can hold an alert's packet, and reading one for a window."""

from pathlib import Path

from snorty.packets.logs import MAX_CANDIDATES, MAX_LOG_BYTES, candidate_logs, read_log
from snorty.packets.pcapfile import Frame, write_pcap

A = Frame(1_000_000_000, 10, b"a" * 10)
B = Frame(9_000_000_000, 10, b"b" * 10)


def touch(folder: Path, *names: str) -> None:
    for name in names:
        (folder / name).write_bytes(write_pcap([A]))


def test_the_newest_log_that_started_before_the_alert_comes_first(tmp_path: Path) -> None:
    touch(tmp_path, "snort.log.100", "snort.log.300", "snort.log.200", "snort.log.900")
    assert [p.name for p in candidate_logs(tmp_path, 350)] == [
        "snort.log.300",
        "snort.log.200",
        "snort.log.100",
    ]


def test_only_a_few_candidates_are_returned(tmp_path: Path) -> None:
    touch(tmp_path, *(f"snort.log.{n}" for n in range(1, 10)))
    assert len(candidate_logs(tmp_path, 100)) == MAX_CANDIDATES


def test_other_files_and_folders_are_ignored(tmp_path: Path) -> None:
    touch(tmp_path, "alert.ids", "snort.log.12.bak", "snort.log.x", "snort.log.", "notes.txt")
    (tmp_path / "snort.log.50").mkdir()
    assert candidate_logs(tmp_path, 1000) == []


def test_a_missing_folder_gives_no_candidates(tmp_path: Path) -> None:
    assert candidate_logs(tmp_path / "gone", 1000) == []


def test_read_log_keeps_only_the_window(tmp_path: Path) -> None:
    path = tmp_path / "snort.log.1"
    path.write_bytes(write_pcap([A, B]))
    log = read_log(path, (B.ts_ns - 5, B.ts_ns + 5))
    assert log is not None and log.frames == (B,) and not log.truncated


def test_unreadable_or_foreign_files_give_none(tmp_path: Path) -> None:
    junk = tmp_path / "snort.log.2"
    junk.write_bytes(b"not a pcap at all" * 5)
    assert read_log(junk, (0, 10**18)) is None
    assert read_log(tmp_path / "snort.log.3", (0, 10**18)) is None


def test_a_log_over_the_size_cap_is_marked_cut(tmp_path: Path) -> None:
    path = tmp_path / "snort.log.4"
    path.write_bytes(write_pcap([A]) + bytes(MAX_LOG_BYTES))
    log = read_log(path, (A.ts_ns, A.ts_ns))  # the zero padding parses as time-zero frames
    assert log is not None and log.truncated and log.frames == (A,)
