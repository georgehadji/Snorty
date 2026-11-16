from pathlib import Path

import pytest

from snorty.sensor import tail
from snorty.sensor.tail import TailState, read_new_lines


def test_missing_file_changes_nothing(tmp_path: Path) -> None:
    state = TailState(offset=5, pending=b"ab")
    result = read_new_lines(tmp_path / "nope.ids", state)
    assert result.lines == [] and result.state == state and result.rotated is False


STAMPED = "11/16/26-20:57:52.742055  [**] ping"


def test_identical_lines_with_one_timestamp_are_numbered_apart(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    other = "11/16/26-20:57:52.742055  [**] pong"  # same instant, different text
    later = "11/16/26-20:57:53.000001  [**] ping"
    f.write_text(f"{STAMPED}\n{STAMPED}\n{other}\n{STAMPED}\n{later}\n{later}\n")
    assert read_new_lines(f, TailState()).ties == [0, 1, 0, 2, 0, 1]


def test_the_numbering_carries_across_reads(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_text(f"{STAMPED}\n")
    first = read_new_lines(f, TailState())
    with f.open("a") as fh:
        fh.write(f"{STAMPED}\n")
    second = read_new_lines(f, first.state)
    assert first.ties == [0] and second.ties == [1]  # the repeat is not mistaken for the first


def test_a_rotated_file_starts_the_numbering_again(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_text(f"{STAMPED}\n{STAMPED}\n")
    state = read_new_lines(f, TailState()).state
    f.write_text(f"{STAMPED}\n")  # shorter: rotated
    result = read_new_lines(f, state)
    assert result.rotated and result.ties == [0]


def test_reads_complete_lines_once(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"one\ntwo\n")
    first = read_new_lines(f, TailState())
    assert first.lines == ["one", "two"]
    second = read_new_lines(f, first.state)
    assert second.lines == [] and second.state == first.state


def test_partial_last_line_waits_for_its_newline(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"one\ntw")
    first = read_new_lines(f, TailState())
    assert first.lines == ["one"] and first.state.pending == b"tw"
    with f.open("ab") as fh:
        fh.write(b"o\nthree\n")
    second = read_new_lines(f, first.state)
    assert second.lines == ["two", "three"] and second.state.pending == b""


def test_crlf_and_blank_lines(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"one\r\n\r\ntwo\r\n")
    assert read_new_lines(f, TailState()).lines == ["one", "two"]


def test_invalid_utf8_is_replaced_not_raised(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"a\xffb\n")
    assert read_new_lines(f, TailState()).lines == ["a�b"]


def test_shrunk_file_is_reread_from_start_and_flagged(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"old line one\nold line two\n")
    state = read_new_lines(f, TailState()).state
    f.write_bytes(b"new\n")  # rotated: smaller than our offset
    result = read_new_lines(f, state)
    assert result.rotated is True
    assert result.lines == ["new"]
    assert result.state.offset == 4


def test_rotation_drops_a_stale_partial_line(tmp_path: Path) -> None:
    f = tmp_path / "a.ids"
    f.write_bytes(b"first\npartial-without-newline")
    state = read_new_lines(f, TailState()).state
    assert state.pending != b""
    f.write_bytes(b"x\n")
    assert read_new_lines(f, state).lines == ["x"]


def test_a_large_file_is_read_in_chunks_without_losing_or_splitting_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Memory is bounded by MAX_CHUNK, not by the size of alert.ids."""
    monkeypatch.setattr(tail, "MAX_CHUNK", 64)
    f = tmp_path / "a.ids"
    f.write_bytes(b"".join(f"line {i}\n".encode() for i in range(50)))
    state, got, reads = TailState(), [], 0
    while (result := read_new_lines(f, state)).lines:
        got += result.lines
        state, reads = result.state, reads + 1
    assert got == [f"line {i}" for i in range(50)]
    assert reads > 1
