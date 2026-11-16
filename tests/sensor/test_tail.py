from pathlib import Path

from snorty.sensor.tail import TailState, read_new_lines


def test_missing_file_changes_nothing(tmp_path: Path) -> None:
    state = TailState(offset=5, pending=b"ab")
    result = read_new_lines(tmp_path / "nope.ids", state)
    assert result.lines == [] and result.state == state and result.rotated is False


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
