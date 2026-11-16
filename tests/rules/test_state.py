from pathlib import Path

from snorty.rules.state import RulesState, load_state, save_state


def test_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "rules-state.json"
    state = RulesState("a" * 32, "2026-11-16T04:00:00+00:00", 52442, "ok")
    save_state(path, state)
    assert load_state(path) == state
    assert [p.name for p in tmp_path.iterdir()] == ["rules-state.json"]  # no temp file left


def test_missing_file_gives_empty_state(tmp_path: Path) -> None:
    assert load_state(tmp_path / "nope.json") == RulesState()


def test_corrupt_or_wrong_shape_gives_empty_state(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    for text in ("{not json", "[1, 2]", '{"last_md5": 5}'):
        path.write_text(text)
        assert load_state(path) == RulesState()
