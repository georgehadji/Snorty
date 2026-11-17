from pathlib import Path

from snorty.rules.find import find_rule

RULE_A = 'alert tcp any any -> any 80 (msg:"A"; sid:2001; rev:3;)'
RULE_B = 'alert udp any any -> any 53 (msg:"B"; content:"sid:99;"; sid:20010; rev:1;)'


def rules(tmp_path: Path) -> Path:
    (tmp_path / "a.rules").write_text(f"# comment\n{RULE_A}\n", encoding="utf-8")
    (tmp_path / "b.rules").write_text(f"{RULE_B}\n#alert tcp any any -> any 1 (sid:7;)\n")
    return tmp_path


def test_a_rule_is_found_by_its_sid(tmp_path: Path) -> None:
    assert find_rule(rules(tmp_path), 2001) == RULE_A


def test_a_longer_sid_is_not_mistaken_for_a_shorter_one(tmp_path: Path) -> None:
    d = rules(tmp_path)
    assert find_rule(d, 20010) == RULE_B
    assert find_rule(d, 2) is None


def test_a_switched_off_rule_is_found_without_its_hash(tmp_path: Path) -> None:
    assert find_rule(rules(tmp_path), 7) == "alert tcp any any -> any 1 (sid:7;)"


def test_a_missing_folder_or_sid_gives_none(tmp_path: Path) -> None:
    assert find_rule(tmp_path / "nope", 1) is None
    assert find_rule(rules(tmp_path), 424242) is None
