import pytest

from snorty.rules.blocks import (
    END,
    START,
    MutedRule,
    apply_block,
    get_home_net,
    read_block,
    rewrite_include,
    rewrite_rule_path,
    set_home_net,
)

BASE = "# threshold\r\n# more\r\n"


def test_render_and_read_roundtrip() -> None:
    text = apply_block(BASE, [MutedRule(30, "b rule"), MutedRule(7)])
    assert text == (
        f"{BASE}{START}\r\nsuppress gen_id 1, sig_id 7\r\n"
        f"# 30: b rule\r\nsuppress gen_id 1, sig_id 30\r\n{END}\r\n"
    )
    assert read_block(text) == [MutedRule(7), MutedRule(30, "b rule")]


def test_no_suppress_line_has_a_trailing_comment() -> None:
    """Snort rejects `suppress ... # note` ('Invalid integer input'), found in a real run."""
    text = apply_block("", [MutedRule(5, "has a\nnewline  and   spaces")])
    for line in text.splitlines():
        if line.startswith("suppress"):
            assert "#" not in line
    assert read_block(text) == [MutedRule(5, "has a newline and spaces")]


def test_no_block_reads_empty() -> None:
    assert read_block(BASE) == []


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_appending_keeps_existing_text_byte_identical(eol: str) -> None:
    original = f"first{eol}# keep me   {eol}{eol}tail line, no newline"
    text = apply_block(original, [MutedRule(1)])
    assert text.startswith(original)
    replaced = apply_block(text, [MutedRule(2)])
    assert replaced.startswith(original)
    assert read_block(replaced) == [MutedRule(2)]
    assert replaced.count(START) == 1


def test_block_in_the_middle_keeps_both_sides() -> None:
    top, bottom = "a\nb\n", "c\nd\n"
    text = f"{top}{START}\nsuppress gen_id 1, sig_id 5\n{END}\n{bottom}"
    out = apply_block(text, [MutedRule(5), MutedRule(6)])
    assert out.startswith(top) and out.endswith(bottom)
    assert read_block(out) == [MutedRule(5), MutedRule(6)]


def test_empty_entries_removes_the_block_only() -> None:
    text = f"a\n{START}\nsuppress gen_id 1, sig_id 5\n{END}\nc\n"
    assert apply_block(text, []) == "a\nc\n"
    assert apply_block("a\nc\n", []) == "a\nc\n"  # nothing to remove


def test_apply_is_idempotent_and_dedupes() -> None:
    once = apply_block(BASE, [MutedRule(3), MutedRule(3, "later")])
    assert read_block(once) == [MutedRule(3, "later")]
    assert apply_block(once, read_block(once)) == once


def test_unterminated_or_stray_markers_are_errors() -> None:
    with pytest.raises(ValueError):
        read_block(f"{START}\nsuppress gen_id 1, sig_id 1\n")
    with pytest.raises(ValueError):
        read_block(f"{END}\n")


def test_unknown_line_inside_block_is_an_error() -> None:
    with pytest.raises(ValueError):
        read_block(f"{START}\nhand written\n{END}\n")


def test_bad_sid_is_rejected() -> None:
    with pytest.raises(ValueError):
        MutedRule(0)


CONF = (
    "# ipvar HOME_NET commented\r\n"
    "ipvar HOME_NET [192.168.1.0/24]\r\n"
    "ipvar EXTERNAL_NET any\r\n"
    "var RULE_PATH C:\\Snort\\rules\r\n"
    "include threshold.conf\r\n"
    "include $RULE_PATH/local.rules\r\n"
)


def changed_lines(a: str, b: str) -> list[tuple[str, str]]:
    return [(x, y) for x, y in zip(a.split("\r\n"), b.split("\r\n"), strict=True) if x != y]


def test_set_home_net_changes_only_that_line() -> None:
    out = set_home_net(CONF, "[10.0.0.0/8]")
    assert changed_lines(CONF, out) == [
        ("ipvar HOME_NET [192.168.1.0/24]", "ipvar HOME_NET [10.0.0.0/8]")
    ]


def test_set_home_net_missing_line_is_an_error() -> None:
    with pytest.raises(ValueError):
        set_home_net("# ipvar HOME_NET any\n", "any")


def test_rewrite_rule_path_changes_only_that_line() -> None:
    out = rewrite_rule_path(CONF, r"C:\tmp\stage")
    assert changed_lines(CONF, out) == [
        ("var RULE_PATH C:\\Snort\\rules", "var RULE_PATH C:\\tmp\\stage")
    ]


def test_rewrite_include_changes_only_that_include() -> None:
    out = rewrite_include(CONF, "threshold.conf", r"C:\tmp\t.conf")
    assert changed_lines(CONF, out) == [("include threshold.conf", "include C:\\tmp\\t.conf")]


def test_rewrite_missing_line_is_an_error() -> None:
    with pytest.raises(ValueError):
        rewrite_rule_path("nothing here\n", "x")
    with pytest.raises(ValueError):
        rewrite_include("nothing here\n", "threshold.conf", "x")


def test_get_home_net_reads_current_value() -> None:
    assert get_home_net(CONF) == "[192.168.1.0/24]"
    with pytest.raises(ValueError):
        get_home_net("# ipvar HOME_NET any\n")
