import pytest

from snorty.lab.lint import MAX_BYTES, MAX_RULES, lint

RULE = 'alert tcp any any -> any 80 (msg:"hello world"; content:"abc"; sid:{sid}; rev:1;)'


def rule(sid: int = 9000001) -> str:
    return RULE.format(sid=sid)


def test_valid_rules_with_comments_and_blank_lines() -> None:
    text = "\n".join(
        [
            "# my rules",
            "",
            rule(9000001),
            "   # indented comment",
            'log udp any any -> any any (msg:"u"; sid:9000002;)',
            "pass ip any any -> any any (sid:9000003;)",
            "",
        ]
    )
    result = lint(text)
    assert result.ok and result.problems == ()
    assert [(r.line, r.sid, r.msg) for r in result.rules] == [
        (3, 9000001, "hello world"),
        (5, 9000002, "u"),
        (6, 9000003, ""),
    ]


def test_crlf_gives_the_same_line_numbers() -> None:
    result = lint(f"# c\r\n{rule(1)}\r\n{rule(2)}\r\n")
    assert result.ok and [r.line for r in result.rules] == [2, 3]


def test_a_rule_continued_with_backslash_is_one_rule_at_its_first_line() -> None:
    text = 'alert tcp any any -> any 80 (msg:"x"; \\\n content:"abc"; \\\n sid:9000009;)\n'
    result = lint(text)
    assert result.ok and [(r.line, r.sid) for r in result.rules] == [(1, 9000009)]


@pytest.mark.parametrize(
    "line",
    [
        "include /etc/passwd",
        "include $RULE_PATH/other.rules",
        "var HOME_NET any",
        "config disable_decode_alerts",
        "preprocessor stream5_global: max_tcp 1",
        'drop tcp any any -> any 80 (msg:"d"; sid:9000010;)',
        'reject tcp any any -> any 80 (msg:"r"; sid:9000011;)',
        "this is just text",
        "ALERT tcp any any -> any any (sid:9000012;)",
    ],
)
def test_anything_but_alert_log_pass_rules_is_refused_with_its_line(line: str) -> None:
    result = lint(f"{rule(1)}\n{line}\n")
    assert not result.ok
    assert [p.line for p in result.problems] == [2]
    assert "not allowed" in result.problems[0].message


def test_a_rule_without_sid_is_refused() -> None:
    result = lint('alert tcp any any -> any 80 (msg:"no sid";)\n')
    assert [(p.line, "sid" in p.message) for p in result.problems] == [(1, True)]


def test_duplicate_sid_points_at_both_lines() -> None:
    result = lint(f"{rule(5)}\n{rule(5)}\n")
    assert [p.line for p in result.problems] == [2]
    assert "line 1" in result.problems[0].message


@pytest.mark.parametrize("bad", ["\x00", "\x07", "\x1b", "a\rb"])
def test_control_characters_are_refused(bad: str) -> None:
    result = lint(f"{rule(1)}\n# note {bad} here\n")
    assert [p.line for p in result.problems] == [2]
    assert "control character" in result.problems[0].message


def test_tabs_are_fine() -> None:
    assert lint("alert\ttcp any any -> any any (\tsid:9000013;)\n").ok


def test_text_over_the_size_cap_is_refused_without_scanning() -> None:
    result = lint("#" * (MAX_BYTES + 1))
    assert [(p.line, "64 KB" in p.message) for p in result.problems] == [(0, True)]
    assert result.rules == ()


def test_a_10_mb_string_is_refused_quickly() -> None:
    assert not lint("x" * 10_000_000).ok


def test_multibyte_text_counts_bytes_not_characters() -> None:
    assert not lint("#" + "é" * (MAX_BYTES // 2)).ok  # over 64 KB as UTF-8


def test_more_than_200_rules_is_refused() -> None:
    text = "\n".join(rule(9100000 + i) for i in range(MAX_RULES + 1))
    result = lint(text)
    assert [(p.line, "200" in p.message) for p in result.problems] == [(0, True)]


def test_exactly_200_rules_is_fine() -> None:
    text = "\n".join(rule(9100000 + i) for i in range(MAX_RULES))
    assert lint(text).ok


def test_empty_text_is_ok_with_no_rules() -> None:
    result = lint("")
    assert result.ok and result.rules == ()
