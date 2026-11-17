import pytest

from snorty.lab.conf import build_lab_conf

SAMPLE = (
    "# conf\n"
    "var RULE_PATH C:/Snort/rules\n"
    "var PREPROC_RULE_PATH C:/Snort/preproc_rules\n"
    "include classification.config\n"
    "include reference.config\n"
    "include $RULE_PATH/local.rules\n"
    "include $RULE_PATH/emerging-dns.rules\n"
    "  INCLUDE   $RULE_PATH/emerging-web.rules  \n"
    "# include $RULE_PATH/commented.rules\n"
    "# include $PREPROC_RULE_PATH/decoder.rules\n"
    "include $PREPROC_RULE_PATH/preprocessor.rules\n"
    "preprocessor stream5_global: max_tcp 1\n"
    "include threshold.conf\n"
)
LAB = "C:/Temp/snorty-lab-ab12/lab.rules"


def test_removes_exactly_the_rules_preproc_rules_and_threshold_includes() -> None:
    out = build_lab_conf(SAMPLE, LAB)
    assert "emerging" not in out.replace("commented", "")
    for gone in (
        "local.rules",
        "emerging-dns",
        "emerging-web",
        "preprocessor.rules",
        "threshold.conf",
    ):
        assert gone not in out
    # kept: other includes, vars, commented-out includes, preprocessors
    for kept in (
        "include classification.config",
        "include reference.config",
        "var RULE_PATH",
        "# include $RULE_PATH/commented.rules",
        "# include $PREPROC_RULE_PATH/decoder.rules",
        "preprocessor stream5_global: max_tcp 1",
    ):
        assert kept in out


def test_appends_one_lab_include_as_the_last_line() -> None:
    out = build_lab_conf(SAMPLE, LAB)
    assert out.endswith(f"include {LAB}\n")
    assert out.count(f"include {LAB}") == 1


def test_every_other_line_is_kept_in_order() -> None:
    out = build_lab_conf(SAMPLE, LAB).splitlines()
    dropped = {
        "include $RULE_PATH/local.rules",
        "include $RULE_PATH/emerging-dns.rules",
        "  INCLUDE   $RULE_PATH/emerging-web.rules  ",
        "include $PREPROC_RULE_PATH/preprocessor.rules",
        "include threshold.conf",
    }
    assert out[:-1] == [ln for ln in SAMPLE.splitlines() if ln not in dropped]


def test_crlf_is_kept_and_used_for_the_added_line() -> None:
    crlf = SAMPLE.replace("\n", "\r\n")
    out = build_lab_conf(crlf, LAB)
    assert "\n" not in out.replace("\r\n", "")
    assert out.endswith(f"include {LAB}\r\n")


def test_a_conf_without_a_final_newline_still_gets_the_include_on_its_own_line() -> None:
    out = build_lab_conf("include classification.config", LAB)
    assert out == f"include classification.config\ninclude {LAB}\n"


def test_a_perfmonitor_line_is_dropped_so_the_lab_never_writes_live_statistics() -> None:
    live = (
        "var X 1\n# snorty: perfmonitor (drop statistics)\n"
        "preprocessor perfmonitor: time 60 file C:\\Snort\\log\\perfmon.csv pktcnt 1000\n"
        "  PREPROCESSOR  PerfMonitor: time 5\npreprocessor perfmonitor_x: kept\n"
    )
    out = build_lab_conf(live, LAB)
    assert out == (
        "var X 1\n# snorty: perfmonitor (drop statistics)\n"
        f"preprocessor perfmonitor_x: kept\ninclude {LAB}\n"
    )


def test_an_empty_conf_gets_just_the_include() -> None:
    assert build_lab_conf("", LAB) == f"include {LAB}\n"


@pytest.mark.parametrize("bad", ["C:/My Temp/lab.rules", "a\tb", "x\ny"])
def test_a_path_with_whitespace_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="whitespace"):
        build_lab_conf(SAMPLE, bad)
