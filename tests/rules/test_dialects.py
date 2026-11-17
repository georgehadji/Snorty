from pathlib import Path

import pytest

from snorty.rules.config import RulesConfig
from snorty.rules.dialects import SnortDialect, SuricataDialect, failed_rule
from snorty.rules.ports import SnortValidator, SuricataValidator, validator_for
from snorty.snort.models import SnortPaths
from snorty.suricata import SuricataPaths

YAML = (
    "%YAML 1.1\r\n---\r\n"
    "vars:\r\n"
    "  address-groups:\r\n"
    '    HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"\r\n'
    '    EXTERNAL_NET: "!$HOME_NET"\r\n'
    "default-rule-path: C:\\old\\rules\r\n"
    "threshold-file: C:\\old\\threshold.config\r\n"
    "outputs:\r\n"
    "  - eve-log:\r\n"
    "      enabled: yes\r\n"
)


def test_suricata_reads_home_net_without_quotes() -> None:
    assert SuricataDialect().get_home_net(YAML) == "[192.168.0.0/16,10.0.0.0/8]"


def test_suricata_sets_only_the_home_net_line_and_keeps_line_endings() -> None:
    out = SuricataDialect().set_home_net(YAML, "[10.1.0.0/16]")
    assert '    HOME_NET: "[10.1.0.0/16]"\r\n' in out
    assert out.replace("[10.1.0.0/16]", "[192.168.0.0/16,10.0.0.0/8]") == YAML


def test_suricata_rewrites_rule_path_and_threshold_file() -> None:
    d = SuricataDialect()
    out = d.rewrite_threshold(d.rewrite_rule_path(YAML, "C:\\new\\rules"), "C:\\new\\t.config")
    assert "default-rule-path: C:\\new\\rules\r\n" in out
    assert "threshold-file: C:\\new\\t.config\r\n" in out
    assert out.count("\r\n") == YAML.count("\r\n")


@pytest.mark.parametrize("call", ["get_home_net", "rewrite_rule_path"])
def test_suricata_missing_line_is_an_error(call: str) -> None:
    method = getattr(SuricataDialect(), call)
    args = ("outputs:\n",) if call == "get_home_net" else ("outputs:\n", "x")
    with pytest.raises(ValueError, match="not found"):
        method(*args)


def test_suricata_adds_a_missing_threshold_file_key() -> None:
    out = SuricataDialect().rewrite_threshold("a: 1\r\nb: 2", "C:\t")
    assert out == "a: 1\r\nb: 2\r\nthreshold-file: C:\t\r\n"


def test_snort_dialect_keeps_the_old_edits() -> None:
    text = "ipvar HOME_NET any\nvar RULE_PATH ../rules\ninclude threshold.conf\n"
    d = SnortDialect()
    assert d.get_home_net(text) == "any"
    assert d.set_home_net(text, "[10.0.0.0/8]").startswith("ipvar HOME_NET [10.0.0.0/8]\n")
    assert "var RULE_PATH C:\\r\n" in d.rewrite_rule_path(text, "C:\\r")
    assert "include C:\\t\n" in d.rewrite_threshold(text, "C:\\t")


def test_config_picks_the_dialect_and_threshold_name_by_engine() -> None:
    snort = RulesConfig()
    assert snort.threshold_conf.name == "threshold.conf"
    paths = SuricataPaths(conf=Path("C:/S/suricata.yaml"))
    suricata = RulesConfig(paths=paths, engine="suricata")
    assert suricata.threshold_conf == Path("C:/S/threshold.config")
    assert isinstance(suricata.dialect, SuricataDialect)


def test_validator_matches_the_paths() -> None:
    assert isinstance(validator_for(SnortPaths()), SnortValidator)
    assert isinstance(validator_for(SuricataPaths()), SuricataValidator)


RULE_FILES = (
    "rule-files:\n - a.rules\n - gone.rules\n # - c.rules\n - b.rules\noutputs:\n - eve-log\n"
)


def test_suricata_drops_only_missing_rule_files() -> None:
    out = SuricataDialect().rewrite_rule_files(RULE_FILES, {"a.rules", "b.rules"})
    assert out == "rule-files:\n - a.rules\n # - c.rules\n - b.rules\noutputs:\n - eve-log\n"


def test_snort_rule_files_are_left_alone() -> None:
    assert SnortDialect().rewrite_rule_files(RULE_FILES, set()) == RULE_FILES


def test_failed_rule_reads_the_file_and_line_from_suricata_output() -> None:
    err = (
        'E: detect: error parsing signature "alert tcp any any -> any any (msg:"x"; '
        'file.magic; sid:1;)" from file C:\\r\\emerging-exploit.rules at line 3999'
    )
    assert failed_rule(["other", err]) == (Path("C:/r/emerging-exploit.rules"), 3999)
    assert failed_rule(["ERROR: snort says no"]) is None
