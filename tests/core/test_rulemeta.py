from snorty.core.rulemeta import Attack, Tag, attack_of, rule_metadata
from snorty.rules.info import RuleInfo

ET_RULE = (
    'alert http any any -> any any (msg:"ET EXPLOIT metadata: not this"; content:"x"; '
    "metadata: affected_product Apache, attack_target Server, created_at 2024_01_01, "
    "mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, "
    "mitre_technique_name Exploit_Public_Facing_Application, mitre_technique_id T1059.001, "
    "mitre_technique_name PowerShell; sid:2050001; rev:3;)"
)


def test_metadata_keeps_every_value_of_a_repeated_key_in_order() -> None:
    meta = rule_metadata(ET_RULE)
    assert meta["mitre_technique_id"] == ("T1190", "T1059.001")
    assert meta["affected_product"] == ("Apache",)
    assert "not" not in meta  # the word inside msg is not an option


def test_rules_without_or_with_a_broken_metadata_option_give_nothing() -> None:
    assert rule_metadata('alert ip any any -> any any (msg:"x"; sid:1;)') == {}
    assert rule_metadata("alert ip any any -> any any (metadata: lonely, ; sid:1;)") == {}
    assert attack_of({}) is None


def test_attack_pairs_ids_with_names_and_links_to_mitre() -> None:
    a = attack_of(rule_metadata(ET_RULE))
    assert a == Attack(
        (Tag("TA0001", "Initial Access"),),
        (Tag("T1190", "Exploit Public Facing Application"), Tag("T1059.001", "PowerShell")),
    )
    assert a.tactics[0].url == "https://attack.mitre.org/tactics/TA0001/"
    assert a.techniques[1].url == "https://attack.mitre.org/techniques/T1059/001/"


def test_an_id_of_the_wrong_shape_never_becomes_a_link() -> None:
    meta = {"mitre_technique_id": ("T1190/../x", "javascript:1"), "mitre_tactic_id": ("TA1",)}
    assert attack_of(meta) is None


def test_rule_info_reads_once_per_sid_and_rev() -> None:
    calls: list[int] = []

    def find(sid: int) -> str:
        calls.append(sid)
        return ET_RULE

    info = RuleInfo(find)
    assert info.attack(2050001, 3) == info.attack(2050001, 3) is not None
    assert calls == [2050001]
    info.attack(2050001, 4)  # a new rev after a rules update is read again
    assert calls == [2050001, 2050001]
    assert RuleInfo(lambda _: None).attack(1, 1) is None
