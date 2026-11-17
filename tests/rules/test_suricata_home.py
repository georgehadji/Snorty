from pathlib import Path

import pytest

from snorty.compose import compose
from snorty.dashboard.config import ConfigError, default_engine, load_config
from snorty.rules.suricata_home import prepare_suricata_home
from snorty.sensor.states import State

STOCK = (
    "default-log-dir: C:\\Program Files\\Suricata\\log\n"
    "default-rule-path: C:\\Program Files\\Suricata\\rules\\\n"
    "rule-files:\n"
    " - botcc.rules\n"
    " - decoder-events.rules\n"
    "classification-file: C:\\Program Files\\Suricata\\classification.config\n"
    "reference-config-file: C:\\Program Files\\Suricata\\reference.config\n"
)


def fake_install(root: Path) -> Path:
    install = root / "Suricata"
    (install / "rules").mkdir(parents=True)
    (install / "suricata.yaml").write_text(STOCK)
    (install / "classification.config").write_text("class")
    (install / "reference.config").write_text("ref")
    (install / "rules" / "decoder-events.rules").write_text(
        "alert ip any any -> any any (sid:1;)\n"
    )
    return install


def test_home_is_made_from_the_install_and_points_at_itself(tmp_path: Path) -> None:
    home = tmp_path / "data" / "suricata"
    paths = prepare_suricata_home(fake_install(tmp_path), home)

    assert paths.conf == home / "suricata.yaml" and paths.log_dir == home / "log"
    assert paths.exe == tmp_path / "Suricata" / "suricata.exe"
    text = paths.conf.read_text()
    assert f"default-rule-path: {home / 'rules'}" in text
    assert f"default-log-dir: {home / 'log'}" in text
    assert f"classification-file: {home / 'classification.config'}" in text
    assert f"threshold-file: {home / 'threshold.config'}" in text
    assert "Program Files" not in text
    assert (home / "rules" / "decoder-events.rules").read_text().startswith("alert")
    assert (home / "reference.config").read_text() == "ref"


def test_listed_rule_files_the_install_lacks_get_empty_placeholders(tmp_path: Path) -> None:
    home = tmp_path / "home"
    prepare_suricata_home(fake_install(tmp_path), home)
    assert (home / "rules" / "botcc.rules").read_text() == ""
    assert (home / "rules" / "decoder-events.rules").read_text() != ""


def test_an_existing_home_is_left_alone(tmp_path: Path) -> None:
    home = tmp_path / "home"
    install = fake_install(tmp_path)
    prepare_suricata_home(install, home)
    (home / "suricata.yaml").write_text("mine: true\n")
    (home / "rules" / "extra.rules").write_text("x")

    prepare_suricata_home(install, home)

    assert (home / "suricata.yaml").read_text() == "mine: true\n"
    assert (home / "rules" / "extra.rules").read_text() == "x"


def test_a_changed_install_remakes_the_config_and_keeps_rules_threshold_and_home_net(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    install = fake_install(tmp_path)
    prepare_suricata_home(install, home)
    conf = home / "suricata.yaml"
    conf.write_text(conf.read_text() + 'vars:\n  address-groups:\n    HOME_NET: "[10.0.0.0/8]"\n')
    (home / "rules" / "botcc.rules").write_text("alert ip any any -> any any (sid:2;)\n")
    (home / "threshold.config").write_text("suppress gen_id 1, sig_id 2\n")
    upgraded = STOCK.replace("rule-files:", "new-engine-key: yes\nrule-files:")
    (install / "suricata.yaml").write_text(
        upgraded + 'vars:\n  address-groups:\n    HOME_NET: "[192.168.0.0/16]"\n'
    )
    (install / "rules" / "decoder-events.rules").write_text(
        "alert ip any any -> any any (sid:3;)\n"
    )

    prepare_suricata_home(install, home)

    text = conf.read_text()
    assert "new-engine-key: yes" in text and 'HOME_NET: "[10.0.0.0/8]"' in text
    assert f"default-rule-path: {home / 'rules'}" in text and "Program Files" not in text
    assert "10.0.0.0/8" in (home / "suricata.yaml.before-rebuild").read_text()
    assert "sid:2;" in (home / "rules" / "botcc.rules").read_text()
    assert "sid:3;" in (home / "rules" / "decoder-events.rules").read_text()
    assert (home / "threshold.config").read_text() == "suppress gen_id 1, sig_id 2\n"


def test_a_copy_made_before_the_record_existed_is_remade_once(tmp_path: Path) -> None:
    home = tmp_path / "home"
    install = fake_install(tmp_path)
    prepare_suricata_home(install, home)
    (home / ".snorty-source").unlink()
    (home / "suricata.yaml").write_text("old: copy\n")

    prepare_suricata_home(install, home)
    first = (home / "suricata.yaml").read_text()
    prepare_suricata_home(install, home)

    assert "old: copy" not in first and (home / "suricata.yaml").read_text() == first
    assert (home / "suricata.yaml.before-rebuild").read_text() == "old: copy\n"


FINGERPRINT_BLOCK = (
    "outputs:\n"
    "  - eve-log:\n"
    "      types:\n"
    "        - tls:\n"
    "            extended: yes\n"
    "            # ja4: off\n"
    "        - quic:\n"
    "            # ja4: off\n"
    "app-layer:\n"
    "  protocols:\n"
    "    tls:\n"
    "      enabled: yes\n"
    "      #ja3-fingerprints: auto\n"
    "      #ja4-fingerprints: auto\n"
)


def test_the_copy_turns_on_tls_fingerprints_and_keeps_every_other_line(tmp_path: Path) -> None:
    install = fake_install(tmp_path)
    (install / "suricata.yaml").write_text(STOCK + FINGERPRINT_BLOCK)
    home = tmp_path / "home"
    text = prepare_suricata_home(install, home).conf.read_text()
    assert "            ja4: on\n        - quic:\n            # ja4: off\n" in text
    assert "      ja3-fingerprints: yes\n      ja4-fingerprints: yes\n" in text
    gone = set((STOCK + FINGERPRINT_BLOCK).splitlines()) - set(text.splitlines())
    # besides the paths, only the two key lines left; `# ja4: off` stays, under quic
    assert {line for line in gone if "Program Files" not in line} == {
        "      #ja3-fingerprints: auto",
        "      #ja4-fingerprints: auto",
    }


def test_a_new_recipe_remakes_a_copy_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install = fake_install(tmp_path)
    home = tmp_path / "home"
    prepare_suricata_home(install, home)
    (home / "suricata.yaml").write_text("old: recipe\n")
    monkeypatch.setattr("snorty.rules.suricata_home.RECIPE", 99)
    prepare_suricata_home(install, home)
    assert "old: recipe" not in (home / "suricata.yaml").read_text()
    assert (home / ".snorty-source").read_text().endswith(" 99")


async def test_compose_with_suricata_uses_the_owned_copy_and_eve_json(tmp_path: Path) -> None:
    install = fake_install(tmp_path)
    rt = compose(tmp_path / "data", engine="suricata", suricata_install=install)
    try:
        assert rt.services.sensor.state is State.STOPPED
        assert (tmp_path / "data" / "suricata" / "suricata.yaml").exists()
        assert rt.services.sensor._alert_path == tmp_path / "data" / "suricata" / "log" / "eve.json"
        await rt.start(sensor=False)
        await rt.stop()
    finally:
        rt.services.repo.close()


def test_engine_is_a_setting_with_two_values(tmp_path: Path) -> None:
    assert load_config(tmp_path).engine == "snort"
    assert load_config(tmp_path, {"engine": "suricata"}).engine == "suricata"
    with pytest.raises(ConfigError, match="engine"):
        load_config(tmp_path, {"engine": "bro"})


def test_the_default_engine_is_suricata_only_when_it_is_installed(tmp_path: Path) -> None:
    exe = tmp_path / "suricata.exe"
    assert default_engine(exe) == "snort"
    exe.write_bytes(b"MZ")
    assert default_engine(exe) == "suricata"
